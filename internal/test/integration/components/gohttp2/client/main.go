// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const applicationTraceparent = "00-11111111111111111111111111111111-2222222222222222-01"

type serverObservation struct {
	CaseID       string   `json:"case_id"`
	Traceparents []string `json:"traceparents"`
	ProtoMajor   int      `json:"proto_major"`
	RemoteAddr   string   `json:"remote_addr"`
	MaxActive    int      `json:"max_active"`
	LargeLength  int      `json:"large_length"`
	LargeSHA256  string   `json:"large_sha256"`
}

type runResult struct {
	CaseID      string            `json:"case_id"`
	Observation serverObservation `json:"observation"`
	Error       string            `json:"error,omitempty"`
}

type runResponse struct {
	Implementation string      `json:"implementation"`
	Results        []runResult `json:"results"`
}

type requestCase struct {
	id          string
	path        string
	traceparent string
	hold        bool
	large       bool
	boundaryLen int
}

type ownedAbandoner interface {
	abandonOwned(*http.Request) error
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		resp, err := http.Get("http://127.0.0.1:8080/health")
		if err != nil {
			log.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			log.Fatalf("unexpected health status %s", resp.Status)
		}
		return
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	http.HandleFunc("/run", run)
	log.Fatal(http.ListenAndServe("0.0.0.0:8080", nil))
}

func run(w http.ResponseWriter, r *http.Request) {
	transport, implementation, err := newTransport()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	defer transport.CloseIdleConnections()
	if r.URL.Query().Get("mode") == "abandonment" {
		runAbandonment(w, client, transport, implementation)
		return
	}

	sequential := []requestCase{
		{id: "metric-ping-1", path: "/ping"},
		{id: "metric-ping-2", path: "/ping"},
		{id: "metric-ping-3", path: "/ping"},
		{id: "metric-pingdo-1", path: "/pingdo"},
		{id: "metric-pingdo-2", path: "/pingdo"},
		{id: "metric-pingdo-3", path: "/pingdo"},
		{id: "metric-pingrt-1", path: "/pingrt"},
		{id: "metric-pingrt-2", path: "/pingrt"},
		{id: "metric-pingrt-3", path: "/pingrt"},
		{id: "owned-index-1", path: "/owned", traceparent: applicationTraceparent},
		{id: "owned-index-2", path: "/owned", traceparent: applicationTraceparent},
		{id: "owned-index-3", path: "/owned", traceparent: applicationTraceparent},
		{id: "owned-index-4", path: "/owned", traceparent: applicationTraceparent},
		{id: "control-after-index", path: "/control"},
		{id: "owned-continuation", path: "/continuation", traceparent: applicationTraceparent, large: true},
		{id: "control-continuation", path: "/continuation", large: true},
		{id: "control-after-continuation", path: "/control"},
	}
	for length := 32500; length <= 32768; length += 4 {
		sequential = append(sequential, requestCase{
			id: fmt.Sprintf("control-prewrite-%d", length), path: "/continuation", boundaryLen: length,
		})
	}

	results := make([]runResult, 0, len(sequential)+4)
	for _, testCase := range sequential {
		results = append(results, execute(client, testCase))
	}

	concurrent := []requestCase{
		{id: "mux-owned-1", path: "/mux", traceparent: applicationTraceparent, hold: true},
		{id: "mux-control-1", path: "/mux", hold: true},
		{id: "mux-owned-2", path: "/mux", traceparent: applicationTraceparent, hold: true},
		{id: "mux-control-2", path: "/mux", hold: true},
	}
	concurrentResults := make([]runResult, len(concurrent))
	var wg sync.WaitGroup
	for i := range concurrent {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			concurrentResults[index] = execute(client, concurrent[index])
		}(i)
	}
	wg.Wait()
	results = append(results, concurrentResults...)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(runResponse{Implementation: implementation, Results: results})
}

func runAbandonment(w http.ResponseWriter, client *http.Client, transport interface{}, implementation string) {
	abandoner, ok := transport.(ownedAbandoner)
	if !ok {
		http.Error(w, "transport does not support abandonment", http.StatusBadRequest)
		return
	}
	results := []runResult{execute(client, requestCase{
		id:   "control-before-abandonment",
		path: "/control",
	})}
	abandoned := requestCase{
		id:          "owned-abandoned-before-framer",
		path:        "/owned",
		traceparent: applicationTraceparent,
	}
	req, err := request(abandoned)
	if err == nil {
		err = abandoner.abandonOwned(req)
	}
	results = append(results, runResult{CaseID: abandoned.id, Error: errorString(err)})
	results = append(results, execute(client, requestCase{
		id:   "control-after-abandonment",
		path: "/control",
	}))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(runResponse{Implementation: implementation, Results: results})
}

func execute(client *http.Client, testCase requestCase) runResult {
	req, err := request(testCase)
	if err != nil {
		return runResult{CaseID: testCase.id, Error: err.Error()}
	}

	resp, err := client.Do(req)
	if err != nil {
		return runResult{CaseID: testCase.id, Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return runResult{CaseID: testCase.id, Error: fmt.Sprintf("unexpected status %s", resp.Status)}
	}
	var observation serverObservation
	if err := json.NewDecoder(resp.Body).Decode(&observation); err != nil {
		return runResult{CaseID: testCase.id, Error: err.Error()}
	}
	return runResult{CaseID: testCase.id, Observation: observation}
}

func request(testCase requestCase) (*http.Request, error) {
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		os.Getenv("TARGET_URL")+testCase.path,
		nil,
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-OBI-Case", testCase.id)
	if testCase.traceparent != "" {
		req.Header.Set("traceparent", testCase.traceparent)
	}
	if testCase.hold {
		req.Header.Set("X-OBI-Hold", "1")
	}
	if testCase.large {
		req.Header.Set("X-OBI-Large", highEntropyHeader())
	} else if testCase.boundaryLen > 0 {
		req.Header.Set("X-OBI-Large", strings.Repeat("~", testCase.boundaryLen))
	}

	return req, nil
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func highEntropyHeader() string {
	data := make([]byte, 32*1024)
	state := uint32(0x2769a5c3)
	for i := range data {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		data[i] = byte(state)
	}
	return base64.RawStdEncoding.EncodeToString(data)
}
