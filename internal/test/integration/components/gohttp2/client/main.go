// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	ownedTraceparent          = "00-11111111111111111111111111111111-2222222222222222-01"
	muxTraceparent            = "00-33333333333333333333333333333333-4444444444444444-01"
	oneContinuationHeaderSize = 20_000
	multiContinuationSize     = 40_000
)

type headerObservation struct {
	Traceparents []string `json:"traceparents"`
	RemoteAddr   string   `json:"remote_addr"`
	Protocol     string   `json:"protocol"`
}

type ownershipResult struct {
	Transport  string              `json:"transport"`
	Repeated   []headerObservation `json:"repeated"`
	Controls   []headerObservation `json:"controls"`
	LargeOwned headerObservation   `json:"large_owned"`
	LargePlain headerObservation   `json:"large_plain"`
	MultiPlain headerObservation   `json:"multi_plain"`
	MuxOwned   headerObservation   `json:"mux_owned"`
	MuxPlain   headerObservation   `json:"mux_plain"`
	Error      string              `json:"error,omitempty"`
}

func checkErr(err error, msg string) {
	if err == nil {
		return
	}
	fmt.Printf("ERROR: %s: %s\n", msg, err)
}

func main() {
	go serveOwnershipTrigger()

	for {
		HttpClientExample()
		RoundTripExample()
		HttpClientDoExample()

		time.Sleep(time.Second)
	}
}

func serveOwnershipTrigger() {
	mux := http.NewServeMux()
	mux.HandleFunc("/run", func(w http.ResponseWriter, _ *http.Request) {
		runOwnershipSuites()
		w.WriteHeader(http.StatusNoContent)
	})
	checkErr(http.ListenAndServe("0.0.0.0:7575", mux), "while serving ownership trigger")
}

func runOwnershipSuites() {
	for _, transport := range ownershipTransports() {
		runOwnershipSuite(transport.name, transport.target, transport.roundTripper)
	}
}

func runOwnershipSuite(name, target string, transport http.RoundTripper) {
	result := ownershipResult{Transport: name}
	client := &http.Client{Transport: transport}

	for i := 0; i < 4; i++ {
		observation, err := observeHeaders(client, target+"/ownership/repeated", ownedTraceparent, 0)
		if err != nil {
			result.Error = err.Error()
			writeOwnershipResult(result)
			return
		}
		result.Repeated = append(result.Repeated, observation)
	}

	for i := 0; i < 2; i++ {
		observation, err := observeHeaders(client, target+"/ownership/control", "", 0)
		if err != nil {
			result.Error = err.Error()
			writeOwnershipResult(result)
			return
		}
		result.Controls = append(result.Controls, observation)
	}

	var err error
	result.LargeOwned, err = observeHeaders(
		client, target+"/ownership/continuation", ownedTraceparent, oneContinuationHeaderSize)
	if err != nil {
		result.Error = err.Error()
		writeOwnershipResult(result)
		return
	}
	result.LargePlain, err = observeHeaders(
		client, target+"/ownership/continuation", "", oneContinuationHeaderSize)
	if err != nil {
		result.Error = err.Error()
		writeOwnershipResult(result)
		return
	}
	result.MultiPlain, err = observeHeaders(
		client, target+"/ownership/multi-continuation", "", multiContinuationSize)
	if err != nil {
		result.Error = err.Error()
		writeOwnershipResult(result)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	start := make(chan struct{})
	var ownedErr, plainErr error
	go func() {
		defer wg.Done()
		<-start
		result.MuxOwned, ownedErr = observeHeaders(
			client, target+"/ownership/multiplex", muxTraceparent, 0)
	}()
	go func() {
		defer wg.Done()
		<-start
		result.MuxPlain, plainErr = observeHeaders(client, target+"/ownership/multiplex", "", 0)
	}()
	close(start)
	wg.Wait()
	if ownedErr != nil {
		result.Error = ownedErr.Error()
	} else if plainErr != nil {
		result.Error = plainErr.Error()
	}

	writeOwnershipResult(result)
}

func observeHeaders(client *http.Client, url, traceparent string, headerSize int) (headerObservation, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return headerObservation{}, err
	}
	if traceparent != "" {
		req.Header.Set("TrAcEpArEnT", traceparent)
	}
	if headerSize > 0 {
		req.Header.Set("X-OBI-Large", strings.Repeat("~", headerSize))
	}

	resp, err := client.Do(req)
	if err != nil {
		return headerObservation{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return headerObservation{}, fmt.Errorf("unexpected status %s", resp.Status)
	}

	var observation headerObservation
	if err := json.NewDecoder(resp.Body).Decode(&observation); err != nil {
		return headerObservation{}, err
	}
	return observation, nil
}

func writeOwnershipResult(result ownershipResult) {
	encoded, err := json.Marshal(result)
	if err != nil {
		fmt.Printf("ERROR: encoding ownership result: %s\n", err)
		return
	}
	fmt.Printf("HTTP2_OWNERSHIP_RESULT %s\n", encoded)
}

func RoundTripExample() {
	req, err := http.NewRequestWithContext(context.Background(), "GET", os.Getenv("TARGET_URL")+"/pingrt", nil)
	checkErr(err, "during new request")

	tr := newHTTP2Transport()
	resp, err := tr.RoundTrip(req)
	checkErr(err, "during roundtrip")

	if err == nil {
		fmt.Printf("RoundTrip Proto: %d\n", resp.ProtoMajor)
	}
}

func HttpClientExample() {
	client := http.Client{
		Transport: newHTTP2Transport(),
	}

	resp, err := client.Get(os.Getenv("TARGET_URL") + "/ping")
	checkErr(err, "during get")

	if err == nil {
		fmt.Printf("Client Proto: %d\n", resp.ProtoMajor)
	}
}

func HttpClientDoExample() {
	client := http.Client{
		Transport: newHTTP2Transport(),
	}

	req, err := http.NewRequestWithContext(context.Background(), "GET", os.Getenv("TARGET_URL")+"/pingdo", nil)
	checkErr(err, "during new request")

	resp, err := client.Do(req)
	checkErr(err, "during get")

	if err == nil {
		fmt.Printf("Client.Do Proto: %d\n", resp.ProtoMajor)
	}
}
