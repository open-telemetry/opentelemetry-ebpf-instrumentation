// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const (
	testMaxReadFrameSize = 16 << 10
	burstWaitTimeout     = 10 * time.Second
)

type headerObservation struct {
	Traceparents []string `json:"traceparents"`
	RemoteAddr   string   `json:"remote_addr"`
	Protocol     string   `json:"protocol"`
}

type burstObservation struct {
	headerObservation
	// every request of the burst was being handled at the same time
	Concurrent bool `json:"concurrent"`
}

type burst struct {
	mu      sync.Mutex
	arrived int
	all     chan struct{}
}

var bursts sync.Map

func checkErr(err error, msg string) {
	if err == nil {
		return
	}
	fmt.Printf("ERROR: %s: %s\n", msg, err)
	os.Exit(1)
}

// waitForBurst blocks until size requests of the burst have arrived, or the timeout expires
func waitForBurst(id string, size int) bool {
	value, _ := bursts.LoadOrStore(id, &burst{all: make(chan struct{})})
	b := value.(*burst)

	b.mu.Lock()
	b.arrived++
	if b.arrived == size {
		close(b.all)
	}
	b.mu.Unlock()

	select {
	case <-b.all:
		return true
	case <-time.After(burstWaitTimeout):
		return false
	}
}

func serveBurst(w http.ResponseWriter, r *http.Request) {
	// /burst/<id>/<stream>?size=<n>
	id, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/burst/"), "/")
	size, err := strconv.Atoi(r.URL.Query().Get("size"))
	if err != nil || size <= 0 {
		http.Error(w, "invalid burst size", http.StatusBadRequest)
		return
	}

	observation := burstObservation{
		headerObservation: headerObservation{
			Traceparents: r.Header.Values("traceparent"),
			RemoteAddr:   r.RemoteAddr,
			Protocol:     r.Proto,
		},
		Concurrent: waitForBurst(id, size),
	}
	w.Header().Set("Content-Type", "application/json")
	checkErr(json.NewEncoder(w).Encode(observation), "while encoding burst response")
}

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/burst/") {
			serveBurst(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/ownership/") {
			if r.URL.Path == "/ownership/multiplex" {
				time.Sleep(200 * time.Millisecond)
			}
			w.Header().Set("Content-Type", "application/json")
			checkErr(json.NewEncoder(w).Encode(headerObservation{
				Traceparents: r.Header.Values("traceparent"),
				RemoteAddr:   r.RemoteAddr,
				Protocol:     r.Proto,
			}), "while encoding ownership response")
			return
		}
		fmt.Fprintf(w, "Hello, %v, http: %v\n", r.URL.Path, r.TLS == nil)
	})

	server := &http.Server{
		Addr:    "0.0.0.0:7373",
		Handler: handler,
	}

	if os.Getenv("TEST_HTTP2_PROTOCOLS") == "1" {
		protocols := &http.Protocols{}
		protocols.SetHTTP2(true)
		server.Protocols = protocols
		server.HTTP2 = &http.HTTP2Config{MaxReadFrameSize: testMaxReadFrameSize}
	} else {
		http2.ConfigureServer(server, &http2.Server{MaxReadFrameSize: testMaxReadFrameSize})
	}

	plaintext := &http.Server{
		Addr:    "0.0.0.0:7374",
		Handler: h2c.NewHandler(handler, &http2.Server{MaxReadFrameSize: testMaxReadFrameSize}),
	}
	go func() {
		fmt.Printf("Listening h2c [0.0.0.0:7374]...\n")
		checkErr(plaintext.ListenAndServe(), "while listening for h2c")
	}()

	fmt.Printf("Listening TLS [0.0.0.0:7373]...\n")
	checkErr(server.ListenAndServeTLS("cert.pem", "key.pem"), "while listening")
}
