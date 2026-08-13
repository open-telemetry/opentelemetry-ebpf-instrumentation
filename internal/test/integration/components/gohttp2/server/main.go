// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

type serverObservation struct {
	CaseID       string   `json:"case_id"`
	Traceparents []string `json:"traceparents"`
	ProtoMajor   int      `json:"proto_major"`
	RemoteAddr   string   `json:"remote_addr"`
	MaxActive    int      `json:"max_active"`
	LargeLength  int      `json:"large_length"`
	LargeSHA256  string   `json:"large_sha256"`
}

var concurrency struct {
	sync.Mutex
	active    int
	maxActive int
}

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		concurrency.Lock()
		concurrency.active++
		if concurrency.active > concurrency.maxActive {
			concurrency.maxActive = concurrency.active
		}
		concurrency.Unlock()

		defer func() {
			concurrency.Lock()
			concurrency.active--
			concurrency.Unlock()
		}()

		if r.Header.Get("X-OBI-Hold") == "1" {
			time.Sleep(250 * time.Millisecond)
		}

		concurrency.Lock()
		maxActive := concurrency.maxActive
		concurrency.Unlock()

		w.Header().Set("Content-Type", "application/json")
		large := r.Header.Get("X-OBI-Large")
		_ = json.NewEncoder(w).Encode(serverObservation{
			CaseID:       r.Header.Get("X-OBI-Case"),
			Traceparents: r.Header.Values("traceparent"),
			ProtoMajor:   r.ProtoMajor,
			RemoteAddr:   r.RemoteAddr,
			MaxActive:    maxActive,
			LargeLength:  len(large),
			LargeSHA256:  fmt.Sprintf("%x", sha256.Sum256([]byte(large))),
		})
	})

	server := &http.Server{Addr: "0.0.0.0:7373", Handler: handler}
	if err := http2.ConfigureServer(server, &http2.Server{MaxReadFrameSize: 1 << 14}); err != nil {
		panic(err)
	}

	fmt.Println("Listening [0.0.0.0:7373]")
	if err := server.ListenAndServeTLS("cert.pem", "key.pem"); err != nil {
		panic(err)
	}
}
