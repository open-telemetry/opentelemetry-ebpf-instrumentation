// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Echoes every traceparent value a request arrived with, so the test sees exactly
// what the .NET client put on the wire.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type observation struct {
	Traceparent []string `json:"traceparent"`
	Protocol    int      `json:"protocol"`
}

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values("Traceparent")
		log.Printf("TRACEPARENT %s protocol=%s values=%q", r.URL.RequestURI(), r.Proto, values)

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(observation{Traceparent: values, Protocol: r.ProtoMajor}); err != nil {
			log.Printf("encoding response: %v", err)
		}
	})

	server := &http.Server{Addr: ":8086", Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(server.ListenAndServe())
}
