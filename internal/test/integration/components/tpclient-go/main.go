// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// tpclient-go is the Go hop of the tpclient chain for large HTTP/1 headers:
// it receives a request with a large cookie and reports its traceparents.
package main

import (
	"encoding/json"
	"log"
	"net/http"
)

// hop is what each service of the chain reports about the request it received.
type hop struct {
	Service      string   `json:"service"`
	Traceparents []string `json:"traceparents"`
}

func main() {
	http.HandleFunc("/smoke", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/large", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		received := hop{Service: "go", Traceparents: r.Header.Values("Traceparent")}
		if err := json.NewEncoder(w).Encode(received); err != nil {
			log.Printf("writing response: %v", err)
		}
	})

	log.Fatal(http.ListenAndServe(":6003", nil))
}
