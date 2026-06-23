// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/smoke", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	http.HandleFunc("/smoke-echo", func(w http.ResponseWriter, r *http.Request) {
		if tp := r.Header.Get("Traceparent"); tp != "" {
			w.Header().Set("X-Received-Traceparent", tp)
		}
		w.WriteHeader(http.StatusOK)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
