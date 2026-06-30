// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "pong")
	})
	mux.HandleFunc("/smoke", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "ok")
	})

	// h2c handler so HTTP/1.1 health checks keep working on the same mux as h2c traffic
	srv := &http.Server{
		Addr:    "0.0.0.0:7373",
		Handler: h2c.NewHandler(mux, &http2.Server{}),
	}

	log.Println("h2c server listening on :7373")
	log.Fatal(srv.ListenAndServe())
}
