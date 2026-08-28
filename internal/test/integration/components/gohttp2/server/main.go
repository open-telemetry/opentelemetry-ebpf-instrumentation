// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type headerObservation struct {
	Traceparents []string `json:"traceparents"`
	RemoteAddr   string   `json:"remote_addr"`
	Protocol     string   `json:"protocol"`
}

func checkErr(err error, msg string) {
	if err == nil {
		return
	}
	fmt.Printf("ERROR: %s: %s\n", msg, err)
	os.Exit(1)
}

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	} else {
		http2.ConfigureServer(server, nil)
	}

	plaintext := &http.Server{
		Addr:    "0.0.0.0:7374",
		Handler: h2c.NewHandler(handler, &http2.Server{}),
	}
	go func() {
		fmt.Printf("Listening h2c [0.0.0.0:7374]...\n")
		checkErr(plaintext.ListenAndServe(), "while listening for h2c")
	}()

	fmt.Printf("Listening TLS [0.0.0.0:7373]...\n")
	checkErr(server.ListenAndServeTLS("cert.pem", "key.pem"), "while listening")
}
