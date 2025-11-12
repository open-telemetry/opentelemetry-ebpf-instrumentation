// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"go.opentelemetry.io/obi/pkg/test/httplib"
)

func checkErr(err error, msg string) {
	if err == nil {
		return
	}
	fmt.Printf("ERROR: %s: %s\n", msg, err)
	os.Exit(1)
}

func roundTripExample() {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, os.Getenv("TARGET_URL")+"/pingrt", nil)
	checkErr(err, "during new request")

	tr := httplib.NewHTTP2Transport()

	resp, err := tr.RoundTrip(req)
	checkErr(err, "during roundtrip")

	if err == nil {
		fmt.Printf("RoundTrip Proto: %d\n", resp.ProtoMajor)
	}
}

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %v, http: %v\n", r.URL.Path, r.TLS == nil)
	})

	protocols := &http.Protocols{}
	protocols.SetHTTP2(true)
	server := &http.Server{
		Addr:      "0.0.0.0:8080",
		Handler:   handler,
		Protocols: protocols,
	}

	roundTripExample()
	fmt.Printf("Listening [0.0.0.0:8080]...\n")
	checkErr(server.ListenAndServeTLS("cert.pem", "key.pem"), "while listening")
}
