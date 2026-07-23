// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

// Command tphttpclient is a helper binary for the gotracer HTTP/1 traceparent
// injection privileged test. It issues an HTTP/1 request to its own loopback
// server, which reports how many `Traceparent` header values it received. Two
// modes exercise the two scenarios:
//
//   - "WITH_TP": the client sets its own Traceparent header (as an SDK or a
//     hand-rolled propagator would). OBI must NOT add a second one -> the
//     receiver sees exactly 1.
//   - "NO_TP": the client sets no Traceparent. OBI injects its own -> the
//     receiver sees exactly 1 (proving injection still happens when absent).
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
)

// A valid W3C traceparent used by the WITH_TP mode.
const staticTraceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%d", len(r.Header.Values("Traceparent")))
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen error: %v\n", err)
		os.Exit(1)
	}
	go func() { _ = http.Serve(ln, mux) }()

	// http:// with the default transport keeps this on HTTP/1.1, exercising
	// OBI's net/http header_writeSubset injection path.
	url := "http://" + ln.Addr().String() + "/"

	fmt.Println("READY")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		switch scanner.Text() {
		case "WITH_TP":
			report(doRequest(url, true))
		case "NO_TP":
			report(doRequest(url, false))
		case "EXIT":
			return
		}
	}
}

func report(count string, err error) {
	if err != nil {
		fmt.Printf("ERROR %v\n", err)
		return
	}
	fmt.Printf("TP_COUNT=%s\n", count)
}

func doRequest(url string, withTraceparent bool) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return "", err
	}
	if withTraceparent {
		req.Header.Set("Traceparent", staticTraceparent)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
