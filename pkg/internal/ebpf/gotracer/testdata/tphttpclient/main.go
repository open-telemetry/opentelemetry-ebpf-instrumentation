// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

// Command tphttpclient is a helper binary for the gotracer HTTP/1 traceparent
// privileged test. It issues plaintext and TLS HTTP/1 requests to loopback
// servers, which report every Traceparent value they received.
package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
)

const (
	staticTraceparent    = "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-86"
	duplicateTraceparent = "00-2122232425262728292a2b2c2d2e2f30-3132333435363738-01"
	invalidTraceparent   = "00-00000000000000000000000000000000-1112131415161718-01"
)

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values("Traceparent")
		fmt.Fprintf(w, "%d|%s", len(values), strings.Join(values, ","))
	})
	plainServer := httptest.NewServer(handler)
	defer plainServer.Close()

	tlsServer := httptest.NewUnstartedServer(handler)
	tlsServer.EnableHTTP2 = false
	tlsServer.StartTLS()
	defer tlsServer.Close()

	fmt.Println("READY")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		switch scanner.Text() {
		case "NO_TP":
			report(doRequest(http.DefaultClient, plainServer.URL, "/no-tp", "", nil))
		case "VALID_TP":
			report(doRequest(http.DefaultClient,
				plainServer.URL,
				"/valid-tp",
				"tRaCePaReNt",
				[]string{staticTraceparent}))
		case "VALID_TLS_TP":
			report(doRequest(tlsServer.Client(),
				tlsServer.URL,
				"/valid-tls-tp",
				"tRaCePaReNt",
				[]string{staticTraceparent}))
		case "DUPLICATE_TP":
			report(doRequest(http.DefaultClient,
				plainServer.URL,
				"/duplicate-tp",
				"Traceparent",
				[]string{staticTraceparent, duplicateTraceparent}))
		case "INVALID_TP":
			report(doRequest(http.DefaultClient,
				plainServer.URL,
				"/invalid-tp",
				"Traceparent",
				[]string{invalidTraceparent}))
		case "INVALID_THEN_VALID_TP":
			report(doRequest(http.DefaultClient,
				plainServer.URL,
				"/invalid-then-valid-tp",
				"Traceparent",
				[]string{invalidTraceparent, staticTraceparent}))
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
	fmt.Printf("TP_RESULT=%s\n", count)
}

func doRequest(
	client *http.Client,
	baseURL string,
	path string,
	headerName string,
	traceparents []string,
) (string, error) {
	req, err := http.NewRequest(http.MethodGet, baseURL+path, http.NoBody)
	if err != nil {
		return "", err
	}
	if headerName != "" {
		req.Header[headerName] = append([]string(nil), traceparents...)
	}
	resp, err := client.Do(req)
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
