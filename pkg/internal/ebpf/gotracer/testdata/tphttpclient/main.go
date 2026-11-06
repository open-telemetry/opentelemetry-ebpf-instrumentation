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
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
)

// A valid W3C traceparent used by the WITH_TP mode.
const staticTraceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

func main() {
	var downstream string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/forward" {
			resp, err := http.Get(downstream + "/details")
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(w, resp.Body)
			return
		}
		if r.URL.Path == "/details" {
			fmt.Fprintf(w, "%d:%s", len(r.Header.Values("Traceparent")), r.Header.Get("Traceparent"))
			return
		}
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
	downstream = strings.TrimSuffix(url, "/")
	tlsServer := httptest.NewTLSServer(mux)
	defer tlsServer.Close()

	fmt.Println("READY")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		mode := scanner.Text()
		switch mode {
		case "WITH_TP":
			report(doRequest(url, true))
		case "NO_TP":
			report(doRequest(url, false))
		case "EXIT":
			return
		default:
			baseURL := downstream
			client := http.DefaultClient
			if strings.Contains(mode, "TLS") {
				baseURL = tlsServer.URL
				client = tlsServer.Client()
			}
			if strings.Contains(mode, "FRAGMENTED") {
				report(doFragmentedRequest(baseURL, client))
			} else {
				report(doLargeRequest(baseURL, client, mode))
			}
		}
	}
}

func doLargeRequest(baseURL string, client *http.Client, mode string) (string, error) {
	if strings.Contains(mode, "TIGHT") {
		base, ok := client.Transport.(*http.Transport)
		if !ok {
			base = http.DefaultTransport.(*http.Transport)
		}
		transport := base.Clone()
		transport.WriteBufferSize = 128
		defer transport.CloseIdleConnections()
		client = &http.Client{Transport: transport}
	}
	req, err := http.NewRequest(http.MethodGet, baseURL+"/details", http.NoBody)
	if err != nil {
		return "", err
	}
	padding := 12 * 1024
	if strings.Contains(mode, "BEYOND_LIMIT") {
		padding = 18 * 1024
	}
	key := "A-Padding"
	if strings.Contains(mode, "EARLY") {
		key = "Z-Padding"
	}
	req.Header.Set(key, strings.Repeat("a", padding))
	if strings.Contains(mode, "WITH_TP") {
		req.Header.Set("Traceparent", staticTraceparent)
	}
	if strings.Contains(mode, "MALFORMED") {
		req.Header.Set("Traceparent", "application-owned-invalid")
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func doFragmentedRequest(baseURL string, client *http.Client) (string, error) {
	address := strings.TrimPrefix(strings.TrimPrefix(baseURL, "https://"), "http://")
	var conn net.Conn
	var err error
	if strings.HasPrefix(baseURL, "https://") {
		conn, err = tls.Dial("tcp", address, client.Transport.(*http.Transport).TLSClientConfig)
	} else {
		conn, err = net.Dial("tcp", address)
	}
	if err != nil {
		return "", err
	}
	defer conn.Close()
	prefix := "GET /forward HTTP/1.1\r\nHost: " + address + "\r\nX-Padding: "
	const headerOffset = 8190
	payload := prefix + strings.Repeat("a", headerOffset-len(prefix)-2) + "\r\nTraceparent: " +
		staticTraceparent + "\r\nConnection: close\r\n\r\n"
	const fragmentSize = 137
	for len(payload) > 0 {
		n := min(len(payload), fragmentSize)
		if _, err := io.WriteString(conn, payload[:n]); err != nil {
			return "", err
		}
		payload = payload[n:]
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
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
