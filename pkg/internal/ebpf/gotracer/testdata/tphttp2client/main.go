// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var useTLS = flag.Bool("tls", false, "use TLS for the loopback connection")

func main() {
	flag.Parse()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values("Traceparent")
		_, _ = fmt.Fprintf(w, "%d:%s", len(values), strings.Join(values, ","))
	})

	client, url, stop, err := startServer(handler)
	if err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
	defer stop()

	fmt.Println("READY")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		switch scanner.Text() {
		case "REQUEST":
			report(call(client, url))
		case "EXIT":
			return
		}
	}
}

func startServer(handler http.Handler) (*http.Client, string, func(), error) {
	if *useTLS {
		server := httptest.NewUnstartedServer(handler)
		server.EnableHTTP2 = true
		server.StartTLS()
		return server.Client(), server.URL, server.Close, nil
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", nil, err
	}
	server := &http.Server{Handler: h2c.NewHandler(handler, &http2.Server{})}
	go func() { _ = server.Serve(listener) }()

	transport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}
	stop := func() {
		transport.CloseIdleConnections()
		_ = server.Close()
	}
	return &http.Client{Transport: transport}, "http://" + listener.Addr().String(), stop, nil
}

func call(client *http.Client, url string) (string, error) {
	response, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	result, err := io.ReadAll(response.Body)
	return string(result), err
}

func report(result string, err error) {
	if err != nil {
		fmt.Printf("ERROR %v\n", err)
		return
	}
	fmt.Printf("TP_RESULT=%s\n", result)
}
