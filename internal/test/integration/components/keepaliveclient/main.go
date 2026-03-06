// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

var traceparentSeen atomic.Bool

func main() {
	transport := &http.Transport{
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		MaxConnsPerHost:     1,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   false,
	}

	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile("/tmp/connected", nil, 0o600); err != nil {
			log.Printf("failed to write /tmp/connected: %v", err)
		}
		return conn, nil
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	go func() {
		http.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
			if traceparentSeen.Load() {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNoContent)
			}
		})
		log.Fatal(http.ListenAndServe(":9091", nil))
	}()

	for {
		resp, err := client.Get("http://tpinjector-server:8080/smoke-echo")
		if err != nil {
			log.Printf("request failed: %v", err)
			time.Sleep(time.Second)
			continue
		}
		resp.Body.Close()

		if tp := resp.Header.Get("X-Received-Traceparent"); tp != "" {
			if traceparentSeen.CompareAndSwap(false, true) {
				fmt.Printf("traceparent received by server: %s\n", tp)
			}
		}

		time.Sleep(time.Second)
	}
}
