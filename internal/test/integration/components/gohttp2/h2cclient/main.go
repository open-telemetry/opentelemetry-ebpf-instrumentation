// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/http2"
)

func main() {
	target := os.Getenv("TARGET_URL")
	if target == "" {
		target = "http://h2cserver:7373"
	}

	for {
		// Fresh transport per request = fresh TCP connection = fresh HPACK dynamic table.
		// This ensures the BPF-level socktracer can decode HPACK from the first frame
		// even when OBI attaches mid-connection.
		client := &http.Client{
			Transport: &http2.Transport{
				AllowHTTP: true,
				DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				},
			},
		}
		resp, err := client.Get(target + "/ping")
		if err != nil {
			log.Printf("GET /ping failed: %v", err)
		} else {
			fmt.Printf("GET /ping: %d\n", resp.StatusCode)
			resp.Body.Close()
		}
		client.CloseIdleConnections()
		time.Sleep(time.Second)
	}
}
