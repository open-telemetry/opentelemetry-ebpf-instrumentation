// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type wrappedTLSConn struct {
	_ int
	*tls.Conn
}

func main() {
	// Adding shutdown hook for graceful stop.
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	client := httpClient()
	for {
		r, err := client.Get(os.Getenv("TARGET_URL"))
		if err != nil {
			fmt.Println("error!", err)
		}
		if r != nil {
			fmt.Println("response:", r.Status)
		}
		select {
		case <-time.After(time.Second):
		// go to the next loop!
		case <-ctx.Done():
			fmt.Println("got signal. Exiting")
			os.Exit(0)
		}
	}
}

func httpClient() *http.Client {
	if os.Getenv("WRAP_TLS_CONN") != "true" {
		return http.DefaultClient
	}

	dialer := tls.Dialer{
		Config: &tls.Config{InsecureSkipVerify: true},
	}
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}

			return &wrappedTLSConn{Conn: conn.(*tls.Conn)}, nil
		},
	}

	return &http.Client{Transport: transport}
}
