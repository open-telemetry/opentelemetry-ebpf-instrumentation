// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build legacy_xnet

package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"os"

	"golang.org/x/net/http2"
)

type ownershipTransport struct {
	name         string
	target       string
	roundTripper http.RoundTripper
}

var newHTTP2Transport = func() http.RoundTripper {
	return &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}

func ownershipTransports() []ownershipTransport {
	return []ownershipTransport{
		{
			name:   "tls",
			target: os.Getenv("TARGET_URL"),
			roundTripper: &http2.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		{
			name:   "plaintext",
			target: "http://testserver:7374",
			roundTripper: &http2.Transport{
				AllowHTTP: true,
				DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
					return net.Dial(network, addr)
				},
			},
		},
	}
}
