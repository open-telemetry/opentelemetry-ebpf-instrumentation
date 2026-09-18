// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !legacy_xnet && !legacy_stdlib

package main

import (
	"context"
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

func init() {
	if os.Getenv("TEST_HTTP2_PROTOCOLS") == "1" {
		newHTTP2Transport = newHTTP2TransportThroughProtocols
		newOwnershipTLSRoundTripper = newHTTP2TransportThroughProtocols
		newOwnershipPlaintextRoundTripper = newHTTP2PlaintextTransportThroughProtocols
	}
}

func newHTTP2TransportThroughProtocols() http.RoundTripper {
	protocols := &http.Protocols{}
	protocols.SetHTTP2(true)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Protocols = protocols
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return transport
}

var newHTTP2Transport = func() http.RoundTripper {
	return &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}

var newOwnershipTLSRoundTripper = func() http.RoundTripper {
	return &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}

var newOwnershipPlaintextRoundTripper = func() http.RoundTripper {
	return &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
}

func newHTTP2PlaintextTransportThroughProtocols() http.RoundTripper {
	protocols := &http.Protocols{}
	protocols.SetUnencryptedHTTP2(true)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Protocols = protocols
	return transport
}

func ownershipTransports() []ownershipTransport {
	return []ownershipTransport{
		{
			name:         "tls",
			target:       os.Getenv("TARGET_URL"),
			roundTripper: newOwnershipTLSRoundTripper(),
		},
		{
			name:         "plaintext",
			target:       "http://testserver:7374",
			roundTripper: newOwnershipPlaintextRoundTripper(),
		},
	}
}
