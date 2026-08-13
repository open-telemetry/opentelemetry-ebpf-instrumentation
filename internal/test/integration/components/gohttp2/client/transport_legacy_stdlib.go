// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build legacy_stdlib

package main

import (
	"crypto/tls"
	"net/http"
)

func newTransport() (interface {
	http.RoundTripper
	CloseIdleConnections()
}, string, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = true
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return transport, "net/http-go1.17", nil
}
