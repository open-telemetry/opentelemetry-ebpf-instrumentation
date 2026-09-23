// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build legacy_stdlib

package main

import (
	"crypto/tls"
	"net/http"
	"os"
)

type ownershipTransport struct {
	name         string
	target       string
	roundTripper http.RoundTripper
}

func newLegacyStdlibTransport() http.RoundTripper {
	return &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
	}
}

var newHTTP2Transport = newLegacyStdlibTransport

func ownershipTransports() []ownershipTransport {
	return []ownershipTransport{
		{
			name:         "tls",
			target:       os.Getenv("TARGET_URL"),
			roundTripper: newLegacyStdlibTransport(),
		},
	}
}
