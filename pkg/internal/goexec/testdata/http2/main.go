// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"os"
)

func main() {
	protocols := &http.Protocols{}
	protocols.SetHTTP2(true)
	transport := &http.Transport{Protocols: protocols}
	client := &http.Client{Transport: transport}
	_, _ = client.Get("https://example.com")

	_ = http.ListenAndServe(":8080", http.FileServer(http.Dir(os.TempDir())))
}
