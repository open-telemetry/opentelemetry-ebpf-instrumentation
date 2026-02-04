// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package testutil // import "go.opentelemetry.io/obi/pkg/internal/testutil"

import (
	"net"
	"testing"
)

// FreeTCPPort returns a free TCP port that can be used for testing.
func FreeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", ":")
	if err != nil {
		t.Fatalf("failed to find a free TCP port: %v", err)
	}
	defer listener.Close()

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("failed to get TCP address")
	}

	return addr.Port
}
