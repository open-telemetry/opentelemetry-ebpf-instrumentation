// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDoHTTPGetReleasesConnections(t *testing.T) {
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			connections.Add(1)
		case http.StateClosed:
			connections.Add(-1)
		}
	}
	server.Start()
	t.Cleanup(server.Close)

	for range 4 {
		DoHTTPGet(t, server.URL, http.StatusOK)
	}

	require.Eventually(t, func() bool {
		testHTTPClient.CloseIdleConnections()
		return connections.Load() == 0
	}, time.Second, time.Millisecond, "HTTP helper retained %d connections", connections.Load())
}
