// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package health

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type response struct {
	SchemaVersion   int   `json:"schema_version"`
	NowUnixNs       int64 `json:"now_unix_ns"`
	ProcessUptimeNs int64 `json:"process_uptime_ns"`
}

func TestServeHTTPShape(t *testing.T) {
	resp := snapshotFor(t, &endpoint{start: time.Now()})

	assert.Equal(t, schemaVersion, resp.SchemaVersion)
	assert.Positive(t, resp.NowUnixNs)
	assert.GreaterOrEqual(t, resp.ProcessUptimeNs, int64(0))
}

func TestServeHTTPAdvancesTime(t *testing.T) {
	e := &endpoint{start: time.Now()}

	r1 := snapshotFor(t, e)

	time.Sleep(2 * time.Millisecond)

	r2 := snapshotFor(t, e)

	assert.Greater(t, r2.NowUnixNs, r1.NowUnixNs)
	assert.GreaterOrEqual(t, r2.ProcessUptimeNs, r1.ProcessUptimeNs)
}

func TestTCPListenAddr(t *testing.T) {
	tests := map[string]struct {
		address string
		want    string
	}{
		"default":       {want: "127.0.0.1:8080"},
		"loopback":      {address: "127.0.0.1", want: "127.0.0.1:8080"},
		"wildcard IPv4": {address: "0.0.0.0", want: "0.0.0.0:8080"},
		"wildcard IPv6": {address: "::", want: "[::]:8080"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.want, tcpListenAddr(test.address, 8080))
		})
	}
}

func TestNewServerHardening(t *testing.T) {
	server := newServer()

	assert.Equal(t, readHeaderTimeout, server.ReadHeaderTimeout)
	assert.Equal(t, readTimeout, server.ReadTimeout)
	assert.Equal(t, writeTimeout, server.WriteTimeout)
	assert.Equal(t, idleTimeout, server.IdleTimeout)
}

func TestIdleConnectionsExpire(t *testing.T) {
	server := newServer()
	server.IdleTimeout = 25 * time.Millisecond

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Serve(lis)
	}()

	t.Cleanup(func() {
		require.NoError(t, server.Close())
		assert.ErrorIs(t, <-serverErr, http.ErrServerClosed)
	})

	conn, err := net.Dial("tcp", lis.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, conn.Close())
	})

	const request = "GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n"
	_, err = io.WriteString(conn, request)
	require.NoError(t, err)

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	time.Sleep(2 * server.IdleTimeout)
	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))

	_, _ = io.WriteString(conn, request)
	_, err = http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	require.Error(t, err)
}

func TestServeEndToEnd(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- Serve(ctx, lis)
	}()

	url := "http://" + lis.Addr().String() + path

	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body response
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, schemaVersion, body.SchemaVersion)

	cancel()
	require.NoError(t, <-srvErr)
}

func TestServeEndToEndUDS(t *testing.T) {
	// On Linux "@"-prefixed names are abstract sockets (no filesystem entry,
	// cleaned up by the kernel). macOS doesn't support abstract sockets, so this
	// becomes a regular socket file in the working directory; remove any leftover
	// from an interrupted previous run before listening.
	const sockAddr = "@obi-health-test"
	_ = os.Remove(sockAddr)

	lis, err := net.Listen("unix", sockAddr)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = lis.Close()
		_ = os.Remove(sockAddr)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- Serve(ctx, lis)
	}()

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sockAddr)
		},
	}}

	resp, err := client.Get("http://localhost" + path)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body response
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, schemaVersion, body.SchemaVersion)

	cancel()
	require.NoError(t, <-srvErr)
}

func snapshotFor(t *testing.T, e *endpoint) response {
	t.Helper()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	e.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var resp response
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	return resp
}
