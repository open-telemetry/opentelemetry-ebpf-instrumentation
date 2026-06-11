// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package health

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
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
	const addr = "@obi-health-test"
	lis, err := net.Listen("unix", addr)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- Serve(ctx, lis)
	}()

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", addr)
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
