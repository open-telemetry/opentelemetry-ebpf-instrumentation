// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package health

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
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

func TestListenAndServeEndToEnd(t *testing.T) {
	port := freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- ListenAndServe(ctx, port)
	}()

	url := "http://127.0.0.1:" + strconv.Itoa(port) + path

	var resp *http.Response
	require.Eventually(t, func() bool {
		r, err := http.Get(url)
		if err != nil {
			return false
		}
		resp = r
		return true
	}, 3*time.Second, 20*time.Millisecond)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body response
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, schemaVersion, body.SchemaVersion)

	cancel()
	require.NoError(t, <-srvErr)
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
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
