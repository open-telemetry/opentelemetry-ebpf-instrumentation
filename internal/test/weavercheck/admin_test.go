// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package weavercheck

import (
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

const testReport = `{"statistics":{"total_entities":1}}`

type fakeWeaverAdmin struct {
	calls    []string
	stopped  bool
	failPath string
}

func (f *fakeWeaverAdmin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	if r.URL.Path == f.failPath {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "POST /stop":
		f.stopped = true
		_, _ = w.Write([]byte(`{"state":"stopped","report":true}`))
	case "GET /report":
		if !f.stopped {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"still receiving; POST /stop first"}`))
			return
		}
		_, _ = w.Write([]byte(testReport))
	case "POST /shutdown":
		_, _ = w.Write([]byte(`{"state":"shutting_down"}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func fetchFrom(t *testing.T, admin *fakeWeaverAdmin) ([]byte, error) {
	t.Helper()
	server := httptest.NewServer(admin)
	defer server.Close()
	return FetchRawReport(t.Context(), server.URL)
}

func TestFetchRawReportStopsReadsThenShutsDown(t *testing.T) {
	admin := &fakeWeaverAdmin{}

	raw, err := fetchFrom(t, admin)

	require.NoError(t, err)
	require.JSONEq(t, testReport, string(raw))
	require.Equal(t, []string{"POST /stop", "GET /report", "POST /shutdown"}, admin.calls)
}

func TestFetchRawReportFailsWhenStopFails(t *testing.T) {
	admin := &fakeWeaverAdmin{failPath: adminStopPath}

	_, err := fetchFrom(t, admin)

	require.ErrorContains(t, err, "weaver /stop returned HTTP 500")
	require.Equal(t, []string{"POST /stop"}, admin.calls)
}

func TestFetchRawReportShutsDownWhenTheReportFails(t *testing.T) {
	admin := &fakeWeaverAdmin{failPath: adminReportPath}

	_, err := fetchFrom(t, admin)

	require.ErrorContains(t, err, "weaver /report returned HTTP 500")
	require.Equal(t, []string{"POST /stop", "GET /report", "POST /shutdown"}, admin.calls)
}

func TestFetchRawReportFailsWhenShutdownFails(t *testing.T) {
	admin := &fakeWeaverAdmin{failPath: adminShutdownPath}

	_, err := fetchFrom(t, admin)

	require.ErrorContains(t, err, "weaver /shutdown returned HTTP 500")
}

func TestFetchRawReportKeepsConnectionRefused(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())

	_, err = FetchRawReport(t.Context(), "http://"+addr)

	require.ErrorIs(t, err, syscall.ECONNREFUSED)
}
