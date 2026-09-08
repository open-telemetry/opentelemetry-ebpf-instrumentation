// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// freePort reserves and releases a port, so the manager can bind it afterwards.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

func testGauge(name string) prometheus.Collector {
	return prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: name})
}

// scrapes reports whether the given port and path answers.
// listenAndServe binds in the background, so this retries briefly.
func scrapes(t *testing.T, port int, path string) bool {
	t.Helper()
	url := "http://127.0.0.1:" + strconv.Itoa(port) + path
	for range 50 {
		//nolint:noctx // fixed loopback URL built from a port this test reserved
		resp, err := http.Get(url)
		if err == nil {
			defer resp.Body.Close()
			return resp.StatusCode == http.StatusOK
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// The internal metrics reporter registers and starts early in startup, while the network
// flows exporter registers and starts later when its pipeline is built. Both ports must
// end up served, whichever order the two components happen to run in.
func TestStartHTTP_ServesPortRegisteredAfterFirstStart(t *testing.T) {
	ctx := t.Context()

	pm := &PrometheusManager{}

	early := freePort(t)
	late := freePort(t)

	pm.Register(early, "/metrics", testGauge("early_metric"))
	pm.StartHTTP(ctx)

	pm.Register(late, "/metrics", testGauge("late_metric"))
	pm.StartHTTP(ctx)

	assert.True(t, scrapes(t, early, "/metrics"), "port registered before the first StartHTTP should be served")
	assert.True(t, scrapes(t, late, "/metrics"), "port registered after the first StartHTTP should be served")
}

// Same case one level down: the port is already listening, and a second component
// registers a different path on it. That path has to reach the running mux.
func TestStartHTTP_ServesPathRegisteredOnAlreadyServedPort(t *testing.T) {
	ctx := t.Context()

	pm := &PrometheusManager{}
	port := freePort(t)

	pm.Register(port, "/metrics", testGauge("first_metric"))
	pm.StartHTTP(ctx)
	require.True(t, scrapes(t, port, "/metrics"))

	pm.Register(port, "/internal", testGauge("second_metric"))
	pm.StartHTTP(ctx)

	assert.True(t, scrapes(t, port, "/internal"), "path registered after the port started serving should be served")
	assert.True(t, scrapes(t, port, "/metrics"), "the path served first should keep working")
}

func TestStartHTTP_ServesAllPortsRegisteredBeforeStart(t *testing.T) {
	ctx := t.Context()

	pm := &PrometheusManager{}

	first := freePort(t)
	second := freePort(t)

	pm.Register(first, "/metrics", testGauge("first_metric"))
	pm.Register(second, "/metrics", testGauge("second_metric"))
	pm.StartHTTP(ctx)

	assert.True(t, scrapes(t, first, "/metrics"))
	assert.True(t, scrapes(t, second, "/metrics"))
}

// Repeated calls with nothing newly registered must not open a second listener, and
// must not re-register a path on the mux, which http.ServeMux panics on.
func TestStartHTTP_IsIdempotentPerPortAndPath(t *testing.T) {
	ctx := t.Context()

	pm := &PrometheusManager{}

	port := freePort(t)
	pm.Register(port, "/metrics", testGauge("only_metric"))

	pm.StartHTTP(ctx)
	require.True(t, scrapes(t, port, "/metrics"))

	pm.StartHTTP(ctx)
	pm.StartHTTP(ctx)

	assert.True(t, scrapes(t, port, "/metrics"), "port should still be served after repeated StartHTTP calls")
}
