// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
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

// scrapes reports whether the metrics endpoint on the given port answers.
// listenAndServe binds in the background, so this retries briefly.
func scrapes(t *testing.T, port int) bool {
	t.Helper()
	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/metrics"
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pm := &PrometheusManager{}

	early := freePort(t)
	late := freePort(t)

	pm.Register(early, "/metrics", testGauge("early_metric"))
	pm.StartHTTP(ctx)

	pm.Register(late, "/metrics", testGauge("late_metric"))
	pm.StartHTTP(ctx)

	assert.True(t, scrapes(t, early), "port registered before the first StartHTTP should be served")
	assert.True(t, scrapes(t, late), "port registered after the first StartHTTP should be served")
}

func TestStartHTTP_ServesAllPortsRegisteredBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pm := &PrometheusManager{}

	first := freePort(t)
	second := freePort(t)

	pm.Register(first, "/metrics", testGauge("first_metric"))
	pm.Register(second, "/metrics", testGauge("second_metric"))
	pm.StartHTTP(ctx)

	assert.True(t, scrapes(t, first))
	assert.True(t, scrapes(t, second))
}

// Repeated calls with nothing newly registered must not open a second listener.
func TestStartHTTP_IsIdempotentPerPort(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pm := &PrometheusManager{}

	port := freePort(t)
	pm.Register(port, "/metrics", testGauge("only_metric"))

	pm.StartHTTP(ctx)
	require.True(t, scrapes(t, port))

	pm.StartHTTP(ctx)
	pm.StartHTTP(ctx)

	assert.True(t, scrapes(t, port), "port should still be served after repeated StartHTTP calls")
}
