// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"net/http"
	"path"
	"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

const (
	// The port the workload's pooled connections go to. They complete their
	// handshake, carry no bytes and are closed by the workload.
	idlePeerPort = 7000
	// The port nothing listens on, so every connect to it is refused.
	unreachablePeerPort = 7001
)

func failedConnectTraces(t require.TestingT) []jaeger.Trace {
	resp, err := http.Get(jaegerQueryURL + "?service=failedconnectclient")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tq jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))

	return tq.Data
}

func connectSpansToPort(traces []jaeger.Trace, port int) []jaeger.Span {
	var matches []jaeger.Span

	for i := range traces {
		for _, span := range traces[i].Spans {
			if span.OperationName != "CONNECT" {
				continue
			}
			if len(span.Diff(jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(port)})) == 0 {
				matches = append(matches, span)
			}
		}
	}

	return matches
}

// Drives the workload for long enough that each request closes connections
// opened by an earlier one, and that several connects to the unreachable port
// have been attempted.
func driveFailedConnectWorkload(t *testing.T) {
	for range 15 {
		ti.DoHTTPGet(t, "http://localhost:8080/work", 200)
		time.Sleep(time.Second)
	}
}

// Confirms the workload is instrumented, so a missing CONNECT span below means
// the connect was not reported rather than that nothing was watched at all.
func testFailedConnectInstrumented(t *testing.T) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var served int
		for _, trace := range failedConnectTraces(ct) {
			served += len(trace.FindByOperationName("GET /work", "server"))
		}
		assert.Positive(ct, served)
	}, testTimeout, 100*time.Millisecond)
}

// A connect that is refused is a genuine failure and stays reported.
func testRefusedConnectIsReported(t *testing.T) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.NotEmpty(ct, connectSpansToPort(failedConnectTraces(ct), unreachablePeerPort))
	}, testTimeout, 100*time.Millisecond)
}

// The pooled connections completed their handshake and were closed by the
// workload without carrying a byte, which is what a client connection pool does
// to an idle connection. None of them is a failed connect.
func testIdlePooledConnectionIsNotAFailedConnect(t *testing.T) {
	spans := connectSpansToPort(failedConnectTraces(t), idlePeerPort)
	assert.Empty(t, spans, "established idle connections reported as failed connects: %d", len(spans))
}

// A connect reported as failed belongs to the transaction that made it, if any.
// The workload closes its pooled connections from inside a request handler, so
// a span attributed to that close joins the request being served, dated at a
// connect that happened before the request existed.
func testNoSpanStartsBeforeItsParent(t *testing.T) {
	for _, trace := range failedConnectTraces(t) {
		for _, span := range trace.Spans {
			parent, ok := trace.ParentOf(&span)
			if !ok {
				continue
			}
			assert.GreaterOrEqual(t, span.StartTime, parent.StartTime,
				"span %s starts before its parent %s", span.OperationName, parent.OperationName)
		}
	}
}

func TestSuite_FailedConnect(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-failed-connect.yml", path.Join(pathOutput, "test-suite-failed-connect.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	driveFailedConnectWorkload(t)

	t.Run("the workload is instrumented", testFailedConnectInstrumented)
	t.Run("a refused connect is reported", testRefusedConnectIsReported)
	t.Run("an idle pooled connection is not a failed connect", testIdlePooledConnectionIsNotAFailedConnect)
	t.Run("no span starts before its parent", testNoSpanStartsBeforeItsParent)

	require.NoError(t, compose.Close())
}
