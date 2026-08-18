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
	// The port of the relay, which re-segments the response so instrumentation
	// never reads a status line. Calls through it are the unparsed case.
	unobservedPeerPort = 9100
	// The port of the peer itself. Calls straight to it are the control: the
	// same origin, the same 200, observed in full.
	observedPeerPort = 9000
	// The port of a peer that answers nothing and resets. Calls to it are the
	// absent case: no response exists at all.
	resettingPeerPort = 9200
)

func unobservedResponseTraces(t require.TestingT) []jaeger.Trace {
	resp, err := http.Get(jaegerQueryURL + "?service=responseobservationclient")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tq jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))

	return tq.Data
}

// The outbound calls are told apart by the port they went to, which is the only
// thing that differs between them.
func clientSpansToPort(traces []jaeger.Trace, port int) []jaeger.Span {
	var matches []jaeger.Span

	for i := range traces {
		for _, span := range traces[i].Spans {
			if kind, ok := jaeger.FindIn(span.Tags, "span.kind"); !ok || kind.Value != "client" {
				continue
			}
			if len(span.Diff(jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(port)})) == 0 {
				matches = append(matches, span)
			}
		}
	}

	return matches
}

func driveResponseObservationWorkload(t *testing.T) {
	for range 15 {
		ti.DoHTTPGet(t, "http://localhost:8080/work", 200)
		time.Sleep(500 * time.Millisecond)
	}
}

// The control. The same peer answered 200 on a socket whose response was read
// normally. It also confirms the workload is instrumented at all.
func testObservedResponseReportsItsStatus(t *testing.T) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		spans := clientSpansToPort(unobservedResponseTraces(ct), observedPeerPort)
		if !assert.NotEmpty(ct, spans) {
			return
		}
		for _, span := range spans {
			assert.Empty(ct, span.Diff(
				jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)}))
		}
	}, testTimeout, 100*time.Millisecond)
}

// The call happened, so it is still reported. The cheapest way to stop publishing a
// fabricated status is to stop publishing the span.
func testUnparsedResponseIsStillReported(t *testing.T) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.NotEmpty(ct, clientSpansToPort(unobservedResponseTraces(ct), unobservedPeerPort))
	}, testTimeout, 100*time.Millisecond)
}

// Nothing was observed to fail, so the span is not an error.
//
// The non-empty guard is this subtest's own. An absence assertion over an empty set
// passes having asserted nothing, and -failfast is a property of how the suite is
// invoked.
func testUnparsedResponseIsNotAnError(t *testing.T) {
	spans := clientSpansToPort(unobservedResponseTraces(t), unobservedPeerPort)
	require.NotEmpty(t, spans, "there is nothing to assert the absence of an error on")

	for _, span := range spans {
		status, ok := jaeger.FindIn(span.Tags, "otel.status_code")
		assert.False(t, ok && status.Value == "ERROR",
			"a call whose response was not observed is reported as failed: %v", status.Value)

		errored, ok := jaeger.FindIn(span.Tags, "error")
		assert.False(t, ok && errored.Value == true,
			"a call whose response was not observed is flagged as an error")
	}
}

// Semconv requires http.response.status_code "if and only if one was received/sent".
// Nothing was received, so there is no status, least of all 499.
func testUnparsedResponseCarriesNoStatusCode(t *testing.T) {
	spans := clientSpansToPort(unobservedResponseTraces(t), unobservedPeerPort)
	require.NotEmpty(t, spans, "there is nothing to assert the absence of a status on")

	for _, span := range spans {
		status, ok := jaeger.FindIn(span.Tags, "http.response.status_code")
		assert.False(t, ok, "a call whose response was not observed reports a status: %v", status.Value)
	}
}

// An absent status attribute reads the same as an exporter that dropped one.
func testUnparsedResponseIsMarked(t *testing.T) {
	spans := clientSpansToPort(unobservedResponseTraces(t), unobservedPeerPort)
	require.NotEmpty(t, spans)

	for _, span := range spans {
		assert.Empty(t, span.Diff(
			jaeger.Tag{Key: "obi.http.response.observed", Type: "bool", Value: false}))
	}
}

// Nothing comes back from this peer, and the record is finished at teardown.
//
// The span exists and reports no status. It is also not an error: OBI cannot tell this
// reset apart from a client that stopped waiting, because sk_err is consumed by the
// application's read before the close.
func testResetPeerReportsNoFabricatedStatus(t *testing.T) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		spans := clientSpansToPort(unobservedResponseTraces(ct), resettingPeerPort)
		if !assert.NotEmpty(ct, spans, "a call that was reset produced no span at all") {
			return
		}
		for _, span := range spans {
			status, ok := jaeger.FindIn(span.Tags, "http.response.status_code")
			assert.False(ct, ok,
				"a call nothing answered reports a status: %v", status.Value)

			otelStatus, ok := jaeger.FindIn(span.Tags, "otel.status_code")
			assert.False(ct, ok && otelStatus.Value == "ERROR",
				"a reset is reported as failed, which OBI cannot actually tell from a client giving up")
		}
	}, testTimeout, 100*time.Millisecond)
}

// The same marker the relay case carries, for the same reason.
func testResetPeerIsMarkedUnobserved(t *testing.T) {
	spans := clientSpansToPort(unobservedResponseTraces(t), resettingPeerPort)
	require.NotEmpty(t, spans, "there is nothing to assert the marker on")

	for _, span := range spans {
		assert.Empty(t, span.Diff(
			jaeger.Tag{Key: "obi.http.response.observed", Type: "bool", Value: false}))
	}
}

// The control must not pick the marker up.
func testObservedResponseIsNotMarked(t *testing.T) {
	spans := clientSpansToPort(unobservedResponseTraces(t), observedPeerPort)
	require.NotEmpty(t, spans, "there is nothing to assert the absence of the marker on")

	for _, span := range spans {
		_, ok := jaeger.FindIn(span.Tags, "obi.http.response.observed")
		assert.False(t, ok, "an observed call is marked as unobserved")
	}
}

func TestSuite_ResponseObservation(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-response-observation.yml", path.Join(pathOutput, "test-suite-unobserved-response.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	driveResponseObservationWorkload(t)

	t.Run("an observed response reports its status", testObservedResponseReportsItsStatus)
	t.Run("an unobserved response is still reported", testUnparsedResponseIsStillReported)
	t.Run("an unobserved response is not an error", testUnparsedResponseIsNotAnError)
	t.Run("an unobserved response carries no status code", testUnparsedResponseCarriesNoStatusCode)
	t.Run("an unobserved response is marked as such", testUnparsedResponseIsMarked)
	t.Run("an observed response is not marked", testObservedResponseIsNotMarked)
	t.Run("a reset peer reports no fabricated status", testResetPeerReportsNoFabricatedStatus)
	t.Run("a reset peer is marked unobserved", testResetPeerIsMarkedUnobserved)

	require.NoError(t, compose.Close())
}
