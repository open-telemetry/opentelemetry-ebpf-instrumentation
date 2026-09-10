// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"net/http"
	"path"
	"strconv"
	"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
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
	// The port of the second relay. Calls to it carry unparsed responses over one
	// connection that is never closed, which is the reuse case.
	reusedConnectionPort = 9300
	// The port of the second peer. The same pooled traffic with parsed responses: the
	// control that separates a loss caused by the unparsed response from one caused by
	// reuse itself.
	reusedControlPort = 9400
	// The port of the peer whose answer the workload never reads. The response arrives
	// and no probe sees it, so the record is finished by the close instead: the one case
	// whose duration runs past the request it describes.
	abandonedPeerPort = 9500
)

// The service graph names the far side of a call by the host it was made to, which is
// the compose service name.
const abandonedPeerService = "abandonpeer"

// reuseStats mirrors what the workload reports at /stats.
type reuseStats struct {
	Calls         int   `json:"calls"`
	Done          bool  `json:"done"`
	Connections   int   `json:"connections"`
	Aborts        int   `json:"aborts"`
	MaxCallMicros int64 `json:"maxCallMicros"`
}

// workloadReuseStats returns the workload's counts for the unparsed case and for the
// parsed control, keyed as the workload reports them.
func workloadReuseStats(t require.TestingT) map[string]reuseStats {
	resp, err := http.Get("http://localhost:8080/stats")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	stats := map[string]reuseStats{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&stats))

	return stats
}

// The limit is explicit because the reuse case produces a trace per call: Jaeger returns
// 20 traces by default, which silently caps the count the assertions are built on.
func unobservedResponseTraces(t require.TestingT) []jaeger.Trace {
	resp, err := http.Get(jaegerQueryURL + "?service=responseobservationclient&limit=1000")
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

	// The pooled runs go last: the spans of the requests above are what prove
	// instrumentation is attached, and traffic before that proves nothing.
	ti.DoHTTPGet(t, "http://localhost:8080/start-reuse", 200)
}

// finishedReuseStats waits for both pooled runs to complete, so the counts the
// assertions compare against are final.
func finishedReuseStats(t *testing.T) map[string]reuseStats {
	var stats map[string]reuseStats

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		stats = workloadReuseStats(ct)
		assert.True(ct, stats["unparsed"].Done && stats["parsed"].Done,
			"the workload is still making pooled calls")
	}, testTimeout, 200*time.Millisecond)

	return stats
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

// The reuse case. The socket carries call after call and never closes, so no close
// finishes a record: the next request does. Each call must still produce a span.
//
// The defect emitted one span per connection instead of one per request, so the
// workload's own connection count is the discriminator. Asserting only "some spans
// exist" would have passed against the defect.
func testReusedConnectionReportsEveryCall(t *testing.T) {
	stats := finishedReuseStats(t)["unparsed"]
	require.Positive(t, stats.Calls, "the workload made no calls over a reused connection")
	require.Zero(t, stats.Aborts, "the calls themselves failed, so there is nothing to observe")
	require.Less(t, stats.Connections, stats.Calls,
		"the connection was not reused, so this run does not exercise the case")

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		spans := clientSpansToPort(unobservedResponseTraces(ct), reusedConnectionPort)
		assert.GreaterOrEqual(ct, len(spans), stats.Calls,
			"%d calls over %d connections produced %d spans",
			stats.Calls, stats.Connections, len(spans))
	}, testTimeout, 100*time.Millisecond)
}

// The control: the same pooled traffic with responses OBI parses normally. It separates
// a call lost to the unparsed response from one lost to reuse itself, and it is what
// makes the count above meaningful.
func testReuseControlReportsEveryCall(t *testing.T) {
	stats := finishedReuseStats(t)["parsed"]
	require.Positive(t, stats.Calls)
	require.Less(t, stats.Connections, stats.Calls, "the control connection was not reused")

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		spans := clientSpansToPort(unobservedResponseTraces(ct), reusedControlPort)
		assert.GreaterOrEqual(ct, len(spans), stats.Calls,
			"%d parsed calls over %d connections produced %d spans",
			stats.Calls, stats.Connections, len(spans))
	}, testTimeout, 100*time.Millisecond)
}

// The reuse case reports no status either, for the same reason as the relay case: no
// response was parsed. A fabricated status here would be the #3067 defect on a new path.
func testReusedConnectionCarriesNoStatusCode(t *testing.T) {
	spans := clientSpansToPort(unobservedResponseTraces(t), reusedConnectionPort)
	require.NotEmpty(t, spans, "there is nothing to assert the absence of a status on")

	for _, span := range spans {
		status, ok := jaeger.FindIn(span.Tags, "http.response.status_code")
		assert.False(t, ok, "a call whose response was not observed reports a status: %v", status.Value)

		assert.Empty(t, span.Diff(
			jaeger.Tag{Key: "obi.http.response.observed", Type: "bool", Value: false}))
	}
}

// A record could be emitted by dating it at the next request's arrival, which reports a
// call that took milliseconds as one that took as long as the caller's think time. The
// duration comes from the response's own bytes instead, so it stays within reach of what
// the application measured.
func testReusedConnectionDurationsAreBounded(t *testing.T) {
	stats := finishedReuseStats(t)["unparsed"]
	require.Positive(t, stats.MaxCallMicros, "the workload timed no calls")

	spans := clientSpansToPort(unobservedResponseTraces(t), reusedConnectionPort)
	require.NotEmpty(t, spans, "there is nothing to bound")

	// Five times the slowest call the application itself timed. Wide enough to absorb
	// probe overhead, far below the think time a next-request timestamp would produce.
	const slack = 5

	for _, span := range spans {
		assert.LessOrEqual(t, span.Duration, stats.MaxCallMicros*slack,
			"a span lasts %dus where the slowest call the application timed took %dus",
			span.Duration, stats.MaxCallMicros)
	}
}

// The call whose answer arrives into a socket nobody reads. Only the socket's byte
// counter says a response came, so the record is finished by the close and its duration
// runs to the close rather than to the answer. The call still happened, so it is still
// reported, and it carries no status because none was read.
func testAbandonedResponseIsReportedWithoutStatus(t *testing.T) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		spans := clientSpansToPort(unobservedResponseTraces(ct), abandonedPeerPort)
		if !assert.NotEmpty(ct, spans, "a call whose response went unread produced no span") {
			return
		}

		for _, span := range spans {
			status, ok := jaeger.FindIn(span.Tags, "http.response.status_code")
			assert.False(ct, ok,
				"a call whose response was never read reports a status: %v", status.Value)

			assert.Empty(ct, span.Diff(
				jaeger.Tag{Key: "obi.http.response.observed", Type: "bool", Value: false}))
		}
	}, testTimeout, 100*time.Millisecond)
}

// promSeries returns the series a query holds once it has any, so the assertions do
// not race the scrape interval.
func promSeries(t *testing.T, query string) []promtest.Result {
	pq := promtest.Client{HostPort: prometheusHostPort}

	var results []promtest.Result
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		results, err = pq.Query(query)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, testTimeout, 100*time.Millisecond)

	return results
}

// A withheld duration must not take unrelated metrics down with it. This gauge reports
// that the host is running, which no call's duration has a say in.
//
// The workload also makes calls that are measured, so this only proves the gauge is
// exported at all. What proves it survives a service whose every call is unmeasured is
// TestAppMetrics_TracesHostInfoUnmeasuredSpans, which drives that service directly.
func testHostInfoIsExported(t *testing.T) {
	promSeries(t, `traces_host_info{}`)
}

// The service graph edge to the abandoned peer exists and is counted, because the call
// was made. Its latency is withheld, because the record's duration runs to the close.
// Dropping the span whole would erase an edge that a service really does talk to.
func testUnmeasuredCallCountsOnItsEdgeWithoutLatency(t *testing.T) {
	counted := promSeries(t,
		`traces_service_graph_request_total{server="`+abandonedPeerService+`"}`)
	require.NotEmpty(t, counted, "the edge a call traveled is missing from the service graph")

	pq := promtest.Client{HostPort: prometheusHostPort}
	latencies, err := pq.Query(
		`traces_service_graph_request_client_seconds_count{server="` + abandonedPeerService + `"}`)
	require.NoError(t, err)
	assert.Empty(t, latencies,
		"a duration that runs to the close of the socket was published as the call's latency")
}

// The RED series separates the two ways a response goes unobserved. The relay's answer
// arrives and is read, so the record ends at those bytes and the duration is a
// measurement worth publishing. The abandoned answer is never read, so the record ends
// at the close and the duration is withheld.
func testUnmeasuredCallPublishesNoDuration(t *testing.T) {
	promSeries(t, `http_client_request_duration_seconds_count{server_port="`+
		strconv.Itoa(unobservedPeerPort)+`"}`)

	pq := promtest.Client{HostPort: prometheusHostPort}
	withheld, err := pq.Query(`http_client_request_duration_seconds_count{server_port="` +
		strconv.Itoa(abandonedPeerPort) + `"}`)
	require.NoError(t, err)
	assert.Empty(t, withheld,
		"a duration that runs past the request it describes was published as the call's duration")
}

// A withheld duration says nothing about the request that was sent. Its size is known
// and is reported. The response size is not known: the record carries a zeroed length,
// and publishing it would report an empty response for a call whose response was never
// seen.
func testUnmeasuredCallStillPublishesItsRequestSize(t *testing.T) {
	promSeries(t, `http_client_request_body_size_bytes_count{server_port="`+
		strconv.Itoa(abandonedPeerPort)+`"}`)

	pq := promtest.Client{HostPort: prometheusHostPort}
	withheld, err := pq.Query(`http_client_response_body_size_bytes_count{server_port="` +
		strconv.Itoa(abandonedPeerPort) + `"}`)
	require.NoError(t, err)
	assert.Empty(t, withheld,
		"a response nobody saw was reported as having a size")
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
	t.Run("a reused connection with parsed responses reports every call", testReuseControlReportsEveryCall)
	t.Run("a reused connection reports every call", testReusedConnectionReportsEveryCall)
	t.Run("a reused connection carries no status code", testReusedConnectionCarriesNoStatusCode)
	t.Run("a reused connection's durations are bounded", testReusedConnectionDurationsAreBounded)
	t.Run("an abandoned response is reported without a status", testAbandonedResponseIsReportedWithoutStatus)

	// What a span reports and what a metric reports are decided in separate code, so
	// the same calls are checked on both sides.
	t.Run("the host info gauge is exported", testHostInfoIsExported)
	t.Run("an unmeasured call counts on its edge without a latency", testUnmeasuredCallCountsOnItsEdgeWithoutLatency)
	t.Run("an unmeasured call publishes no duration", testUnmeasuredCallPublishesNoDuration)
	t.Run("an unmeasured call still publishes its request size", testUnmeasuredCallStillPublishesItsRequestSize)

	require.NoError(t, compose.Close())
}
