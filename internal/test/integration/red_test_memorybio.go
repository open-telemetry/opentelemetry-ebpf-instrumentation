// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

const (
	memoryBIOAppURL = "http://localhost:8090/"
	// The only host the instrumented app ever calls, so every client span must name
	// it.
	memoryBIOUpstreamPort = "8380"
	memoryBIOService      = "memorybio"

	// Concurrency is what puts the attribution under test: the event loop must be
	// serving an inbound request at the moment the outbound ciphertext reaches the
	// socket, which a serial driver never arranges.
	memoryBIOConcurrency = 150
	memoryBIORequests    = 1500

	// Attribution is exercised at a stochastic rate - between 3% and 12% for asyncio
	// and around 80% for Node - so the assertion covers every client span over a
	// sample large enough that even the low end of that range appears many times.
	memoryBIOMinObserved = 500
)

// testMemoryBIOTLSClientPeer drives concurrent load through an app that makes one
// outbound TLS call per inbound request, and requires every resulting client span to
// name the upstream server.
//
// Memory-BIO TLS stacks (asyncio's ssl.MemoryBIO, Node's TLSWrap) hand the ciphertext
// to the event loop, which writes it once the SSL_write uprobe has returned, so the
// binding has to come from the ciphertext itself. Under concurrency the thread's most
// recent connection is the inbound request being served, which is what makes the peer
// on a client span worth asserting.
func testMemoryBIOTLSClientPeer(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}

	// Warm up serially until OBI reports a client span, so the measured load runs
	// against instrumentation that saw every connection established. One request at a
	// time leaves the sample clean, since the attribution under test needs an inbound
	// request in flight to be exercised at all.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		callMemoryBIOApp(ct)
		results, err := pq.Query(memoryBIOClientCount(""))
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, testTimeout, 100*time.Millisecond)

	driveMemoryBIOLoad(t)

	// Let the last spans of the run make it through the exporter and one scrape.
	waitForMemoryBIOMetricsToSettle(t, pq)

	// Every client span counts toward the sample: one outbound call is made per
	// inbound request, so the total is what says whether the load ran.
	total := memoryBIOCount(t, pq, memoryBIOClientCount(""))
	require.GreaterOrEqualf(t, total, memoryBIOMinObserved,
		"only %d client spans were recorded; the sample is too small to conclude anything", total)
	correct := memoryBIOCount(t, pq, memoryBIOClientCount(`,server_port="`+memoryBIOUpstreamPort+`"`))

	// Every client span must name the upstream. A single one that does not is the
	// defect: there is nothing else this app calls.
	results, err := pq.Query(memoryBIOClientCount(`,server_port!="` + memoryBIOUpstreamPort + `"`))
	require.NoError(t, err)
	assert.Emptyf(t, results, "client spans named a peer other than the upstream: %s\n%d spans named the upstream",
		describeMemoryBIOPeers(results), correct)

	assertMemoryBIOTraces(t)
}

func memoryBIOClientCount(extraLabels string) string {
	return fmt.Sprintf(`http_client_request_duration_seconds_count{service_name=%q,service_namespace="integration-test"%s}`,
		memoryBIOService, extraLabels)
}

func memoryBIOCount(t require.TestingT, pq promtest.Client, query string) int {
	results, err := pq.Query(query)
	require.NoError(t, err)
	if len(results) == 0 {
		return 0
	}
	return totalPromCount(t, results)
}

// describeMemoryBIOPeers renders the offending peers so a failure names the address
// and port the spans were attributed to.
func describeMemoryBIOPeers(results []promtest.Result) string {
	var lines []string
	for _, r := range results {
		lines = append(lines, fmt.Sprintf("  server.address=%q server.port=%q",
			r.Metric["server_address"], r.Metric["server_port"]))
	}
	sort.Strings(lines)
	return "\n" + strings.Join(lines, "\n")
}

func driveMemoryBIOLoad(_ *testing.T) {
	var wg sync.WaitGroup
	requests := make(chan struct{}, memoryBIORequests)
	for range memoryBIORequests {
		requests <- struct{}{}
	}
	close(requests)

	for range memoryBIOConcurrency {
		wg.Go(func() {
			client := &http.Client{Timeout: 10 * time.Second}
			for range requests {
				resp, err := client.Get(memoryBIOAppURL)
				if err != nil {
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		})
	}
	wg.Wait()
}

func callMemoryBIOApp(t require.TestingT) {
	resp, err := http.Get(memoryBIOAppURL)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// waitForMemoryBIOMetricsToSettle waits until the client span count stops growing, so
// the assertion runs against the complete sample.
func waitForMemoryBIOMetricsToSettle(t *testing.T, pq promtest.Client) {
	previous, stable := -1, 0
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		current := memoryBIOCount(ct, pq, memoryBIOClientCount(""))
		if current == previous && current > 0 {
			stable++
		} else {
			stable = 0
		}
		previous = current
		require.GreaterOrEqual(ct, stable, 3)
	}, testTimeout, time.Second)
}

// assertMemoryBIOTraces repeats the assertion on the traces themselves: the metric
// labels and the span attributes are produced by different exporters, and it is the
// spans that a user reads.
func assertMemoryBIOTraces(t *testing.T) {
	resp, err := http.Get(fmt.Sprintf("%s?service=%s&limit=200", jaegerQueryURL, memoryBIOService))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tq jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))

	clientSpans := 0
	for _, trace := range tq.Data {
		for _, span := range trace.Spans {
			if kind, ok := jaeger.FindIn(span.Tags, "span.kind"); !ok || kind.Value != "client" {
				continue
			}
			clientSpans++
			port, ok := jaeger.FindIn(span.Tags, "server.port")
			assert.Truef(t, ok, "client span %s has no server.port", span.SpanID)
			assert.EqualValuesf(t, 8380, port.Value,
				"client span %s names port %v, and the upstream is 8380", span.SpanID, port.Value)
		}
	}
	assert.NotZero(t, clientSpans, "no client spans found in Jaeger")
}
