// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

func testStatMetricsTCPRtt(t *testing.T, port string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		countResults, err := pq.Query(`obi_stat_tcp_rtt_seconds_count{dst_port="` + port + `"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, countResults)

		// pumba injects a 100ms delay on the testclient, so the average
		// observed RTT (sum/count, aggregated across all matching series)
		// should be at or above 100ms. The threshold is folded into the
		// PromQL: a comparison operator filters the result, so a non-empty
		// response means "the average exists and is >= 100ms". Asserting on
		// the average rather than a specific bucket boundary keeps the test
		// independent of the histogram's exact bucket layout.
		avgQuery := `sum(obi_stat_tcp_rtt_seconds_sum{dst_port="` + port + `"}) /` +
			` sum(obi_stat_tcp_rtt_seconds_count{dst_port="` + port + `"}) >= 0.1`
		avgResults, err := pq.Query(avgQuery)
		require.NoError(ct, err)
		enoughPromResults(ct, avgResults)
	}, testTimeout, 100*time.Millisecond)
}

func testStatMetricsTCPRttGo(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8381",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponentsTCP(t, testCaseURL)
			testStatMetricsTCPRtt(t, "8080")
		})
	}
}

func testStatMetricsTCPFailedConnectionGo(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_stat_tcp_failed_connections_total{dst_port="19999",network_tcp_handshake_role="client"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		assert.Positive(ct, totalPromCount(ct, results))
	}, testTimeout, 100*time.Millisecond)
}
