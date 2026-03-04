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
	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		results, err = pq.Query(`obi_stat_tcp_rtt_seconds_bucket{` +
			`dst_port="` + port + `"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		val := totalPromCount(ct, results)
		assert.LessOrEqual(ct, 1, val)

		results, err = pq.Query(`obi_stat_tcp_rtt_seconds_count{` +
			`dst_port="` + port + `"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		val = totalPromCount(ct, results)
		assert.LessOrEqual(ct, 1, val)
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
