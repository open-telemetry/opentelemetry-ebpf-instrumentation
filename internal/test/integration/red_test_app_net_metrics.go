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

func testAppNetMetricsTCPRtt(t *testing.T, comm, namespace string) {
	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		results, err = pq.Query(`obi_net_tcp_rtt_seconds_bucket{` +
			`host_name="obi",` +
			`service_namespace="` + namespace + `",` +
			`service_name="` + comm + `"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		val := totalPromCount(ct, results)
		assert.LessOrEqual(ct, 1, val)

		results, err = pq.Query(`obi_net_tcp_rtt_seconds_count{` +
			`host_name="obi",` +
			`service_namespace="` + namespace + `",` +
			`service_name="` + comm + `"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		val = totalPromCount(ct, results)
		assert.LessOrEqual(ct, 1, val)
	}, testTimeout, 100*time.Millisecond)
}

func testAppNetMetricsTCPRttGo(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8381",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponentsTCP(t, testCaseURL)
			testAppNetMetricsTCPRtt(t, "testserver", "integration-test")
		})
	}
}

func testAppNetMetricsTCPRttPython(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8381",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponentsTCP(t, testCaseURL)
			testAppNetMetricsTCPRtt(t, "python3.14", "integration-test")
		})
	}
}
