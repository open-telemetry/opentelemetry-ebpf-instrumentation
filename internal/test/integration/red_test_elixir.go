// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

// does a smoke test to verify that all the components that started
// asynchronously for the Elixir test are up and communicating properly
func waitForElixirTestComponents(t *testing.T, url string) {
	waitForTestComponentsSub(t, url, "/smoke")
}

func testREDMetricsForElixirHTTPLibrary(t *testing.T, url string, comm string) {
	path := "/test"

	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result

	// Call 4 times the instrumented service, forcing it to:
	// - process multiple calls in a row with, one more than we might need
	// - returning a 200 code
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, fmt.Sprintf("%s%s/%d", url, path, i), 200)
	}

	// Eventually, Prometheus would make this query visible
	require.Eventually(t, func() bool {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="` + comm + `",` +
			`http_route="/test/:test_id"}`)
		if err != nil {
			return false
		}
		if len(results) == 0 {
			return false
		}
		val := totalPromCount(t, results)
		if val < 3 {
			return false
		}
		if len(results) > 0 {
			res := results[0]
			if res.Metric["client_address"] == nil {
				return false
			}
		}
		return true
	}, testTimeout, 500*time.Millisecond, "Elixir HTTP metrics not found")
}

func testREDMetricsElixirHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:4000",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForElixirTestComponents(t, testCaseURL)
			testREDMetricsForElixirHTTPLibrary(t, testCaseURL, "beam.smp")
		})
	}
}
