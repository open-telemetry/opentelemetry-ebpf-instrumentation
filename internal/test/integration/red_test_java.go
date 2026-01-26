// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

// does a smoke test to verify that all the components that started
// asynchronously for the Java test are up and communicating properly
func waitForJavaTestComponents(t *testing.T, url string) {
	waitForTestComponentsSub(t, url, "/greeting")
}

func testREDMetricsForJavaHTTPLibrary(t *testing.T, urls []string, comm string) {
	path := "/greeting"

	// Call 3 times the instrumented service, forcing it to:
	// - take at least 30ms to respond
	// - returning a 204 code
	for i := 0; i < 4; i++ {
		for _, url := range urls {
			ti.DoHTTPGet(t, url+path+"?delay=30&response=204", 204)
		}
	}

	commMatch := `service_name="` + comm + `",`
	namespaceMatch := `service_namespace="integration-test",`
	if comm == "" {
		commMatch = ""
		namespaceMatch = ""
	}

	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	require.Eventually(t, func() bool {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="204",` +
			namespaceMatch +
			commMatch +
			`url_path="` + path + `"}`)
		if err != nil {
			return false
		}
		// check duration_count has 3 calls and all the arguments
		if len(results) == 0 {
			return false
		}
		if len(results) > 0 {
			val := totalPromCount(t, results)
			if val < 3 {
				return false
			}

			res := results[0]
			if res.Metric["client_address"] == nil {
				return false
			}
		}
		return true
	}, testTimeout, 500*time.Millisecond, "Java HTTP metrics not found")
}

func testREDMetricsJavaHTTP(t *testing.T) {
	t.Run("http://localhost:8086", func(t *testing.T) {
		waitForJavaTestComponents(t, "http://localhost:8086")
		testREDMetricsForJavaHTTPLibrary(t, []string{"http://localhost:8086"}, "greeting")
	})
}
