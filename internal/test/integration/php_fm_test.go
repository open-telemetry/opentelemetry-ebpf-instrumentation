// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

// does a smoke test to verify that all the components that started
// asynchronously for the Elixir test are up and communicating properly
func waitForPHPTestComponents(t *testing.T, url string) {
	waitForTestComponentsSub(t, url, "/status")
}

func waitForPHPTraceTestComponents(t *testing.T, url string) {
	waitForTestComponentsSubStatus(t, url, "/hello", 404)
	waitForSQLTestComponentsMySQL(t, url, "/")
}

func testREDMetricsForPHPHTTPLibrary(t *testing.T, url string, nginx, php string) {
	path := "/ping"

	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result

	// Call 4 times the instrumented service, forcing it to:
	// - process multiple calls in a row with, one more than we might need
	// - returning a 200 code
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, fmt.Sprintf("%s%s", url, path), 200)
	}

	// Eventually, Prometheus would make this query visible
	require.Eventually(t, func() bool {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="` + nginx + `",` +
			`http_route="/ping"}`)
		if err != nil {
			return false
		}
		if !enoughPromResultsCheck(results) {
			return false
		}
		val := totalPromCount(t, results)
		return val >= 3
	}, testTimeout, 500*time.Millisecond, "failed to find nginx http metrics")
	require.Eventually(t, func() bool {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="` + php + `",` +
			`http_route="/ping"}`)
		if err != nil {
			return false
		}
		if !enoughPromResultsCheck(results) {
			return false
		}
		val := totalPromCount(t, results)
		return val >= 3
	}, testTimeout, 500*time.Millisecond, "failed to find php-fpm http metrics")
	require.Eventually(t, func() bool {
		var err error
		results, err = pq.Query(`http_client_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="` + nginx + `",` +
			`http_route="/ping"}`)
		if err != nil {
			return false
		}
		if !enoughPromResultsCheck(results) {
			return false
		}
		val := totalPromCount(t, results)
		return val >= 3
	}, testTimeout, 500*time.Millisecond, "failed to find client http metrics")
}

func testREDMetricsPHPFPM(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8080",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForPHPTestComponents(t, testCaseURL)
			testREDMetricsForPHPHTTPLibrary(t, testCaseURL, "nginx", "php-fpm")
		})
	}
}

func TestPHPFM(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-php-fpm.yml", path.Join(pathOutput, "test-suite-php-fpm.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`)
	require.NoError(t, compose.Up())

	t.Run("PHP-FM RED metrics", testREDMetricsPHPFPM)

	require.NoError(t, compose.Close())
}

func testHTTPTracesPHP(t *testing.T) {
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, "http://localhost:8080/", 200)
	}

	var trace jaeger.Trace
	require.Eventually(t, func() bool {
		resp, err := http.Get(jaegerQueryURL + "?service=nginx&operation=GET%20%2F")
		if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
			return false
		}
		var tq jaeger.TracesQuery
		if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
			return false
		}
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/"})
		if len(traces) < 1 {
			return false
		}
		trace = traces[len(traces)-1]

		// Check the information of the parent span
		res := trace.FindByOperationNameAndService("GET /", "nginx")
		if len(res) != 2 {
			return false
		}
		parent := res[0]
		if parent.TraceID == "" || parent.SpanID == "" {
			return false
		}
		traceID := parent.TraceID
		// check duration is at least 2us
		if parent.Duration <= (2 * time.Microsecond).Microseconds() {
			return false
		}

		res = trace.FindByOperationNameAndService("GET /", "php-fpm")
		if len(res) != 1 {
			return false
		}

		parent = res[0]
		if parent.TraceID == "" || parent.SpanID == "" || traceID != parent.TraceID {
			return false
		}

		res = trace.FindByOperationNameAndService("SELECT accounts", "php-fpm")
		if len(res) != 1 {
			return false
		}

		parent = res[0]
		return parent.TraceID != "" && traceID == parent.TraceID && parent.SpanID != ""
	}, testTimeout, 500*time.Millisecond, "failed to verify PHP traces")
}

func testTracesPHPFPM(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8080",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForPHPTraceTestComponents(t, testCaseURL)
			testHTTPTracesPHP(t)
		})
	}
}

func TestPHPFMUnixSock(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-php-fpm-sock.yml", path.Join(pathOutput, "test-suite-php-fpm-sock.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`)
	require.NoError(t, compose.Up())

	t.Run("PHP-FM RED metrics", testTracesPHPFPM)

	require.NoError(t, compose.Close())
}
