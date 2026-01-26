// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

func testClientWithMethodAndStatusCode(t *testing.T, method string, statusCode int, traces bool) {
	// Eventually, Prometheus would make this query visible
	var (
		pq     = promtest.Client{HostPort: prometheusHostPort}
		labels = fmt.Sprintf(`http_request_method="%s",`, method) +
			fmt.Sprintf(`http_response_status_code="%d",`, statusCode) +
			`http_route="/oss/",` +
			`server_address="grafana.com",` +
			`service_namespace="integration-test",` +
			`service_name="pingclient"`
	)

	require.Eventually(t, func() bool {
		query := fmt.Sprintf("http_client_request_duration_seconds_count{%s}", labels)
		results, err := pq.Query(query)
		if err != nil || len(results) == 0 {
			return false
		}
		val := totalPromCount(t, results)
		return val >= 1
	}, testTimeout, 500*time.Millisecond, "http client request duration not found")

	require.Eventually(t, func() bool {
		query := fmt.Sprintf("http_client_request_body_size_bytes_count{%s}", labels)
		results, err := pq.Query(query)
		if err != nil || len(results) == 0 {
			return false
		}
		val := totalPromCount(t, results)
		return val >= 1
	}, testTimeout, 500*time.Millisecond, "http client request body size not found")

	require.Eventually(t, func() bool {
		query := fmt.Sprintf("http_client_response_body_size_bytes_count{%s}", labels)
		results, err := pq.Query(query)
		if err != nil || len(results) == 0 {
			return false
		}
		val := totalPromCount(t, results)
		return val >= 1
	}, testTimeout, 500*time.Millisecond, "http client response body size not found")

	if !traces {
		return
	}

	var trace jaeger.Trace
	require.Eventually(t, func() bool {
		resp, err := http.Get(jaegerQueryURL + fmt.Sprintf("?service=pingclient&operation=%s%%20/oss/", method))
		if err != nil || resp == nil {
			return false
		}
		if resp.StatusCode != http.StatusOK {
			return false
		}
		var tq jaeger.TracesQuery
		if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
			return false
		}
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(statusCode)})
		if len(traces) < 1 {
			return false
		}
		trace = traces[0]
		return true
	}, testTimeout, 100*time.Millisecond, "trace not found in jaeger")

	spans := trace.FindByOperationName(method+" /oss/", "")
	require.Len(t, spans, 1)
	parent := spans[0]

	addr, ok := jaeger.FindIn(parent.Tags, "server.address")
	assert.True(t, ok)
	assert.Equal(t, "grafana.com", addr.Value)

	addr, ok = jaeger.FindIn(parent.Tags, "server.port")
	assert.True(t, ok)
	assert.EqualValues(t, 443, addr.Value)
}

func testREDMetricsForClientHTTPLibrary(t *testing.T) {
	testClientWithMethodAndStatusCode(t, "GET", 200, true)
	testClientWithMethodAndStatusCode(t, "OPTIONS", 204, true)
}

func testREDMetricsForClientHTTPLibraryNoTraces(t *testing.T) {
	testClientWithMethodAndStatusCode(t, "GET", 200, false)
	testClientWithMethodAndStatusCode(t, "OPTIONS", 204, false)
}
