// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

// testREDMetricsRedisServerSide verifies the server-side view: OBI instruments
// the redis-server process (not the python client), so operations must be
// reported as db.server.operation.duration and never as the client metric.
func testREDMetricsRedisServerSide(t *testing.T) {
	url := "http://localhost:8381"
	urlPath := "redis"
	namespace := "integration-test"

	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, url+"/"+urlPath, 200)
	}

	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, operation := range []string{"HSET", "HGETALL", "SET", "GET"} {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			results, err := pq.Query(`db_server_operation_duration_seconds_count{` +
				`db_operation_name="` + operation + `",` +
				`db_system_name="redis",` +
				`service_namespace="` + namespace + `"}`)
			require.NoError(ct, err, "failed to query prometheus for %s", operation)
			enoughPromResults(ct, results)
			val := totalPromCount(ct, results)
			assert.LessOrEqual(ct, 3, val, "expected at least 3 %s operations, got %d", operation, val)
		}, testTimeout, 100*time.Millisecond)
	}

	// The python client is not instrumented, so the client-side metric must
	// not exist: server-side spans must not leak into it.
	results, err := pq.Query(`db_client_operation_duration_seconds_count{}`)
	require.NoError(t, err, "failed to query prometheus for db_client_operation_duration_seconds_count")
	require.Empty(t, results, "expected no client-side db operations, got %d", len(results))

	// Traces: the same operations must be visible as server spans of the
	// redis-server service.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=redis-server&operation=GET")
		require.NoError(ct, err, "failed to query jaeger for GET")
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode, "unexpected status code: %d", resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq), "failed to decode jaeger response")
		tags := []jaeger.Tag{
			otelAttributeToJaegerTag(attribute.String("db.system.name", "redis")),
			otelAttributeToJaegerTag(attribute.String("span.kind", "server")),
		}
		traces := tq.FindBySpan(tags...)
		assert.LessOrEqual(ct, 1, len(traces), "server GET span with tags %v not found in %v", tags, tq.Data)
	}, testTimeout, 100*time.Millisecond)
}

func waitForRedisServerTestComponents(t *testing.T, url string, subpath string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(ct, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, r.StatusCode)

		// now, verify that the server-side metric has been reported
		results, err := pq.Query(`db_server_operation_duration_seconds_count{db_system_name="redis"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, 1*time.Minute, time.Second)
}
