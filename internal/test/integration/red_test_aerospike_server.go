// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

// The Jaeger service name is the instrumented executable: the aerospike
// server daemon.
const aerospikeServerService = "asd"

// testREDTracesAerospikeServerSide verifies the server-side view: OBI
// instruments the aerospike server process (asd), not the java client, so
// every operation must be reported as a server span. The error operation must
// carry the response result_code even though no capture buffer size is
// configured: the server writes each response in a single send.
// Server-side metrics (db.server.operation.duration) are wired in a follow-up;
// this test asserts traces only and pins the metric absence meanwhile.
func testREDTracesAerospikeServerSide(t *testing.T) {
	baseURL := "http://localhost:8392"

	for range 4 {
		ti.DoHTTPGet(t, baseURL+"/aerospike", 200)
	}

	spans := []TestCaseSpan{
		{Name: "PUT test.demo", Attributes: []attribute.KeyValue{
			attribute.String("db.operation.name", "PUT"),
		}},
		// The create-only PUT on an existing record: the server-side span must
		// report the result_code without any capture buffer configured.
		{Name: "PUT test.demo", Attributes: []attribute.KeyValue{
			attribute.String("db.operation.name", "PUT"),
			attribute.String("db.response.status_code", "KEY_EXISTS_ERROR"),
		}},
		{Name: "GET test.demo", Attributes: []attribute.KeyValue{attribute.String("db.operation.name", "GET")}},
		{Name: "DELETE test.demo", Attributes: []attribute.KeyValue{attribute.String("db.operation.name", "DELETE")}},
		{Name: "SCAN test.demo", Attributes: []attribute.KeyValue{attribute.String("db.operation.name", "SCAN")}},
	}
	commonAttributes := []attribute.KeyValue{
		attribute.String("db.system.name", "aerospike"),
		attribute.String("span.kind", "server"),
		attribute.String("db.namespace", "test"),
		attribute.String("db.collection.name", "demo"),
	}
	for i := range spans {
		spans[i].Attributes = append(spans[i].Attributes, commonAttributes...)
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for _, span := range spans {
			resp, err := http.Get(jaegerQueryURL + "?service=" + aerospikeServerService + "&operation=" + url.QueryEscape(span.Name))
			require.NoError(ct, err, "failed to query jaeger for %s", span.Name)
			if resp == nil {
				return
			}
			require.Equal(ct, http.StatusOK, resp.StatusCode, "unexpected status code for %s: %d", span.Name, resp.StatusCode)
			var tq jaeger.TracesQuery
			require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq), "failed to decode jaeger response for %s", span.Name)
			var tags []jaeger.Tag
			for _, attr := range span.Attributes {
				tags = append(tags, otelAttributeToJaegerTag(attr))
			}
			traces := tq.FindBySpan(tags...)
			assert.LessOrEqual(ct, 1, len(traces), "server span %s with tags %v not found in traces %v", span.Name, tags, tq.Data)
		}
	}, testTimeout, 100*time.Millisecond)

	// The java client is not instrumented, so no client-side metric may exist.
	pq := promtest.Client{HostPort: prometheusHostPort}
	results, err := pq.Query(`db_client_operation_duration_seconds_count{}`)
	require.NoError(t, err, "failed to query prometheus for db_client_operation_duration_seconds_count")
	require.Empty(t, results, "expected no client-side db operations, got %d", len(results))

	// Server-side metric routing lands in a follow-up PR; this assertion is
	// meant to flip to a positive check there.
	results, err = pq.Query(`db_server_operation_duration_seconds_count{db_system_name="aerospike"}`)
	require.NoError(t, err, "failed to query prometheus for db_server_operation_duration_seconds_count")
	require.Empty(t, results, "server-side metric not wired yet, expected no series, got %d", len(results))
}

// waitForAerospikeServerTestComponents cannot wait on a db metric (none is
// emitted server-side yet), so it waits for the first server span instead.
func waitForAerospikeServerTestComponents(t *testing.T, baseURL string) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// the test service endpoint is healthy (each hit drives the aerospike ops)
		req, err := http.NewRequest(http.MethodGet, baseURL+"/aerospike", nil)
		require.NoError(ct, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, r.StatusCode)

		// a server span reached Jaeger (OBI + collector are healthy)
		resp, err := http.Get(jaegerQueryURL + "?service=" + aerospikeServerService + "&operation=" + url.QueryEscape("PUT test.demo"))
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		require.NotEmpty(ct, tq.Data)
	}, 1*time.Minute, time.Second)
}
