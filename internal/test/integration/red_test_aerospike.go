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

func testREDMetricsForAerospikeLibrary(t *testing.T, testCase TestCase) {
	baseURL := testCase.Route
	urlPath := testCase.Subpath
	comm := testCase.Comm
	namespace := testCase.Namespace

	// Drive the instrumented service a few times so each Aerospike operation runs.
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, baseURL+"/"+urlPath, 200)
	}

	// Prometheus should report the db client duration metric per operation.
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, span := range testCase.Spans {
		operation := span.FindAttribute("db.operation.name")
		require.NotNil(t, operation, "db.operation.name attribute not found in span %s", span.Name)
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			results, err := pq.Query(`db_client_operation_duration_seconds_count{` +
				`db_operation_name="` + operation.Value.AsString() + `",` +
				`db_system_name="aerospike",` +
				`service_namespace="` + namespace + `"}`)
			require.NoError(ct, err, "failed to query prometheus for %s", span.Name)
			enoughPromResults(ct, results)
			val := totalPromCount(ct, results)
			assert.LessOrEqual(ct, 3, val, "expected at least 3 %s operations, got %d", span.Name, val)
		}, testTimeout, 100*time.Millisecond)
	}

	// No HTTP server metrics should be produced (only aerospike is instrumented here).
	results, err := pq.Query(`http_server_request_duration_seconds_count{}`)
	require.NoError(t, err, "failed to query prometheus for http_server_request_duration_seconds_count")
	require.Empty(t, results, "expected no HTTP requests, got %d", len(results))

	// Jaeger should contain a span per operation with the expected attributes. The
	// span name (jaeger "operation") is "{db.operation.name} {db.namespace}.{db.collection.name}".
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for _, span := range testCase.Spans {
			resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=" + url.QueryEscape(span.Name))
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
			assert.LessOrEqual(ct, 1, len(traces), "span %s with tags %v not found in traces %v", span.Name, tags, tq.Data)
		}
	}, testTimeout, 100*time.Millisecond)
}

func testREDMetricsAerospikeOnly(t *testing.T) {
	commonAttributes := []attribute.KeyValue{
		attribute.String("db.system.name", "aerospike"),
		attribute.String("span.kind", "client"),
		attribute.String("db.namespace", "test"),
		attribute.String("db.collection.name", "demo"),
	}
	testCases := []TestCase{
		{
			Route:     "http://localhost:8390",
			Subpath:   "aerospike",
			Comm:      "java",
			Namespace: "integration-test",
			Spans: []TestCaseSpan{
				// PUT sends the key (sendKey), so db.query.text carries the primary key.
				{Name: "PUT test.demo", Attributes: []attribute.KeyValue{
					attribute.String("db.operation.name", "PUT"),
					attribute.String("db.query.text", "obi"),
				}},
				{Name: "GET test.demo", Attributes: []attribute.KeyValue{attribute.String("db.operation.name", "GET")}},
				{Name: "DELETE test.demo", Attributes: []attribute.KeyValue{attribute.String("db.operation.name", "DELETE")}},
				{Name: "SCAN test.demo", Attributes: []attribute.KeyValue{attribute.String("db.operation.name", "SCAN")}},
			},
		},
	}
	for _, testCase := range testCases {
		for i := range testCase.Spans {
			testCase.Spans[i].Attributes = append(testCase.Spans[i].Attributes, commonAttributes...)
		}
		t.Run(testCase.Route, func(t *testing.T) {
			waitForAerospikeTestComponents(t, testCase.Route, "/"+testCase.Subpath)
			testREDMetricsForAerospikeLibrary(t, testCase)
		})
	}
}

func waitForAerospikeTestComponents(t *testing.T, baseURL, subpath string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, baseURL+subpath, nil)
		require.NoError(ct, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, r.StatusCode)

		// the db client metric is visible (OTel + Prometheus are healthy)
		results, err := pq.Query(`db_client_operation_duration_seconds_count{db_system_name="aerospike"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, 1*time.Minute, time.Second)
}
