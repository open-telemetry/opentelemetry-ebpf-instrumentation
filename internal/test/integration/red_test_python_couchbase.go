// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

func testREDMetricsForPythonCouchbaseLibrary(t *testing.T, testCase TestCase) {
	uri := testCase.Route
	urlPath := testCase.Subpath
	comm := testCase.Comm
	namespace := testCase.Namespace

	// Call 4 times the instrumented service
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, uri+"/"+urlPath, 200)
	}

	// Eventually, Prometheus would make couchbase operations visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	var err error
	for _, span := range testCase.Spans {
		operation := span.FindAttribute("db.operation.name")
		require.NotNil(t, operation, "db.operation.name attribute not found in span %s", span.Name)
		test.Eventually(t, testTimeout, func(t require.TestingT) {
			var err error
			results, err = pq.Query(`db_client_operation_duration_seconds_count{` +
				`db_operation_name="` + operation.Value.AsString() + `",` +
				`service_namespace="` + namespace + `"}`)
			require.NoError(t, err, "failed to query prometheus for %s", span.Name)
			enoughPromResults(t, results)
			val := totalPromCount(t, results)
			assert.LessOrEqual(t, 3, val, "expected at least 3 %s operations, got %d", span.Name, val)
		})
	}

	// Ensure we don't see any http requests
	results, err = pq.Query(`http_server_request_duration_seconds_count{}`)
	require.NoError(t, err, "failed to query prometheus for http_server_request_duration_seconds_count")
	require.Empty(t, results, "expected no HTTP requests, got %d", len(results))

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		for _, span := range testCase.Spans {
			command := span.Name
			resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=" + url.QueryEscape(command))
			require.NoError(t, err, "failed to query jaeger for %s", command)
			if resp == nil {
				return
			}
			require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status code for %s: %d", command, resp.StatusCode)
			var tq jaeger.TracesQuery
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq), "failed to decode jaeger response for %s", command)
			var tags []jaeger.Tag
			for _, attr := range span.Attributes {
				tags = append(tags, otelAttributeToJaegerTag(attr))
			}
			traces := tq.FindBySpan(tags...)
			assert.LessOrEqual(t, 1, len(traces), "span %s with tags %v not found in traces in traces %v", command, tags, tq.Data)
		}
	}, test.Interval(100*time.Millisecond))

	// Ensure we don't find any HTTP traces, since we filter them out
	resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=GET%20%2F" + urlPath)
	require.NoError(t, err, "failed to query jaeger for HTTP traces")
	if resp == nil {
		return
	}
	require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status code for HTTP traces: %d", resp.StatusCode)
	var tq jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq), "failed to decode jaeger response for HTTP traces")
	traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/" + urlPath})
	require.Empty(t, traces, "expected no HTTP traces, got %d", len(traces))
}

func testREDMetricsPythonCouchbaseOnly(t *testing.T) {
	couchbaseCommonAttributes := []attribute.KeyValue{
		attribute.String("db.system.name", "couchbase"),
		attribute.String("span.kind", "client"),
		attribute.Int("server.port", 11210),
	}
	testCases := []TestCase{
		{
			Route:     "http://localhost:8381",
			Subpath:   "couchbase",
			Comm:      "python3.14",
			Namespace: "integration-test",
			Spans: []TestCaseSpan{
				{
					Name: "SET test-scope.test-collection",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "SET"),
						attribute.String("db.namespace", "test-bucket"),
						attribute.String("db.collection.name", "test-scope.test-collection"),
					},
				},
				{
					Name: "GET test-scope.test-collection",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "GET"),
						attribute.String("db.namespace", "test-bucket"),
						attribute.String("db.collection.name", "test-scope.test-collection"),
					},
				},
				{
					Name: "REPLACE test-scope.test-collection",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "REPLACE"),
						attribute.String("db.namespace", "test-bucket"),
						attribute.String("db.collection.name", "test-scope.test-collection"),
					},
				},
				{
					Name: "DELETE test-scope.test-collection",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "DELETE"),
						attribute.String("db.namespace", "test-bucket"),
						attribute.String("db.collection.name", "test-scope.test-collection"),
					},
				},
			},
		},
	}
	for _, testCase := range testCases {
		// Add common attributes to each span
		for i := range testCase.Spans {
			testCase.Spans[i].Attributes = append(testCase.Spans[i].Attributes, couchbaseCommonAttributes...)
		}

		t.Run(testCase.Route, func(t *testing.T) {
			waitForCouchbaseTestComponents(t, testCase.Route, "/"+testCase.Subpath)
			testREDMetricsForPythonCouchbaseLibrary(t, testCase)
		})
	}
}

func testREDMetricsPythonCouchbaseError(t *testing.T) {
	couchbaseCommonAttributes := []attribute.KeyValue{
		attribute.String("db.system.name", "couchbase"),
		attribute.String("span.kind", "client"),
		attribute.Int("server.port", 11210),
	}
	testCases := []TestCase{
		{
			Route:     "http://localhost:8381",
			Subpath:   "couchbase-error",
			Comm:      "python3.14",
			Namespace: "integration-test",
			Spans: []TestCaseSpan{
				{
					Name: "GET test-scope.test-collection",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "GET"),
						attribute.String("db.namespace", "test-bucket"),
						attribute.String("db.collection.name", "test-scope.test-collection"),
						attribute.String("db.response.status_code", "1"), // KEY_NOT_FOUND
					},
				},
			},
		},
	}
	for _, testCase := range testCases {
		// Add common attributes to each span
		for i := range testCase.Spans {
			testCase.Spans[i].Attributes = append(testCase.Spans[i].Attributes, couchbaseCommonAttributes...)
		}

		t.Run(testCase.Route, func(t *testing.T) {
			waitForCouchbaseTestComponents(t, testCase.Route, "/"+testCase.Subpath)
			testREDMetricsForPythonCouchbaseLibrary(t, testCase)
		})
	}
}

func waitForCouchbaseTestComponents(t *testing.T, url string, subpath string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	test.Eventually(t, 2*time.Minute, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(t, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`db_client_operation_duration_seconds_count{db_system_name="couchbase"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	}, test.Interval(time.Second))
}
