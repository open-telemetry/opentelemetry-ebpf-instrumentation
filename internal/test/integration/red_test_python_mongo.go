// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

func testREDMetricsForPythonMongoLibrary(t *testing.T, testCase TestCase) {
	uri := testCase.Route
	urlPath := testCase.Subpath
	comm := testCase.Comm
	namespace := testCase.Namespace
	// Call 3 times the instrumented service, forcing it to:
	// - take a large JSON file
	// - returning a 200 code
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, uri+"/"+urlPath, 200)
	}

	// Eventually, Prometheus would make mongo operations visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	var err error
	for _, span := range testCase.Spans {
		operation := span.FindAttribute("db.operation.name")
		require.NotNil(t, operation, "db.operation.name attribute not found in span %s", span.Name)
		require.Eventually(t, func() bool {
			var err error
			results, err = pq.Query(`db_client_operation_duration_seconds_count{` +
				`db_operation_name="` + operation.Value.AsString() + `",` +
				`service_namespace="` + namespace + `"}`)
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
			return true
		}, testTimeout, 500*time.Millisecond, "MongoDB operation %s metrics not found", span.Name)
	}

	// Ensure we don't see any http requests
	results, err = pq.Query(`http_server_request_duration_seconds_count{}`)
	require.NoError(t, err, "failed to query prometheus for http_server_request_duration_seconds_count")
	require.Empty(t, results, "expected no HTTP requests, got %d", len(results))
	require.Eventually(t, func() bool {
		for _, span := range testCase.Spans {
			command := span.Name
			resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=" + url.QueryEscape(command))
			if err != nil {
				return false
			}
			if resp == nil {
				return false
			}
			if resp.StatusCode != http.StatusOK {
				return false
			}
			var tq jaeger.TracesQuery
			if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
				return false
			}
			var tags []jaeger.Tag
			for _, attr := range span.Attributes {
				tags = append(tags, otelAttributeToJaegerTag(attr))
			}
			traces := tq.FindBySpan(tags...)
			if len(traces) < 1 {
				return false
			}
		}
		return true
	}, testTimeout, 100*time.Millisecond, "MongoDB trace spans not found")

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

func testREDMetricsPythonMongoOnly(t *testing.T) {
	mongoCommonAttributes := []attribute.KeyValue{
		attribute.String("db.system.name", "mongodb"),
		attribute.String("span.kind", "client"),
		attribute.Int("server.port", 27017),
	}
	testCases := []TestCase{
		{
			Route:     "http://localhost:8381",
			Subpath:   "mongo",
			Comm:      "python3.14",
			Namespace: "integration-test",
			Spans: []TestCaseSpan{
				{
					Name: "insert mycollection",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "insert"),
						attribute.String("db.collection.name", "mycollection"),
						attribute.String("db.namespace", "mydatabase"),
					},
				},
				{
					Name: "update mycollection",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "update"),
						attribute.String("db.collection.name", "mycollection"),
						attribute.String("db.namespace", "mydatabase"),
					},
				},
				{
					Name: "delete mycollection",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "delete"),
						attribute.String("db.collection.name", "mycollection"),
						attribute.String("db.namespace", "mydatabase"),
					},
				},
				{
					Name: "find mycollection",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "find"),
						attribute.String("db.collection.name", "mycollection"),
						attribute.String("db.namespace", "mydatabase"),
					},
				},
			},
		},
	}
	for _, testCase := range testCases {
		// Add common attributes to each span
		for i := range testCase.Spans {
			testCase.Spans[i].Attributes = append(testCase.Spans[i].Attributes, mongoCommonAttributes...)
		}

		t.Run(testCase.Route, func(t *testing.T) {
			waitForMongoTestComponents(t, testCase.Route, "/"+testCase.Subpath)
			testREDMetricsForPythonMongoLibrary(t, testCase)
		})
	}
}

func waitForMongoTestComponents(t *testing.T, url string, subpath string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.Eventually(t, func() bool {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		if err != nil {
			return false
		}
		r, err := testHTTPClient.Do(req)
		if err != nil {
			return false
		}
		if r.StatusCode != http.StatusOK {
			return false
		}

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`db_client_operation_duration_seconds_count{db_system_name="mongodb"}`)
		if err != nil {
			return false
		}
		if len(results) == 0 {
			return false
		}
		return true
	}, 1*time.Minute, time.Second, "MongoDB test components not ready")
}
