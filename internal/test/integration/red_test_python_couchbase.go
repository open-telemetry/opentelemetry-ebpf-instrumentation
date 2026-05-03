// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

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
	for _, span := range testCase.Spans {
		operation := span.FindAttribute("db.operation.name")
		require.NotNil(t, operation, "db.operation.name attribute not found in span %s", span.Name)
		require.EventuallyWithT(t, func(t *assert.CollectT) {
			var err error
			results, err = pq.Query(`db_client_operation_duration_seconds_count{` +
				`db_operation_name="` + operation.Value.AsString() + `",` +
				`service_namespace="` + namespace + `"}`)
			require.NoError(t, err, "failed to query prometheus for %s", span.Name)
			enoughPromResults(t, results)
			val := totalPromCount(t, results)
			assert.LessOrEqual(t, 3, val, "expected at least 3 %s operations, got %d", span.Name, val)
		}, testTimeout, time.Second)
	}

	require.EventuallyWithT(t, func(t *assert.CollectT) {
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
	}, testTimeout, time.Second)
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
			// Verify db.query.text is emitted for KV operations. We check GET
			// and DELETE because their rendered format is the most stable
			// ("OP user::1"), and accept any prefix/suffix wrapping since the
			// exact bytes depend on whether collections are enabled and how
			// the SDK frames the key.
			assertCouchbaseDBQueryTextContains(t, testCase.Comm, "GET test-scope.test-collection", "GET ", "user::1")
			assertCouchbaseDBQueryTextContains(t, testCase.Comm, "DELETE test-scope.test-collection", "DELETE ", "user::1")
		})
	}
}

// assertCouchbaseDBQueryTextContains fetches traces from Jaeger for the given
// operation name and verifies at least one span has a db.query.text attribute
// whose value starts with wantPrefix and contains wantKey.
func assertCouchbaseDBQueryTextContains(t *testing.T, comm, operation, wantPrefix, wantKey string) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=" + url.QueryEscape(operation))
		require.NoError(ct, err)
		if err != nil || resp == nil {
			return
		}
		defer resp.Body.Close()

		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		var found bool
		for _, tr := range tq.Data {
			for _, sp := range tr.Spans {
				tag, ok := jaeger.FindIn(sp.Tags, "db.query.text")
				if !ok {
					continue
				}
				v, isStr := tag.Value.(string)
				if !isStr {
					continue
				}
				if strings.HasPrefix(v, wantPrefix) && strings.Contains(v, wantKey) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		assert.True(ct, found, "no span with db.query.text starting %q and containing %q found for operation %q", wantPrefix, wantKey, operation)
	}, testTimeout, time.Second)
}

func testREDMetricsPythonCouchbaseDefaultCollection(t *testing.T) {
	couchbaseCommonAttributes := []attribute.KeyValue{
		attribute.String("db.system.name", "couchbase"),
		attribute.String("span.kind", "client"),
		attribute.Int("server.port", 11210),
	}
	testCases := []TestCase{
		{
			Route:     "http://localhost:8381",
			Subpath:   "couchbase-default",
			Comm:      "python3.14",
			Namespace: "integration-test",
			Spans: []TestCaseSpan{
				{
					Name: "SET",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "SET"),
						attribute.String("db.namespace", "test-bucket"),
					},
				},
				{
					Name: "GET",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "GET"),
						attribute.String("db.namespace", "test-bucket"),
					},
				},
				{
					Name: "DELETE",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "DELETE"),
						attribute.String("db.namespace", "test-bucket"),
					},
				},
			},
		},
	}
	for _, testCase := range testCases {
		for i := range testCase.Spans {
			testCase.Spans[i].Attributes = append(testCase.Spans[i].Attributes, couchbaseCommonAttributes...)
		}

		t.Run(testCase.Route, func(t *testing.T) {
			waitForCouchbaseTestComponents(t, testCase.Route, "/"+testCase.Subpath)
			testREDMetricsForPythonCouchbaseLibrary(t, testCase)
			// Verify db.query.text for default collection (no GET_COLLECTION_ID
			// negotiation — tests the Bucket-based heuristic for LEB128 stripping).
			// Uses user::2 (not user::1) to avoid matching named-collection spans
			// from testREDMetricsPythonCouchbaseOnly which run in the same compose.
			assertCouchbaseDBQueryTextContains(t, testCase.Comm, "GET", "GET ", "user::2")
			assertCouchbaseDBQueryTextContains(t, testCase.Comm, "DELETE", "DELETE ", "user::2")
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
	require.EventuallyWithT(t, func(t *assert.CollectT) {
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
	}, testTimeout, time.Second)
}

// testREDMetricsPythonCouchbaseSQLPP tests SQL++ (N1QL) queries via HTTP API
func testREDMetricsPythonCouchbaseSQLPP(t *testing.T) {
	sqlppCommonAttributes := []attribute.KeyValue{
		attribute.String("db.system.name", "couchbase"),
		attribute.String("span.kind", "client"),
	}
	testCases := []TestCase{
		{
			Route:     "http://localhost:8381",
			Subpath:   "sqlpp",
			Comm:      "python3.14",
			Namespace: "integration-test",
			Spans: []TestCaseSpan{
				{
					Name: "INSERT test-scope.test-collection",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "INSERT"),
						attribute.String("db.namespace", "test-bucket"),
						attribute.String("db.collection.name", "test-scope.test-collection"),
					},
				},
				{
					Name: "SELECT test-scope.test-collection",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "SELECT"),
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
			testCase.Spans[i].Attributes = append(testCase.Spans[i].Attributes, sqlppCommonAttributes...)
		}

		t.Run(testCase.Route, func(t *testing.T) {
			waitForCouchbaseSQLPPTestComponents(t, testCase.Route, "/"+testCase.Subpath)
			testREDMetricsForCouchbaseSQLPP(t, testCase)
		})
	}
}

// testREDMetricsPythonCouchbaseSQLPPError tests SQL++ (N1QL) queries that return errors
func testREDMetricsPythonCouchbaseSQLPPError(t *testing.T) {
	sqlppCommonAttributes := []attribute.KeyValue{
		attribute.String("db.system.name", "couchbase"),
		attribute.String("span.kind", "client"),
	}
	testCases := []TestCase{
		{
			Route:     "http://localhost:8381",
			Subpath:   "sqlpp-error",
			Comm:      "python3.14",
			Namespace: "integration-test",
			Spans: []TestCaseSpan{
				{
					Name: "SELECT nonexistent-scope.nonexistent-collection",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "SELECT"),
						attribute.String("db.namespace", "nonexistent-bucket"),
						attribute.String("db.collection.name", "nonexistent-scope.nonexistent-collection"),
						attribute.String("db.response.status_code", "12003"), // Keyspace not found
					},
				},
			},
		},
	}
	for _, testCase := range testCases {
		// Add common attributes to each span
		for i := range testCase.Spans {
			testCase.Spans[i].Attributes = append(testCase.Spans[i].Attributes, sqlppCommonAttributes...)
		}

		t.Run(testCase.Route, func(t *testing.T) {
			waitForCouchbaseSQLPPTestComponents(t, testCase.Route, "/"+testCase.Subpath)
			testREDMetricsForCouchbaseSQLPP(t, testCase)
		})
	}
}

// testREDMetricsPythonCouchbaseSQLPPWithContext tests SQL++ queries using query_context
func testREDMetricsPythonCouchbaseSQLPPWithContext(t *testing.T) {
	sqlppCommonAttributes := []attribute.KeyValue{
		attribute.String("db.system.name", "couchbase"),
		attribute.String("span.kind", "client"),
	}
	testCases := []TestCase{
		{
			Route:     "http://localhost:8381",
			Subpath:   "sqlpp-with-context",
			Comm:      "python3.14",
			Namespace: "integration-test",
			Spans: []TestCaseSpan{
				{
					Name: "SELECT test-collection",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "SELECT"),
						attribute.String("db.namespace", "test-bucket"),
						attribute.String("db.collection.name", "test-collection"),
					},
				},
			},
		},
	}
	for _, testCase := range testCases {
		// Add common attributes to each span
		for i := range testCase.Spans {
			testCase.Spans[i].Attributes = append(testCase.Spans[i].Attributes, sqlppCommonAttributes...)
		}

		t.Run(testCase.Route, func(t *testing.T) {
			waitForCouchbaseSQLPPTestComponents(t, testCase.Route, "/"+testCase.Subpath)
			testREDMetricsForCouchbaseSQLPP(t, testCase)
		})
	}
}

func testREDMetricsForCouchbaseSQLPP(t *testing.T, testCase TestCase) {
	uri := testCase.Route
	urlPath := testCase.Subpath
	comm := testCase.Comm
	namespace := testCase.Namespace

	// Call 4 times the instrumented service
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, uri+"/"+urlPath, 200)
	}

	// Eventually, Prometheus would make SQL++ operations visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	for _, span := range testCase.Spans {
		operation := span.FindAttribute("db.operation.name")
		require.NotNil(t, operation, "db.operation.name attribute not found in span %s", span.Name)
		require.EventuallyWithT(t, func(t *assert.CollectT) {
			var err error
			results, err = pq.Query(`db_client_operation_duration_seconds_count{` +
				`db_operation_name="` + operation.Value.AsString() + `",` +
				`db_system_name="couchbase",` +
				`service_namespace="` + namespace + `"}`)
			require.NoError(t, err, "failed to query prometheus for %s", span.Name)
			enoughPromResults(t, results)
			val := totalPromCount(t, results)
			assert.LessOrEqual(t, 3, val, "expected at least 3 %s operations, got %d", span.Name, val)
		}, testTimeout, time.Second)
	}

	require.EventuallyWithT(t, func(t *assert.CollectT) {
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
	}, testTimeout, time.Second)
}

func waitForCouchbaseSQLPPTestComponents(t *testing.T, url string, subpath string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(t, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode)

		// now, verify that the metric has been reported.
		results, err := pq.Query(`db_client_operation_duration_seconds_count{db_system_name="couchbase"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	}, testTimeout, time.Second)
}
