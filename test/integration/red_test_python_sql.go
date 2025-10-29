// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"strings"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"
	"go.opentelemetry.io/obi/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/test/integration/components/prom"
)

func assertHTTPRequests(t *testing.T, comm, urlPath string) {
	t.Helper()

	pq := prom.Client{HostPort: prometheusHostPort}

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`db_client_operation_duration_seconds_count{` +
			`db_operation_name="SELECT",` +
			`service_namespace="integration-test"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 1, val)
	})

	results, err := pq.Query(`http_server_request_duration_seconds_count{}`)
	require.NoError(t, err, "failed to query prometheus for http_server_request_duration_seconds_count")
	require.Empty(t, results, "expected no HTTP requests, got %d", len(results))

	params := neturl.Values{}
	params.Add("service", comm)
	params.Add("operation", "GET "+urlPath)
	fullURL := fmt.Sprintf("%s?%s", jaegerQueryURL, params.Encode())

	resp, err := http.Get(fullURL)
	require.NoError(t, err, "failed to query jaeger for HTTP traces")
	if resp == nil {
		return
	}
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tq jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
	traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: urlPath})
	require.Empty(t, traces, "expected no HTTP traces, got %d", len(traces))
}

func assertSQLOperation(t *testing.T, comm, op, table, db string) {
	t.Helper()

	dbOperation := fmt.Sprintf("%s %s", op, table)

	params := neturl.Values{}
	params.Add("service", comm)
	params.Add("operation", dbOperation)
	fullURL := fmt.Sprintf("%s?%s", jaegerQueryURL, params.Encode())

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(fullURL)
		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "db.operation.name", Type: "string", Value: op})
		assert.GreaterOrEqual(t, len(traces), 1)
		lastTrace := traces[len(traces)-1]
		span := lastTrace.Spans[0]

		assert.Equal(t, dbOperation, span.OperationName)

		tag, found := jaeger.FindIn(span.Tags, "db.query.text")
		assert.True(t, found)
		assert.True(t, strings.HasPrefix(tag.Value.(string), "SELECT * FROM "+table))

		tag, found = jaeger.FindIn(span.Tags, "db.system.name")
		assert.True(t, found)
		assert.Equal(t, db, tag.Value)

		_, found = jaeger.FindIn(span.Tags, "db.response.status_code")
		assert.False(t, found)

		tag, found = jaeger.FindIn(span.Tags, "db.collection.name")
		assert.True(t, found)
		assert.Equal(t, table, tag.Value)
	}, test.Interval(100*time.Millisecond))
}

func assertSQLOperationErrored(t *testing.T, comm, op, table, db string) {
	t.Helper()

	dbOperation := fmt.Sprintf("%s %s", op, table)

	expectedData := map[string]map[string]string{
		"mysql": {
			"db.response.status_code": "1049",
			"error.type":              "#42000",
			"otel.status_description": "SQL Server errored for command 'COM_QUERY': error_code=1049 sql_state=#42000 message=Unknown database 'obi'",
		},
		"postgresql": {
			"db.response.status_code": "0",
			"error.type":              "42P01",
			"otel.status_description": "SQL Server errored for command 'COM_QUERY': error_code=NA sql_state=42P01 message=relation \"obi.nonexisting\" does not exist",
		},
	}

	params := neturl.Values{}
	params.Add("service", comm)
	params.Add("operation", dbOperation)
	fullURL := fmt.Sprintf("%s?%s", jaegerQueryURL, params.Encode())

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(fullURL)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "db.collection.name", Type: "string", Value: table})
		require.GreaterOrEqual(t, len(traces), 1)

		lastTrace := traces[len(traces)-1]
		span := lastTrace.Spans[0]

		assert.Equal(t, dbOperation, span.OperationName)

		tag, found := jaeger.FindIn(span.Tags, "db.query.text")
		assert.True(t, found)
		assert.Equal(t, "SELECT * FROM obi.nonexisting", tag.Value)

		tag, found = jaeger.FindIn(span.Tags, "db.system.name")
		assert.True(t, found)
		assert.Equal(t, db, tag.Value)

		tag, found = jaeger.FindIn(span.Tags, "db.collection.name")
		assert.True(t, found)
		assert.Equal(t, table, tag.Value)

		tag, found = jaeger.FindIn(span.Tags, "db.response.status_code")
		assert.True(t, found)
		assert.Equal(t, expectedData[db]["db.response.status_code"], tag.Value)

		tag, found = jaeger.FindIn(span.Tags, "error.type")
		assert.True(t, found)
		assert.Equal(t, expectedData[db]["error.type"], tag.Value)

		tag, found = jaeger.FindIn(span.Tags, "otel.status_description")
		assert.True(t, found)
		assert.Equal(t, expectedData[db]["otel.status_description"], tag.Value)
	}, test.Interval(100*time.Millisecond))
}

func testPythonSQLQuery(t *testing.T, comm, url, table, db string) {
	t.Helper()

	urlPath := "/query"
	ti.DoHTTPGet(t, url+urlPath, 200)

	assertSQLOperation(t, comm, "SELECT", table, db)
}

func testPythonSQLPreparedStatements(t *testing.T, comm, url, table, db string) {
	t.Helper()

	urlPath := "/prepquery"
	ti.DoHTTPGet(t, url+urlPath, 200)

	assertSQLOperation(t, comm, "SELECT", table, db)
}

func testPythonSQLError(t *testing.T, comm, url, db string) {
	t.Helper()

	urlPath := "/error"
	ti.DoHTTPGet(t, url+urlPath, 200)

	assertSQLOperationErrored(t, comm, "SELECT", "obi.nonexisting", db)
}

func testPythonPostgres(t *testing.T) {
	testCaseURL := "http://localhost:8381"
	comm := "python3.12"
	table := "accounting.contacts"
	db := "postgresql"

	waitForSQLTestComponentsWithDB(t, testCaseURL, "/query", db)

	assertHTTPRequests(t, comm, "/query")
	testPythonSQLQuery(t, comm, testCaseURL, table, db)
	testPythonSQLPreparedStatements(t, comm, testCaseURL, table, db)
	testPythonSQLError(t, comm, testCaseURL, db)
}

func testPythonMySQL(t *testing.T) {
	testCaseURL := "http://localhost:8381"
	comm := "python3.12"
	table := "actor"
	db := "mysql"

	waitForSQLTestComponentsWithDB(t, testCaseURL, "/query", db)

	assertHTTPRequests(t, comm, "/query")
	testPythonSQLQuery(t, comm, testCaseURL, table, db)
	testPythonSQLPreparedStatements(t, comm, testCaseURL, table, db)
	testPythonSQLError(t, comm, testCaseURL, db)
}

func testREDMetricsForPythonSQLSSL(t *testing.T, url, comm, namespace string) {
	urlPath := "/query"

	// Call 3 times the instrumented service, forcing it to:
	// - take a large JSON file
	// - returning a 200 code
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, url+urlPath, 200)
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`db_client_operation_duration_seconds_count{` +
			`db_operation_name="SELECT",` +
			`service_namespace="` + namespace + `"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
	})

	// Look for a trace with SELECT accounting.contacts
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=SELECT%20accounting.contacts")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "db.operation.name", Type: "string", Value: "SELECT"})
		assert.LessOrEqual(t, 1, len(traces))
	}, test.Interval(100*time.Millisecond))

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=GET%20%2Fquery")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/query"})
		require.LessOrEqual(t, 1, len(traces))
		trace := traces[0]
		// Check the information of the parent span
		res := trace.FindByOperationName("GET /query", "")
		require.Len(t, res, 1)
	}, test.Interval(100*time.Millisecond))
}

func testREDMetricsPythonSQLSSL(t *testing.T) {
	for _, testCaseURL := range []string{
		"https://localhost:8381",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponentsSub(t, testCaseURL, "/query")
			testREDMetricsForPythonSQLSSL(t, testCaseURL, "python3.12", "integration-test")
		})
	}
}
