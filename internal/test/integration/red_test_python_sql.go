// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

func assertHTTPRequests(t *testing.T, comm, urlPath string) {
	t.Helper()

	pq := promtest.Client{HostPort: prometheusHostPort}

	require.Eventually(t, func() bool {
		results, err := pq.Query(`db_client_operation_duration_seconds_count{` +
			`db_operation_name="SELECT",` +
			`service_namespace="integration-test"}`)
		if err != nil {
			return false
		}
		if !enoughPromResultsCheck(results) {
			return false
		}
		val := totalPromCount(t, results)
		return val >= 1
	}, testTimeout, 500*time.Millisecond, "failed to find db_client_operation_duration_seconds_count metric")

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

	require.Eventually(t, func() bool {
		resp, err := http.Get(fullURL)
		if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
			return false
		}

		var tq jaeger.TracesQuery
		if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
			return false
		}
		traces := tq.FindBySpan(jaeger.Tag{Key: "db.operation.name", Type: "string", Value: op})
		if len(traces) < 1 {
			return false
		}
		lastTrace := traces[len(traces)-1]
		span := lastTrace.Spans[0]

		if dbOperation != span.OperationName {
			return false
		}

		tag, found := jaeger.FindIn(span.Tags, "db.query.text")
		if !found || !strings.HasPrefix(tag.Value.(string), "SELECT * FROM "+table) {
			return false
		}

		tag, found = jaeger.FindIn(span.Tags, "db.system.name")
		if !found || db != tag.Value {
			return false
		}

		_, found = jaeger.FindIn(span.Tags, "db.response.status_code")
		if found {
			return false
		}

		tag, found = jaeger.FindIn(span.Tags, "db.collection.name")
		return found && table == tag.Value
	}, testTimeout, 500*time.Millisecond, "failed to verify SQL operation")
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

	require.Eventually(t, func() bool {
		resp, err := http.Get(fullURL)
		if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
			return false
		}

		var tq jaeger.TracesQuery
		if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
			return false
		}
		traces := tq.FindBySpan(jaeger.Tag{Key: "db.collection.name", Type: "string", Value: table})
		if len(traces) < 1 {
			return false
		}

		lastTrace := traces[len(traces)-1]
		span := lastTrace.Spans[0]

		if dbOperation != span.OperationName {
			return false
		}

		tag, found := jaeger.FindIn(span.Tags, "db.query.text")
		if !found || "SELECT * FROM obi.nonexisting" != tag.Value {
			return false
		}

		tag, found = jaeger.FindIn(span.Tags, "db.system.name")
		if !found || db != tag.Value {
			return false
		}

		tag, found = jaeger.FindIn(span.Tags, "db.collection.name")
		if !found || table != tag.Value {
			return false
		}

		tag, found = jaeger.FindIn(span.Tags, "db.response.status_code")
		if !found || expectedData[db]["db.response.status_code"] != tag.Value {
			return false
		}

		tag, found = jaeger.FindIn(span.Tags, "error.type")
		if !found || expectedData[db]["error.type"] != tag.Value {
			return false
		}

		tag, found = jaeger.FindIn(span.Tags, "otel.status_description")
		return found && expectedData[db]["otel.status_description"] == tag.Value
	}, testTimeout, 500*time.Millisecond, "failed to verify SQL operation error")
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
	comm := "python3.14"
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
	comm := "python3.14"
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
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	require.Eventually(t, func() bool {
		var err error
		results, err = pq.Query(`db_client_operation_duration_seconds_count{` +
			`db_operation_name="SELECT",` +
			`service_namespace="` + namespace + `"}`)
		if err != nil {
			return false
		}
		if !enoughPromResultsCheck(results) {
			return false
		}
		val := totalPromCount(t, results)
		return val >= 3
	}, testTimeout, 500*time.Millisecond, "failed to find db_client_operation_duration_seconds_count metric for namespace")

	// Look for a trace with SELECT accounting.contacts
	require.Eventually(t, func() bool {
		resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=SELECT%20accounting.contacts")
		if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
			return false
		}
		var tq jaeger.TracesQuery
		if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
			return false
		}
		traces := tq.FindBySpan(jaeger.Tag{Key: "db.operation.name", Type: "string", Value: "SELECT"})
		return len(traces) >= 1
	}, testTimeout, 500*time.Millisecond, "failed to find SELECT accounting.contacts trace")

	require.Eventually(t, func() bool {
		resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=GET%20%2Fquery")
		if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
			return false
		}
		var tq jaeger.TracesQuery
		if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
			return false
		}
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/query"})
		if len(traces) < 1 {
			return false
		}
		trace := traces[0]
		results := trace.FindByOperationName("GET /query", "")
		return len(results) == 1
	}, testTimeout, 500*time.Millisecond, "failed to find GET /query trace")
}

func testREDMetricsPythonSQLSSL(t *testing.T) {
	for _, testCaseURL := range []string{
		"https://localhost:8381",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponentsSub(t, testCaseURL, "/query")
			testREDMetricsForPythonSQLSSL(t, testCaseURL, "python3.14", "integration-test")
		})
	}
}
