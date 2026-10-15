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

const (
	couchbasePreparedSelect = "SELECT META().id FROM `test-bucket`.`test-scope`.`test-collection` WHERE type = $1"
	couchbasePreparedDelete = "DELETE FROM `test-bucket`.`test-scope`.`test-collection` WHERE META().id = $1"
)

type couchbasePreparedStatement struct {
	operation string
	text      string
}

func sqlppCommonAttributes() []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("db.system.name", "couchbase"),
		attribute.String("span.kind", "client"),
	}
}

func runCouchbaseSQLPPTestCase(t *testing.T, testCase TestCase) {
	for i := range testCase.Spans {
		testCase.Spans[i].Attributes = append(testCase.Spans[i].Attributes, sqlppCommonAttributes()...)
	}
	waitForCouchbaseSQLPPTestComponents(t, testCase.Route, "/"+testCase.Subpath)
	testREDMetricsForCouchbaseSQLPP(t, testCase)
}

func testREDMetricsCouchbaseSQLPPPrepared(comm string, statements ...couchbasePreparedStatement) func(t *testing.T) {
	return func(t *testing.T) {
		testCase := TestCase{
			Route:     "http://localhost:8381",
			Subpath:   "sqlpp-prepared",
			Comm:      comm,
			Namespace: "integration-test",
		}
		waitForCouchbasePreparedStatements(t, testCase, statements)
		assertCouchbasePreparedExecutionsResolved(t, testCase, statements)
		assertCouchbasePreparedOperationMetrics(t, testCase, statements)
	}
}

func waitForCouchbasePreparedStatements(t *testing.T, testCase TestCase, statements []couchbasePreparedStatement) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, testCase.Route+"/"+testCase.Subpath, 200)
		counts := countCouchbasePreparedSpans(ct, testCase.Comm)
		for _, statement := range statements {
			assert.Positive(ct, counts.resolved[statement.text], "no span carries %q yet", statement.text)
		}
	}, testTimeout, time.Second)
}

func assertCouchbasePreparedOperationMetrics(t *testing.T, testCase TestCase, statements []couchbasePreparedStatement) {
	t.Helper()
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, statement := range statements {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			results, err := pq.Query(`db_client_operation_duration_seconds_count{` +
				`db_operation_name="` + statement.operation + `",` +
				`db_system_name="couchbase",` +
				`db_collection_name="test-scope.test-collection",` +
				`service_namespace="` + testCase.Namespace + `"}`)
			require.NoError(ct, err)
			enoughPromResults(ct, results)
			assert.LessOrEqual(ct, 3, totalPromCount(ct, results))
		}, testTimeout, time.Second)
	}
}

type couchbasePreparedSpanCounts struct {
	unresolved int
	resolved   map[string]int
}

func countCouchbasePreparedSpans(t require.TestingT, comm string) couchbasePreparedSpanCounts {
	resp, err := getJaeger(jaegerQueryURL + "?service=" + comm + "&limit=2000&lookback=10m")
	require.NoError(t, err)
	require.NotNil(t, resp)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var tq jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))

	counts := couchbasePreparedSpanCounts{resolved: map[string]int{}}
	for _, tr := range tq.Data {
		for _, sp := range tr.Spans {
			if op, ok := jaeger.FindIn(sp.Tags, "db.operation.name"); ok && op.Value == "EXECUTE" {
				counts.unresolved++
			}
			if text, ok := jaeger.FindIn(sp.Tags, "db.query.text"); ok {
				if s, isStr := text.Value.(string); isStr {
					counts.resolved[s]++
				}
			}
		}
	}
	return counts
}

func assertCouchbasePreparedExecutionsResolved(t *testing.T, testCase TestCase, statements []couchbasePreparedStatement) {
	t.Helper()
	const (
		executions      = 4
		stabilityWindow = 3 * time.Second
	)

	var baseline couchbasePreparedSpanCounts
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		before := countCouchbasePreparedSpans(ct, testCase.Comm)
		time.Sleep(stabilityWindow)
		baseline = countCouchbasePreparedSpans(ct, testCase.Comm)
		assert.Equal(ct, before, baseline, "spans still arriving")
	}, testTimeout, time.Second)

	for range executions {
		ti.DoHTTPGet(t, testCase.Route+"/"+testCase.Subpath, 200)
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		counts := countCouchbasePreparedSpans(ct, testCase.Comm)
		assert.Equal(ct, baseline.unresolved, counts.unresolved, "prepared executions emitted without their statement")
		for _, statement := range statements {
			assert.GreaterOrEqual(ct, counts.resolved[statement.text], baseline.resolved[statement.text]+executions,
				"executions of %q carrying the statement", statement.text)
		}
	}, testTimeout, time.Second)
}

func testREDMetricsGoCouchbaseSQLPPAdhoc(t *testing.T) {
	runCouchbaseSQLPPTestCase(t, TestCase{
		Route:     "http://localhost:8381",
		Subpath:   "sqlpp-adhoc",
		Comm:      "testserver",
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
				Name: "DELETE test-scope.test-collection",
				Attributes: []attribute.KeyValue{
					attribute.String("db.operation.name", "DELETE"),
					attribute.String("db.namespace", "test-bucket"),
					attribute.String("db.collection.name", "test-scope.test-collection"),
				},
			},
		},
	})
}
