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
		for _, statement := range statements {
			testCase.Spans = append(testCase.Spans, TestCaseSpan{
				Name: statement.operation + " test-scope.test-collection",
				Attributes: []attribute.KeyValue{
					attribute.String("db.operation.name", statement.operation),
					attribute.String("db.namespace", "test-bucket"),
					attribute.String("db.collection.name", "test-scope.test-collection"),
					attribute.String("db.query.text", statement.text),
				},
			})
		}
		runCouchbaseSQLPPTestCase(t, testCase)
		assertCouchbasePreparedExecutionsResolved(t, comm, statements)
	}
}

func assertCouchbasePreparedExecutionsResolved(t *testing.T, comm string, statements []couchbasePreparedStatement) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := getJaeger(jaegerQueryURL + "?service=" + comm + "&limit=2000&lookback=10m")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))

		resolved := map[string]int{}
		unresolved := 0
		for _, tr := range tq.Data {
			for _, sp := range tr.Spans {
				if op, ok := jaeger.FindIn(sp.Tags, "db.operation.name"); ok && op.Value == "EXECUTE" {
					unresolved++
				}
				if text, ok := jaeger.FindIn(sp.Tags, "db.query.text"); ok {
					if s, isStr := text.Value.(string); isStr {
						resolved[s]++
					}
				}
			}
		}
		assert.Zero(ct, unresolved, "prepared executions emitted without their statement")
		for _, statement := range statements {
			assert.LessOrEqual(ct, 3, resolved[statement.text], "too few spans carry %q", statement.text)
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
