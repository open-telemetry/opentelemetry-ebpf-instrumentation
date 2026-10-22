// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/sdk/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
)

func queryTextSpans() []request.Span {
	return []request.Span{
		{Type: request.EventTypeSQLClient, SubType: int(request.DBPostgres), Method: "SELECT", Statement: `SELECT "a" FROM t WHERE id = -1`},
		{Type: request.EventTypeSQLServer, SubType: int(request.DBMySQL), Method: "INSERT", Statement: "INSERT INTO t (id, name) VALUES (1, 'first')"},
		{Type: request.EventTypeSQLClient, SubType: int(request.DBMSSQL), Method: "SELECT", Statement: "SELECT [a] FROM t WHERE id = @p1"},
		{Type: request.EventTypeHTTPClient, SubType: request.HTTPSubtypeSQLPP, Method: "SELECT", Statement: `SELECT * FROM b WHERE type = "airline"`},
		{Type: request.EventTypeRedisClient, Method: "SET", Path: "SET key 1"},
	}
}

func groupedQueryTexts(t *testing.T, sanitize bool) []string {
	groups := GroupSpansWithOptions(
		t.Context(),
		queryTextSpans(),
		map[attr.Name]struct{}{attr.DBQueryText: {}},
		trace.AlwaysSample(),
		instrumentations.NewInstrumentationSelection(
			[]instrumentations.Instrumentation{instrumentations.InstrumentationALL},
		),
		GroupSpansOptions{SanitizeSQLQueryText: sanitize},
	)

	var got []string
	for _, group := range groups {
		for _, span := range group {
			value, ok := attrValue(span.Attributes, string(attr.DBQueryText))
			require.True(t, ok)
			got = append(got, value.AsString())
		}
	}
	return got
}

func TestDBQueryTextRawByDefault(t *testing.T) {
	spans := queryTextSpans()
	want := make([]string, 0, len(spans))
	for _, span := range spans {
		want = append(want, span.Statement+span.Path)
	}
	selected := map[attr.Name]struct{}{attr.DBQueryText: {}}

	for i, span := range spans {
		value, ok := attrValue(TraceAttributesSelector(&span, selected), string(attr.DBQueryText))
		require.True(t, ok)
		assert.Equal(t, want[i], value.AsString())
	}
	assert.ElementsMatch(t, want, groupedQueryTexts(t, false))
}

func TestDBQueryTextSanitized(t *testing.T) {
	want := []string{
		`SELECT "a" FROM t WHERE id = ?`,
		"INSERT INTO t (id, name) VALUES (?, ?)",
		"SELECT [a] FROM t WHERE id = @p1",
		"SELECT * FROM b WHERE type = ?",
		"SET key 1",
	}

	assert.ElementsMatch(t, want, groupedQueryTexts(t, true))
}
