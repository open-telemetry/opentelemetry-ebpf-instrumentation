// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestSanitizeElasticsearchBody(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "search",
			body: `{"query": {"match": {"user": "jane.doe@example.com"}}, "size": 5}`,
			want: `{"query":{"match":{"user":"?"}},"size":"?"}`,
		},
		{
			name: "document",
			body: `{"user": "jane.doe@example.com", "card": "4111111111111111", "age": 42, "active": true, "note": null}`,
			want: `{"user":"?","card":"?","age":"?","active":"?","note":"?"}`,
		},
		{
			name: "arrays",
			body: `{"query": {"terms": {"id": [1, "two", false]}}, "sort": [{"age": "desc"}], "empty": [], "none": {}}`,
			want: `{"query":{"terms":{"id":["?","?","?"]}},"sort":[{"age":"?"}],"empty":[],"none":{}}`,
		},
		{
			name: "pretty printed",
			body: "{\n  \"query\": {\n    \"term\": {\"card\": \"4111111111111111\"}\n  }\n}\n",
			want: `{"query":{"term":{"card":"?"}}}`,
		},
		{
			name: "msearch",
			body: "{\"index\": \"repro\"}\n{\"query\": {\"term\": {\"card\": \"4111111111111111\"}}}\n",
			want: `{"index":"?"};{"query":{"term":{"card":"?"}}}`,
		},
		{
			name: "bulk",
			body: "{\"index\": {\"_index\": \"repro\", \"_id\": \"1\"}}\n{\"user\": \"jane\"}\n{\"delete\": {\"_index\": \"repro\", \"_id\": \"2\"}}\n",
			want: `{"index":{"_index":"?","_id":"?"}};{"user":"?"};{"delete":{"_index":"?","_id":"?"}}`,
		},
		{
			name: "out of range number",
			body: `{"n": 1e400}`,
			want: `{"n":"?"}`,
		},
		{
			name: "escaped key",
			body: `{"a\"b": "secret"}`,
			want: `{"a\"b":"?"}`,
		},
		{
			name: "top-level scalar",
			body: `"secret"`,
			want: `"?"`,
		},
		{
			name: "empty",
			body: "",
			want: "",
		},
		{
			name: "not JSON",
			body: "user=jane.doe@example.com",
			want: "",
		},
		{
			name: "truncated",
			body: `{"query": {"match": {"user": "jane.doe@exa`,
			want: "",
		},
		{
			name: "truncated NDJSON",
			body: "{\"index\": \"repro\"}\n{\"query\": {\"term\": {\"card\": \"4111",
			want: "",
		},
		{
			name: "trailing garbage",
			body: `{"user": "jane"} secret`,
			want: "",
		},
		{
			name: "values on one line",
			body: `{"query": {}} {"private": 1}`,
			want: "",
		},
		{
			name: "invalid UTF-8",
			body: "{\"us\xffer\": \"jane\"}",
			want: "",
		},
		{
			name: "unbalanced close",
			body: `{"user": "jane"}]`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sanitizeElasticsearchBody(tt.body))
		})
	}
}

func TestElasticsearchQueryText(t *testing.T) {
	body := `{"query": {"match": {"user": "jane.doe@example.com"}}}`
	selected := map[attr.Name]struct{}{attr.DBQueryText: {}}

	for _, dbSystemName := range []string{"elasticsearch", "opensearch"} {
		span := request.Span{
			Type:    request.EventTypeHTTPClient,
			SubType: request.HTTPSubtypeElasticsearch,
			Method:  "POST",
			Elasticsearch: &request.Elasticsearch{
				DBOperationName: "search",
				DBQueryText:     body,
				DBSystemName:    dbSystemName,
			},
		}

		value, ok := attrValue(traceAttributesSelectorInternal(&span, selected, nil, false, defaultQueryParamReplacement), string(attr.DBQueryText))
		require.True(t, ok)
		assert.Equal(t, body, value.AsString())

		value, ok = attrValue(traceAttributesSelectorInternal(&span, selected, nil, true, defaultQueryParamReplacement), string(attr.DBQueryText))
		require.True(t, ok)
		assert.JSONEq(t, `{"query":{"match":{"user":"?"}}}`, value.AsString())
	}
}

func TestElasticsearchQueryTextOmittedWhenBodyIsNotJSON(t *testing.T) {
	span := request.Span{
		Type:    request.EventTypeHTTPClient,
		SubType: request.HTTPSubtypeElasticsearch,
		Method:  "POST",
		Elasticsearch: &request.Elasticsearch{
			DBOperationName: "search",
			DBQueryText:     `{"query": {"match": {"user": "jane.doe@exa`,
			DBSystemName:    "elasticsearch",
		},
	}
	selected := map[attr.Name]struct{}{attr.DBQueryText: {}}

	_, ok := attrValue(traceAttributesSelectorInternal(&span, selected, nil, true, defaultQueryParamReplacement), string(attr.DBQueryText))
	assert.False(t, ok)
}
