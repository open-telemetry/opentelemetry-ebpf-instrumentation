// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

var sanitizeElasticsearchBodyTests = []struct {
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
	{
		name: "numbers",
		body: `[0, -0, 12, -1.5, 2e10, 3E-2, 4.25e+1]`,
		want: `["?","?","?","?","?","?","?"]`,
	},
	{
		name: "escapes",
		body: `{"k\u00e9y": "a\"\\\/\b\f\n\r\t\u00E9"}`,
		want: `{"k\u00e9y":"?"}`,
	},
	{
		name: "unicode",
		body: `{"usér": "jané"}`,
		want: `{"usér":"?"}`,
	},
	{
		name: "html characters in key",
		body: `{"<a>&": "secret"}`,
		want: `{"<a>&":"?"}`,
	},
	{
		name: "whitespace only",
		body: " \n\t",
		want: "",
	},
	{
		name: "trailing comma",
		body: `{"user": "jane",}`,
		want: "",
	},
	{
		name: "trailing comma in array",
		body: `["jane",]`,
		want: "",
	},
	{
		name: "missing colon",
		body: `{"user" "jane"}`,
		want: "",
	},
	{
		name: "non-string key",
		body: `{user: "jane"}`,
		want: "",
	},
	{
		name: "bad escape",
		body: `{"user": "ja\x"}`,
		want: "",
	},
	{
		name: "bad unicode escape",
		body: `{"user": "\u12g4"}`,
		want: "",
	},
	{
		name: "control character in string",
		body: "{\"user\": \"ja\tne\"}",
		want: "",
	},
	{
		name: "leading zero",
		body: `{"n": 01}`,
		want: "",
	},
	{
		name: "bad numbers",
		body: `[1.]`,
		want: "",
	},
	{
		name: "bad exponent",
		body: `[1e+]`,
		want: "",
	},
	{
		name: "bad literal",
		body: `{"active": tru}`,
		want: "",
	},
	{
		name: "nesting at limit",
		body: strings.Repeat("[", elasticsearchMaxDepth) + strings.Repeat("]", elasticsearchMaxDepth),
		want: strings.Repeat("[", elasticsearchMaxDepth) + strings.Repeat("]", elasticsearchMaxDepth),
	},
	{
		name: "nesting over limit",
		body: strings.Repeat("[", elasticsearchMaxDepth+1) + strings.Repeat("]", elasticsearchMaxDepth+1),
		want: "",
	},
}

func TestSanitizeElasticsearchBody(t *testing.T) {
	for _, tt := range sanitizeElasticsearchBodyTests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sanitizeElasticsearchBody(tt.body))
		})
	}
}

// FuzzSanitizeElasticsearchBody checks the sanitizer against encoding/json.
func FuzzSanitizeElasticsearchBody(f *testing.F) {
	for _, tt := range sanitizeElasticsearchBodyTests {
		f.Add(tt.body)
	}

	f.Fuzz(func(t *testing.T, body string) {
		got := sanitizeElasticsearchBody(body)

		if utf8.ValidString(body) && json.Valid([]byte(body)) {
			require.NotEmpty(t, got)
			var sanitized any
			require.NoError(t, json.Unmarshal([]byte(got), &sanitized), "sanitized %q to invalid JSON %q", body, got)
			requireOnlySanitizedValues(t, sanitized)
		}
		if got != "" {
			require.True(t, decodesAsJSONValues(body), "accepted invalid JSON %q", body)
		}
	})
}

func requireOnlySanitizedValues(t *testing.T, value any) {
	switch value := value.(type) {
	case map[string]any:
		for _, v := range value {
			requireOnlySanitizedValues(t, v)
		}
	case []any:
		for _, v := range value {
			requireOnlySanitizedValues(t, v)
		}
	default:
		require.Equal(t, "?", value)
	}
}

func decodesAsJSONValues(body string) bool {
	dec := json.NewDecoder(strings.NewReader(body))
	for dec.More() {
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return false
		}
	}
	_, err := dec.Token()
	return errors.Is(err, io.EOF)
}

func BenchmarkSanitizeElasticsearchBody(b *testing.B) {
	benchmarks := []struct {
		name string
		body string
	}{
		{"search", `{"query": {"bool": {"must": [{"match": {"user": "jane.doe@example.com"}}, {"range": {"age": {"gte": 18}}}]}}, "size": 5}`},
		{"pretty", "{\n  \"query\": {\n    \"term\": {\"card\": \"4111111111111111\"}\n  }\n}\n"},
		{"bulk", "{\"index\": {\"_index\": \"repro\", \"_id\": \"1\"}}\n{\"user\": \"jane\", \"card\": \"4111111111111111\", \"age\": 42}\n"},
		{"numbers", "[" + strings.Repeat("1,", 1023) + "1]"},
		{"long value", `{"doc": "` + strings.Repeat("x", 64*1024) + `"}`},
		{"truncated", `{"query": {"match": {"user": "jane.doe@exa`},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				sanitizeElasticsearchBody(bm.body)
			}
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
