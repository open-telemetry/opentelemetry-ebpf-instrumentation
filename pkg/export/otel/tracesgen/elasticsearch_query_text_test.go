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
		name: "duplicate keys",
		body: `{"user": "jane", "user": "john"}`,
		want: `{"user":"?","user":"?"}`,
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

func FuzzSanitizeElasticsearchBody(f *testing.F) {
	for _, tt := range sanitizeElasticsearchBodyTests {
		f.Add(tt.body)
	}

	f.Fuzz(func(t *testing.T, body string) {
		got := sanitizeElasticsearchBody(body)

		values, ok := ndjsonValues(body)
		if !ok {
			require.Empty(t, got, "accepted invalid body %q", body)
			return
		}

		sanitizedValues := make([]string, 0, len(values))
		for _, value := range values {
			sanitized := sanitizeElasticsearchBody(value)
			requireSanitized(t, value, sanitized)
			sanitizedValues = append(sanitizedValues, sanitized)
		}
		require.Equal(t, strings.Join(sanitizedValues, elasticsearchBodySeparator), got)
	})
}

// requireSanitized walks value and its sanitized form token by token, so that
// a repeated key cannot hide a value.
func requireSanitized(t *testing.T, value, sanitized string) {
	input := json.NewDecoder(strings.NewReader(value))
	input.UseNumber()
	output := json.NewDecoder(strings.NewReader(sanitized))
	requireSanitizedTokens(t, input, output)

	_, err := output.Token()
	require.ErrorIs(t, err, io.EOF, "sanitized %q to %q", value, sanitized)
}

func requireSanitizedTokens(t *testing.T, input, output *json.Decoder) {
	inToken, err := input.Token()
	require.NoError(t, err)
	outToken, err := output.Token()
	require.NoError(t, err)

	if inToken != json.Delim('{') && inToken != json.Delim('[') {
		require.Equal(t, "?", outToken)
		return
	}

	require.Equal(t, inToken, outToken)
	for input.More() {
		if inToken == json.Delim('{') {
			requireSameToken(t, input, output)
		}
		requireSanitizedTokens(t, input, output)
	}
	requireSameToken(t, input, output)
}

func requireSameToken(t *testing.T, input, output *json.Decoder) {
	inToken, err := input.Token()
	require.NoError(t, err)
	outToken, err := output.Token()
	require.NoError(t, err)
	require.Equal(t, inToken, outToken)
}

func ndjsonValues(body string) ([]string, bool) {
	if !utf8.ValidString(body) {
		return nil, false
	}

	dec := json.NewDecoder(strings.NewReader(body))
	var values []string
	var valueEnd int64
	for dec.More() {
		// More skips whitespace, so InputOffset is the start of the next value.
		if len(values) > 0 && !strings.Contains(body[valueEnd:dec.InputOffset()], "\n") {
			return nil, false
		}

		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, false
		}
		values = append(values, string(value))
		valueEnd = dec.InputOffset()
	}

	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, false
	}
	return values, len(values) > 0
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
