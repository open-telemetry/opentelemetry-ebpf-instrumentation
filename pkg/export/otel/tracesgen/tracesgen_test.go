// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestTraceAttributesSelector_DNSQuestionName(t *testing.T) {
	span := &request.Span{
		Type:   request.EventTypeDNS,
		Method: "A",
		Path:   "example.com",
	}

	// When optionalAttrs is empty, DNSQuestionName is not emitted
	emptyAttrs := TraceAttributesSelector(span, map[attr.Name]struct{}{})
	assert.NotEmpty(t, emptyAttrs)
	assert.NotContains(t, emptyAttrs, semconv.DNSQuestionName("example.com"))

	// With default config (no explicit user selection), DNSQuestionName defaults
	// to true for traces, so it should be present in the selected attributes.
	defaultAttrs, err := UserSelectedAttributes(&attributes.SelectorConfig{})
	require.NoError(t, err)
	assert.Contains(t, defaultAttrs, attr.DNSQuestionName)

	optInAttrs := TraceAttributesSelector(span, defaultAttrs)
	assert.Contains(t, optInAttrs, semconv.DNSQuestionName("example.com"))
}

func TestTraceAttributesSelector_GraphQLDocumentSelection(t *testing.T) {
	const document = `mutation ChangeEmail { updateUser(email: "secret@example.com") { id } }`

	span := &request.Span{
		Type:    request.EventTypeHTTP,
		SubType: request.HTTPSubtypeGraphQL,
		Method:  "POST",
		Path:    "/graphql",
		Status:  200,
		GraphQL: &request.GraphQL{
			Document:      document,
			OperationName: "ChangeEmail",
			OperationType: "mutation",
		},
	}

	defaultAttrs, err := UserSelectedAttributes(&attributes.SelectorConfig{})
	require.NoError(t, err)
	assert.NotContains(t, defaultAttrs, attr.GraphQLDocument)

	defaultSelected := AttrsToMap(TraceAttributesSelector(span, defaultAttrs))
	_, ok := defaultSelected.Get(string(semconv.GraphQLDocumentKey))
	assert.False(t, ok)

	operationName, ok := defaultSelected.Get(string(semconv.GraphQLOperationNameKey))
	require.True(t, ok)
	assert.Equal(t, "ChangeEmail", operationName.Str())

	operationType, ok := defaultSelected.Get(string(semconv.GraphQLOperationTypeKey))
	require.True(t, ok)
	assert.Equal(t, "mutation", operationType.Str())

	optInAttrs, err := UserSelectedAttributes(&attributes.SelectorConfig{
		SelectionCfg: attributes.Selection{
			attributes.Traces.Section: attributes.InclusionLists{
				Include: []string{string(attr.GraphQLDocument)},
			},
		},
	})
	require.NoError(t, err)
	assert.Contains(t, optInAttrs, attr.GraphQLDocument)

	optInSelected := AttrsToMap(TraceAttributesSelector(span, optInAttrs))
	selectedDocument, ok := optInSelected.Get(string(semconv.GraphQLDocumentKey))
	require.True(t, ok)
	assert.Equal(t, document, selectedDocument.Str())
}

func TestTraceAttributesSelector_MCPToolCallPayloadSelection(t *testing.T) {
	span := &request.Span{
		Type:    request.EventTypeHTTP,
		SubType: request.HTTPSubtypeMCP,
		GenAI: &request.GenAI{
			MCP: &request.MCPCall{
				Method:            "tools/call",
				ToolName:          "read_secret",
				ToolCallArguments: `{"path":"/etc/secrets/api_key"}`,
				ToolCallResult:    `[{"type":"text","text":"api_key=SECRET123"}]`,
			},
		},
	}

	inputOutputAttrs := AttrsToMap(TraceAttributesSelector(span, map[attr.Name]struct{}{
		attr.GenAIInput:  {},
		attr.GenAIOutput: {},
	}))
	_, ok := inputOutputAttrs.Get(string(attr.GenAIToolCallArguments))
	assert.False(t, ok)
	_, ok = inputOutputAttrs.Get(string(attr.GenAIToolCallResult))
	assert.False(t, ok)

	toolCallAttrs := AttrsToMap(TraceAttributesSelector(span, map[attr.Name]struct{}{
		attr.GenAIToolCallArguments: {},
		attr.GenAIToolCallResult:    {},
	}))
	arguments, ok := toolCallAttrs.Get(string(attr.GenAIToolCallArguments))
	require.True(t, ok)
	assert.JSONEq(t, `{"path":"/etc/secrets/api_key"}`, arguments.Str())
	result, ok := toolCallAttrs.Get(string(attr.GenAIToolCallResult))
	require.True(t, ok)
	assert.JSONEq(t, `[{"type":"text","text":"api_key=SECRET123"}]`, result.Str())
}

func TestHTTPServerSpanURLQuery(t *testing.T) {
	optInCfg := &attributes.SelectorConfig{
		SelectionCfg: attributes.Selection{
			attributes.Traces.Section: attributes.InclusionLists{
				Include: []string{string(attr.HTTPUrlQuery)},
			},
		},
	}

	t.Run("url.query present by default", func(t *testing.T) {
		// url.query is Conditionally Required per OTel semconv, so it is on by default.
		span := &request.Span{Type: request.EventTypeHTTP, Method: "GET", Path: "/", FullPath: "/?cmd=BLABLA", Status: 200}
		defaultAttrs, err := UserSelectedAttributes(&attributes.SelectorConfig{})
		require.NoError(t, err)
		selected := AttrsToMap(TraceAttributesSelector(span, defaultAttrs))
		val, ok := selected.Get("url.query")
		require.True(t, ok)
		assert.Equal(t, "cmd=BLABLA", val.Str())
	})

	t.Run("url.query absent when no query string", func(t *testing.T) {
		span := &request.Span{Type: request.EventTypeHTTP, Method: "GET", Path: "/health", FullPath: "/health", Status: 200}
		defaultAttrs, err := UserSelectedAttributes(&attributes.SelectorConfig{})
		require.NoError(t, err)
		selected := AttrsToMap(TraceAttributesSelector(span, defaultAttrs))
		_, ok := selected.Get("url.query")
		assert.False(t, ok)
	})

	t.Run("sensitive key redacted in url.query", func(t *testing.T) {
		span := &request.Span{Type: request.EventTypeHTTP, Method: "GET", Path: "/", FullPath: "/?cmd=OBIWANKENOBI&signature=abc123", Status: 200}
		optInAttrs, err := UserSelectedAttributes(optInCfg)
		require.NoError(t, err)
		selected := AttrsToMap(TraceAttributesSelector(span, optInAttrs, "signature"))
		val, ok := selected.Get("url.query")
		require.True(t, ok)
		assert.Equal(t, "cmd=OBIWANKENOBI&signature=REDACTED", val.Str())
	})

	t.Run("sensitive key also scrubbed from url.full on client span", func(t *testing.T) {
		// url.full is a client-span attribute; server spans use url.path instead.
		span := &request.Span{
			Type: request.EventTypeHTTPClient, Method: "GET", Path: "/", FullPath: "/?cmd=OBIWANKENOBI&sig=abc123",
			Host: "example.com", HostPort: 80, Status: 200,
		}
		optInAttrs, err := UserSelectedAttributes(optInCfg)
		require.NoError(t, err)
		selected := AttrsToMap(TraceAttributesSelector(span, optInAttrs, "sig"))
		val, ok := selected.Get("url.full")
		require.True(t, ok)
		assert.Contains(t, val.Str(), "cmd=OBIWANKENOBI")
		assert.Contains(t, val.Str(), "sig=REDACTED")
		assert.NotContains(t, val.Str(), "abc123")
	})

	t.Run("legacy AWS signed URL keys redacted by default list", func(t *testing.T) {
		span := &request.Span{Type: request.EventTypeHTTP, Method: "GET", Path: "/", FullPath: "/?AWSAccessKeyId=AKID&Signature=secret&SecurityToken=session&cmd=ok", Status: 200}
		optInAttrs, err := UserSelectedAttributes(optInCfg)
		require.NoError(t, err)
		selected := AttrsToMap(TraceAttributesSelector(span, optInAttrs, attributes.DefaultSensitiveQueryParams...))
		val, ok := selected.Get("url.query")
		require.True(t, ok)
		assert.Equal(t, "AWSAccessKeyId=REDACTED&Signature=REDACTED&SecurityToken=REDACTED&cmd=ok", val.Str())
	})

	t.Run("no redaction when no sensitive params passed to TraceAttributesSelector", func(t *testing.T) {
		// TraceAttributesSelector is the single-span public API; callers must pass
		// sensitive params explicitly. The default list flows through GroupSpans via
		// SensitiveQueryParams in DefaultConfig.
		span := &request.Span{Type: request.EventTypeHTTP, Method: "GET", Path: "/", FullPath: "/?sig=abc123", Status: 200}
		optInAttrs, err := UserSelectedAttributes(optInCfg)
		require.NoError(t, err)
		selected := AttrsToMap(TraceAttributesSelector(span, optInAttrs))
		val, ok := selected.Get("url.query")
		require.True(t, ok)
		assert.Equal(t, "sig=abc123", val.Str())
	})

	t.Run("url.query suppressed when explicitly excluded", func(t *testing.T) {
		// Operators can opt out of url.query via:
		//   attributes.select.traces.exclude: [url.query]
		excludeCfg := &attributes.SelectorConfig{
			SelectionCfg: attributes.Selection{
				attributes.Traces.Section: attributes.InclusionLists{
					Exclude: []string{string(attr.HTTPUrlQuery)},
				},
			},
		}
		span := &request.Span{Type: request.EventTypeHTTP, Method: "GET", Path: "/", FullPath: "/?cmd=BLABLA", Status: 200}
		excludeAttrs, err := UserSelectedAttributes(excludeCfg)
		require.NoError(t, err)
		selected := AttrsToMap(TraceAttributesSelector(span, excludeAttrs))
		_, ok := selected.Get("url.query")
		assert.False(t, ok, "url.query should be absent when explicitly excluded")
	})

	t.Run("url.full keeps scrubbed query even when url.query is excluded", func(t *testing.T) {
		excludeCfg := &attributes.SelectorConfig{
			SelectionCfg: attributes.Selection{
				attributes.Traces.Section: attributes.InclusionLists{
					Exclude: []string{string(attr.HTTPUrlQuery)},
				},
			},
		}
		span := &request.Span{
			Type: request.EventTypeHTTPClient, Method: "GET", Path: "/", FullPath: "/?cmd=BLABLA&sig=secret",
			Host: "example.com", HostPort: 80, Status: 200,
		}
		excludeAttrs, err := UserSelectedAttributes(excludeCfg)
		require.NoError(t, err)
		selected := AttrsToMap(TraceAttributesSelector(span, excludeAttrs, "sig"))
		_, ok := selected.Get("url.query")
		assert.False(t, ok, "url.query should be absent when excluded")
		urlFull, ok := selected.Get("url.full")
		require.True(t, ok, "url.full should be present")
		assert.Contains(t, urlFull.Str(), "cmd=BLABLA")
		assert.Contains(t, urlFull.Str(), "sig=REDACTED")
		assert.NotContains(t, urlFull.Str(), "secret")
	})

	t.Run("url.path omitted when path is unobservable", func(t *testing.T) {
		// FastCGI spans with no REQUEST_URI (truncated buffer or older nginx config)
		// produce Path="". OTel semconv says omit the attribute rather than emit "".
		span := &request.Span{Type: request.EventTypeHTTP, Method: "GET", Path: "", FullPath: "", Status: 200}
		defaultAttrs, err := UserSelectedAttributes(&attributes.SelectorConfig{})
		require.NoError(t, err)
		selected := AttrsToMap(TraceAttributesSelector(span, defaultAttrs))
		_, ok := selected.Get("url.path")
		assert.False(t, ok, "url.path must be omitted when path is unobservable")
	})

	t.Run("url.query absent when FullPath is empty", func(t *testing.T) {
		// Same truncation scenario: FullPath="" means there is no query string to emit.
		span := &request.Span{Type: request.EventTypeHTTP, Method: "GET", Path: "", FullPath: "", Status: 200}
		defaultAttrs, err := UserSelectedAttributes(&attributes.SelectorConfig{})
		require.NoError(t, err)
		selected := AttrsToMap(TraceAttributesSelector(span, defaultAttrs))
		_, ok := selected.Get("url.query")
		assert.False(t, ok, "url.query must be absent when FullPath is empty")
	})
}

func TestGenAIToolCallAttributes(t *testing.T) {
	t.Run("nil tool calls", func(t *testing.T) {
		assert.Nil(t, genAIToolCallAttributes(nil))
	})

	t.Run("empty tool calls", func(t *testing.T) {
		assert.Nil(t, genAIToolCallAttributes([]request.ToolCall{}))
	})

	t.Run("single tool call with ID", func(t *testing.T) {
		attrs := genAIToolCallAttributes([]request.ToolCall{
			{ID: "call_1", Name: "get_weather"},
		})
		require.Len(t, attrs, 2)
		assert.Equal(t, attribute.StringSlice(string(attr.GenAIToolName), []string{"get_weather"}), attrs[0])
		assert.Equal(t, attribute.StringSlice(string(attr.GenAIToolCallID), []string{"call_1"}), attrs[1])
	})

	t.Run("multiple tool calls with IDs", func(t *testing.T) {
		attrs := genAIToolCallAttributes([]request.ToolCall{
			{ID: "call_1", Name: "get_weather"},
			{ID: "call_2", Name: "get_time"},
		})
		require.Len(t, attrs, 2)
		assert.Equal(t, attribute.StringSlice(string(attr.GenAIToolName), []string{"get_weather", "get_time"}), attrs[0])
		assert.Equal(t, attribute.StringSlice(string(attr.GenAIToolCallID), []string{"call_1", "call_2"}), attrs[1])
	})

	t.Run("tool calls without IDs", func(t *testing.T) {
		attrs := genAIToolCallAttributes([]request.ToolCall{
			{Name: "get_weather"},
			{Name: "get_time"},
		})
		require.Len(t, attrs, 1)
		assert.Equal(t, attribute.StringSlice(string(attr.GenAIToolName), []string{"get_weather", "get_time"}), attrs[0])
	})

	t.Run("skips empty names", func(t *testing.T) {
		attrs := genAIToolCallAttributes([]request.ToolCall{
			{ID: "call_1", Name: ""},
			{ID: "call_2", Name: "get_time"},
		})
		require.Len(t, attrs, 2)
		assert.Equal(t, attribute.StringSlice(string(attr.GenAIToolName), []string{"get_time"}), attrs[0])
		assert.Equal(t, attribute.StringSlice(string(attr.GenAIToolCallID), []string{"call_2"}), attrs[1])
	})
}
