// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
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

func TestCreateToolCallSpans(t *testing.T) {
	t.Run("nil tool calls creates no spans", func(t *testing.T) {
		ss := ptrace.NewScopeSpans()
		traceID := pcommon.TraceID([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
		parentSpanID := pcommon.SpanID([8]byte{1, 2, 3, 4, 5, 6, 7, 8})
		now := time.Now()
		createToolCallSpans(nil, parentSpanID, traceID, &ss, now, now)
		assert.Equal(t, 0, ss.Spans().Len())
	})

	t.Run("empty tool calls creates no spans", func(t *testing.T) {
		ss := ptrace.NewScopeSpans()
		traceID := pcommon.TraceID([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
		parentSpanID := pcommon.SpanID([8]byte{1, 2, 3, 4, 5, 6, 7, 8})
		now := time.Now()
		createToolCallSpans([]request.ToolCall{}, parentSpanID, traceID, &ss, now, now)
		assert.Equal(t, 0, ss.Spans().Len())
	})

	t.Run("single tool call with ID", func(t *testing.T) {
		ss := ptrace.NewScopeSpans()
		traceID := pcommon.TraceID([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
		parentSpanID := pcommon.SpanID([8]byte{1, 2, 3, 4, 5, 6, 7, 8})
		start := time.Now()
		end := start.Add(100 * time.Millisecond)
		createToolCallSpans([]request.ToolCall{
			{ID: "call_1", Name: "get_weather"},
		}, parentSpanID, traceID, &ss, start, end)

		require.Equal(t, 1, ss.Spans().Len())
		sp := ss.Spans().At(0)
		assert.Equal(t, "execute_tool get_weather", sp.Name())
		assert.Equal(t, ptrace.SpanKindInternal, sp.Kind())
		assert.Equal(t, traceID, sp.TraceID())
		assert.Equal(t, parentSpanID, sp.ParentSpanID())
		assert.Equal(t, pcommon.NewTimestampFromTime(start), sp.StartTimestamp())
		assert.Equal(t, pcommon.NewTimestampFromTime(end), sp.EndTimestamp())

		attrs := sp.Attributes()
		opName, ok := attrs.Get("gen_ai.operation.name")
		require.True(t, ok)
		assert.Equal(t, "execute_tool", opName.Str())

		toolName, ok := attrs.Get("gen_ai.tool.name")
		require.True(t, ok)
		assert.Equal(t, "get_weather", toolName.Str())

		toolCallID, ok := attrs.Get("gen_ai.tool.call.id")
		require.True(t, ok)
		assert.Equal(t, "call_1", toolCallID.Str())
	})

	t.Run("multiple tool calls", func(t *testing.T) {
		ss := ptrace.NewScopeSpans()
		traceID := pcommon.TraceID([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
		parentSpanID := pcommon.SpanID([8]byte{1, 2, 3, 4, 5, 6, 7, 8})
		start := time.Now()
		end := start.Add(100 * time.Millisecond)
		createToolCallSpans([]request.ToolCall{
			{ID: "call_1", Name: "get_weather"},
			{ID: "call_2", Name: "get_time"},
		}, parentSpanID, traceID, &ss, start, end)

		require.Equal(t, 2, ss.Spans().Len())
		assert.Equal(t, "execute_tool get_weather", ss.Spans().At(0).Name())
		assert.Equal(t, "execute_tool get_time", ss.Spans().At(1).Name())
	})

	t.Run("skips empty names", func(t *testing.T) {
		ss := ptrace.NewScopeSpans()
		traceID := pcommon.TraceID([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
		parentSpanID := pcommon.SpanID([8]byte{1, 2, 3, 4, 5, 6, 7, 8})
		now := time.Now()
		createToolCallSpans([]request.ToolCall{
			{ID: "call_1", Name: ""},
			{ID: "call_2", Name: "get_time"},
		}, parentSpanID, traceID, &ss, now, now)

		require.Equal(t, 1, ss.Spans().Len())
		assert.Equal(t, "execute_tool get_time", ss.Spans().At(0).Name())
	})

	t.Run("tool call without ID omits gen_ai.tool.call.id", func(t *testing.T) {
		ss := ptrace.NewScopeSpans()
		traceID := pcommon.TraceID([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
		parentSpanID := pcommon.SpanID([8]byte{1, 2, 3, 4, 5, 6, 7, 8})
		now := time.Now()
		createToolCallSpans([]request.ToolCall{
			{Name: "get_weather"},
		}, parentSpanID, traceID, &ss, now, now)

		require.Equal(t, 1, ss.Spans().Len())
		sp := ss.Spans().At(0)
		_, ok := sp.Attributes().Get("gen_ai.tool.call.id")
		assert.False(t, ok, "gen_ai.tool.call.id should not be present when ID is empty")
	})
}

func TestTraceAttributesSelector_OpenAICompatible(t *testing.T) {
	defaultAttrs, err := UserSelectedAttributes(&attributes.SelectorConfig{})
	require.NoError(t, err)

	t.Run("chat completions with configured provider", func(t *testing.T) {
		span := &request.Span{
			Type:    request.EventTypeHTTPClient,
			SubType: request.HTTPSubtypeOpenAICompatible,
			GenAI: &request.GenAI{
				OpenAICompatible: &request.VendorOpenAI{
					ID:            "chatcmpl-gw-001",
					OperationName: request.ChatOperationName,
					ResponseModel: "gpt-4o-mini-2024-07-18",
					ProviderName:  "litellm",
					Request: request.OpenAIInput{
						Model: "gpt-4o-mini",
					},
					Usage: request.OpenAIUsage{
						PromptTokens:     10,
						CompletionTokens: 8,
						TotalTokens:      18,
					},
					Choices: []byte(`[{"index":0,"message":{"role":"assistant","content":"Hello!"},"finish_reason":"stop"}]`),
				},
			},
		}

		selected := AttrsToMap(TraceAttributesSelector(span, defaultAttrs))

		provider, ok := selected.Get("gen_ai.provider.name")
		require.True(t, ok)
		assert.Equal(t, "litellm", provider.Str())

		opName, ok := selected.Get("gen_ai.operation.name")
		require.True(t, ok)
		assert.Equal(t, request.ChatOperationName, opName.Str())

		respModel, ok := selected.Get("gen_ai.response.model")
		require.True(t, ok)
		assert.Equal(t, "gpt-4o-mini-2024-07-18", respModel.Str())

		inputTokens, ok := selected.Get("gen_ai.usage.input_tokens")
		require.True(t, ok)
		assert.Equal(t, int64(10), inputTokens.Int())

		outputTokens, ok := selected.Get("gen_ai.usage.output_tokens")
		require.True(t, ok)
		assert.Equal(t, int64(8), outputTokens.Int())

		// openai.* attributes must NOT be present for OpenAI-compatible spans
		_, ok = selected.Get("openai.request.service_tier")
		assert.False(t, ok, "openai.request.service_tier should not be present")
		_, ok = selected.Get("openai.response.service_tier")
		assert.False(t, ok, "openai.response.service_tier should not be present")
		_, ok = selected.Get("openai.response.system_fingerprint")
		assert.False(t, ok, "openai.response.system_fingerprint should not be present")
		_, ok = selected.Get("openai.api.type")
		assert.False(t, ok, "openai.api.type should not be present")
	})

	t.Run("empty provider falls back to custom", func(t *testing.T) {
		span := &request.Span{
			Type:    request.EventTypeHTTPClient,
			SubType: request.HTTPSubtypeOpenAICompatible,
			GenAI: &request.GenAI{
				OpenAICompatible: &request.VendorOpenAI{
					OperationName: request.ChatOperationName,
					Request: request.OpenAIInput{
						Model: "gpt-4o-mini",
					},
				},
			},
		}

		selected := AttrsToMap(TraceAttributesSelector(span, defaultAttrs))

		provider, ok := selected.Get("gen_ai.provider.name")
		require.True(t, ok)
		assert.Equal(t, "custom", provider.Str())
	})

	t.Run("embeddings with dimensions", func(t *testing.T) {
		// NOTE: OperationName is set manually here because this test verifies
		// the tracesgen attribute emission logic (gen_ai.embeddings.dimension.count,
		// gen_ai.operation.name, etc.), not the HTTP response parsing path.
		// In production, OpenAICompatibleSpan derives OperationName from the URL
		// path (/v1/embeddings -> request.EmbeddingOperationName).
		span := &request.Span{
			Type:    request.EventTypeHTTPClient,
			SubType: request.HTTPSubtypeOpenAICompatible,
			GenAI: &request.GenAI{
				OpenAICompatible: &request.VendorOpenAI{
					OperationName: request.EmbeddingOperationName,
					ResponseModel: "text-embedding-3-small",
					ProviderName:  "litellm",
					Request: request.OpenAIInput{
						Model:      "text-embedding-3-small",
						Dimensions: 256,
					},
					Usage: request.OpenAIUsage{
						PromptTokens: 5,
						TotalTokens:  5,
					},
					Data: []byte(`[{"object":"embedding","embedding":[0.1,0.2],"index":0}]`),
				},
			},
		}

		selected := AttrsToMap(TraceAttributesSelector(span, defaultAttrs))

		dims, ok := selected.Get("gen_ai.embeddings.dimension.count")
		require.True(t, ok)
		assert.Equal(t, int64(256), dims.Int())

		opName, ok := selected.Get("gen_ai.operation.name")
		require.True(t, ok)
		assert.Equal(t, request.EmbeddingOperationName, opName.Str())
	})

	t.Run("text completions operation name", func(t *testing.T) {
		span := &request.Span{
			Type:    request.EventTypeHTTPClient,
			SubType: request.HTTPSubtypeOpenAICompatible,
			GenAI: &request.GenAI{
				OpenAICompatible: &request.VendorOpenAI{
					OperationName: request.CompletionOperationName,
					ProviderName:  "litellm",
					Request: request.OpenAIInput{
						Model: "gpt-3.5-turbo-instruct",
					},
				},
			},
		}

		selected := AttrsToMap(TraceAttributesSelector(span, defaultAttrs))

		opName, ok := selected.Get("gen_ai.operation.name")
		require.True(t, ok)
		assert.Equal(t, request.CompletionOperationName, opName.Str())
	})
}
