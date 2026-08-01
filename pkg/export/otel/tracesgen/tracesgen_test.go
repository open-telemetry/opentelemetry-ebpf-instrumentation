// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	trace2 "go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
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

func TestHTTPRequestMethodOmittedWhenEmpty(t *testing.T) {
	defaultAttrs, err := UserSelectedAttributes(&attributes.SelectorConfig{})
	require.NoError(t, err)

	for _, tt := range []struct {
		name      string
		spanType  request.EventType
		method    string
		wantValue string
		wantOK    bool
	}{
		{name: "server span with known method", spanType: request.EventTypeHTTP, method: "GET", wantValue: "GET", wantOK: true},
		{name: "server span with empty method", spanType: request.EventTypeHTTP, method: "", wantOK: false},
		{name: "client span with known method", spanType: request.EventTypeHTTPClient, method: "GET", wantValue: "GET", wantOK: true},
		{name: "client span with empty method", spanType: request.EventTypeHTTPClient, method: "", wantOK: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			span := &request.Span{Type: tt.spanType, Method: tt.method, Path: "/", Host: "example.com", HostPort: 80, Status: 200}
			selected := AttrsToMap(TraceAttributesSelector(span, defaultAttrs))
			val, ok := selected.Get("http.request.method")
			assert.Equal(t, tt.wantOK, ok, "http.request.method presence should match method availability")
			if tt.wantOK {
				assert.Equal(t, tt.wantValue, val.Str())
			}
		})
	}
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
						PromptTokens:     request.NewTokenCount(10),
						CompletionTokens: request.NewTokenCount(8),
						TotalTokens:      request.NewTokenCount(18),
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
						PromptTokens: request.NewTokenCount(5),
						TotalTokens:  request.NewTokenCount(5),
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

func TestGenAIResponseErrorStatusMessage(t *testing.T) {
	const rawMessage = "  api_key=sk-secret\nprompt=\"private input\" account=acct_123 🧪  "

	tests := []struct {
		name      string
		subType   int
		genAI     *request.GenAI
		errorType string
	}{
		{
			name:    "OpenAI",
			subType: request.HTTPSubtypeOpenAI,
			genAI: &request.GenAI{OpenAI: &request.VendorOpenAI{
				Error: request.OpenAIError{Type: "rate_limit_error", Message: rawMessage},
			}},
			errorType: "rate_limit_error",
		},
		{
			name:    "OpenAI compatible",
			subType: request.HTTPSubtypeOpenAICompatible,
			genAI: &request.GenAI{OpenAICompatible: &request.VendorOpenAI{
				Error: request.OpenAIError{Type: "gateway_error", Message: rawMessage},
			}},
			errorType: "gateway_error",
		},
		{
			name:    "Anthropic",
			subType: request.HTTPSubtypeAnthropic,
			genAI: &request.GenAI{Anthropic: &request.VendorAnthropic{
				Output: request.AnthropicResponse{
					Error: &request.AnthropicError{Type: "authentication_error", Message: rawMessage},
				},
			}},
			errorType: "authentication_error",
		},
		{
			name:    "Gemini",
			subType: request.HTTPSubtypeGemini,
			genAI: &request.GenAI{Gemini: &request.VendorGemini{
				Output: request.GeminiResponse{
					Error: &request.GeminiError{Status: "PERMISSION_DENIED", Message: rawMessage},
				},
			}},
			errorType: "PERMISSION_DENIED",
		},
		{
			name:    "Qwen",
			subType: request.HTTPSubtypeQwen,
			genAI: &request.GenAI{Qwen: &request.VendorOpenAI{
				Error: request.OpenAIError{Type: "invalid_request_error", Message: rawMessage},
			}},
			errorType: "invalid_request_error",
		},
		{
			name:    "AWS Bedrock",
			subType: request.HTTPSubtypeAWSBedrock,
			genAI: &request.GenAI{Bedrock: &request.VendorBedrock{
				Output: request.BedrockResponse{
					ErrorType:    "ValidationException",
					ErrorMessage: rawMessage,
				},
			}},
			errorType: "ValidationException",
		},
		{
			name:    "Rerank",
			subType: request.HTTPSubtypeRerank,
			genAI: &request.GenAI{Rerank: &request.VendorRerank{
				Output: request.RerankResponse{
					Error: &request.RerankError{Type: "invalid_request", Message: rawMessage},
				},
			}},
			errorType: "invalid_request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span := &request.Span{
				Type:    request.EventTypeHTTPClient,
				SubType: tt.subType,
				Method:  "POST",
				Status:  429,
				GenAI:   tt.genAI,
			}

			defaultSpan := generateSingleTraceSpan(t, span, nil)
			assert.Equal(t, ptrace.StatusCodeError, defaultSpan.Status().Code())
			assert.Empty(t, defaultSpan.Status().Message())
			assertSpanStringAttribute(t, defaultSpan, semconv.ErrorTypeKey, tt.errorType)
			assertSpanAttributeAbsent(t, defaultSpan, string(attr.GenAIResponseError))
			assertSpanAttributeAbsent(t, defaultSpan, "error.message")

			selectedSpan := generateSingleTraceSpan(t, span, map[attr.Name]struct{}{
				attr.GenAIResponseError: {},
			})
			assert.Equal(t, ptrace.StatusCodeError, selectedSpan.Status().Code())
			assert.Equal(t, rawMessage, selectedSpan.Status().Message())
			assertSpanStringAttribute(t, selectedSpan, semconv.ErrorTypeKey, tt.errorType)
			assertSpanAttributeAbsent(t, selectedSpan, string(attr.GenAIResponseError))
			assertSpanAttributeAbsent(t, selectedSpan, "error.message")
		})
	}
}

func TestGenAIResponseErrorSelectionToStatusMessage(t *testing.T) {
	const rawMessage = "provider request failed"

	tests := []struct {
		name     string
		include  []string
		expected string
	}{
		{
			name: "default",
		},
		{
			name:    "all attributes wildcard",
			include: []string{"*"},
		},
		{
			name:    "GenAI wildcard",
			include: []string{"gen_ai.*"},
		},
		{
			name:     "exact name",
			include:  []string{"gen_ai.response.error"},
			expected: rawMessage,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &attributes.SelectorConfig{}
			if tt.include != nil {
				cfg.SelectionCfg = attributes.Selection{
					attributes.Traces.Section: attributes.InclusionLists{
						Include: tt.include,
					},
				}
			}
			selectedAttrs, err := UserSelectedAttributes(cfg)
			require.NoError(t, err)

			span := request.Span{
				Type:    request.EventTypeHTTPClient,
				SubType: request.HTTPSubtypeOpenAI,
				Method:  "POST",
				Status:  429,
				GenAI: &request.GenAI{OpenAI: &request.VendorOpenAI{
					Error: request.OpenAIError{
						Type:    "rate_limit_error",
						Message: rawMessage,
					},
				}},
			}
			sampler := &recordingSampler{}
			groups := GroupSpans(
				t.Context(),
				[]request.Span{span},
				selectedAttrs,
				sampler,
				instrumentations.NewInstrumentationSelection(
					[]instrumentations.Instrumentation{instrumentations.InstrumentationALL},
				),
			)
			group := groups[span.Service.UID]
			require.Len(t, group, 1)
			assertAttributeKeyAbsent(t, sampler.attributes, string(attr.GenAIResponseError))
			assertAttributeKeyAbsent(t, sampler.attributes, string(genAIResponseErrorControlKey))
			assertAttributeKeyAbsent(t, group[0].Attributes, string(attr.GenAIResponseError))

			exported := generateTraceSpan(t, group[0])
			assert.Equal(t, ptrace.StatusCodeError, exported.Status().Code())
			assert.Equal(t, tt.expected, exported.Status().Message())
			assertSpanAttributeAbsent(t, exported, string(attr.GenAIResponseError))
			assertSpanAttributeAbsent(t, exported, string(genAIResponseErrorControlKey))
		})
	}
}

func TestGenAIResponseErrorStatusMessageEdgeCases(t *testing.T) {
	t.Run("empty provider message", func(t *testing.T) {
		span := &request.Span{
			Type:    request.EventTypeHTTPClient,
			SubType: request.HTTPSubtypeOpenAI,
			Method:  "POST",
			Status:  429,
			GenAI: &request.GenAI{OpenAI: &request.VendorOpenAI{
				Error: request.OpenAIError{Type: "rate_limit_error"},
			}},
		}

		exported := generateSingleTraceSpan(t, span, map[attr.Name]struct{}{
			attr.GenAIResponseError: {},
		})
		assert.Equal(t, ptrace.StatusCodeError, exported.Status().Code())
		assert.Empty(t, exported.Status().Message())
		assertSpanAttributeAbsent(t, exported, string(attr.GenAIResponseError))
	})

	t.Run("non-error status", func(t *testing.T) {
		span := &request.Span{
			Type:    request.EventTypeHTTPClient,
			SubType: request.HTTPSubtypeOpenAI,
			Method:  "POST",
			Status:  200,
			GenAI: &request.GenAI{OpenAI: &request.VendorOpenAI{
				Error: request.OpenAIError{Message: "message without an error"},
			}},
		}

		exported := generateSingleTraceSpan(t, span, map[attr.Name]struct{}{
			attr.GenAIResponseError: {},
		})
		assert.Equal(t, ptrace.StatusCodeUnset, exported.Status().Code())
		assert.Empty(t, exported.Status().Message())
		assertSpanAttributeAbsent(t, exported, string(attr.GenAIResponseError))
	})
}

func TestGenAIResponseErrorPreservesProtocolStatusMessages(t *testing.T) {
	tests := []struct {
		name    string
		span    *request.Span
		message string
	}{
		{
			name: "JSON-RPC",
			span: &request.Span{
				Type:    request.EventTypeHTTPClient,
				SubType: request.HTTPSubtypeJSONRPC,
				Method:  "POST",
				Status:  200,
				JSONRPC: &request.JSONRPC{
					ErrorCode:    -32600,
					ErrorMessage: "Invalid Request",
				},
			},
			message: "Invalid Request",
		},
		{
			name: "MCP",
			span: &request.Span{
				Type:    request.EventTypeHTTPClient,
				SubType: request.HTTPSubtypeMCP,
				Method:  "POST",
				Status:  200,
				GenAI: &request.GenAI{MCP: &request.MCPCall{
					ErrorCode:    -32602,
					ErrorMessage: "Unknown tool",
				}},
			},
			message: "Unknown tool",
		},
		{
			name: "JSON-RPC without native message",
			span: &request.Span{
				Type:    request.EventTypeHTTPClient,
				SubType: request.HTTPSubtypeJSONRPC,
				Method:  "POST",
				Status:  200,
				JSONRPC: &request.JSONRPC{
					ErrorCode: -32600,
				},
			},
		},
		{
			name: "MCP without native message",
			span: &request.Span{
				Type:    request.EventTypeHTTPClient,
				SubType: request.HTTPSubtypeMCP,
				Method:  "POST",
				Status:  200,
				GenAI: &request.GenAI{MCP: &request.MCPCall{
					ErrorCode: -32602,
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exported := generateSingleTraceSpan(t, tt.span, map[attr.Name]struct{}{
				attr.GenAIResponseError: {},
			})
			assert.Equal(t, ptrace.StatusCodeError, exported.Status().Code())
			assert.Equal(t, tt.message, exported.Status().Message())
			assertSpanAttributeAbsent(t, exported, string(attr.GenAIResponseError))
		})
	}
}

func TestGenAIResponseErrorAttributeCollision(t *testing.T) {
	const ordinaryValue = "ordinary application attribute"

	tests := []struct {
		name string
		span *request.Span
	}{
		{
			name: "manual span",
			span: &request.Span{
				Type:   request.EventTypeManualSpan,
				Method: "manual",
				Status: int(codes.Error),
			},
		},
		{
			name: "MCP without native message",
			span: &request.Span{
				Type:    request.EventTypeHTTPClient,
				SubType: request.HTTPSubtypeMCP,
				Method:  "POST",
				Status:  200,
				GenAI: &request.GenAI{MCP: &request.MCPCall{
					ErrorCode: -32602,
				}},
			},
		},
		{
			name: "supported provider without selection metadata",
			span: &request.Span{
				Type:    request.EventTypeHTTPClient,
				SubType: request.HTTPSubtypeOpenAI,
				Method:  "POST",
				Status:  429,
				GenAI: &request.GenAI{OpenAI: &request.VendorOpenAI{
					Error: request.OpenAIError{Message: ordinaryValue},
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exported := generateTraceSpan(t, TraceSpanAndAttributes{
				Span: tt.span,
				Attributes: []attribute.KeyValue{
					attribute.String(string(attr.GenAIResponseError), ordinaryValue),
				},
			})
			assert.Equal(t, ptrace.StatusCodeError, exported.Status().Code())
			assert.Empty(t, exported.Status().Message())
			assertSpanStringAttribute(
				t,
				exported,
				attribute.Key(attr.GenAIResponseError),
				ordinaryValue,
			)
		})
	}
}

type recordingSampler struct {
	attributes []attribute.KeyValue
}

func (s *recordingSampler) ShouldSample(parameters sdktrace.SamplingParameters) sdktrace.SamplingResult {
	s.attributes = append([]attribute.KeyValue(nil), parameters.Attributes...)
	return sdktrace.SamplingResult{Decision: sdktrace.RecordAndSample}
}

func (*recordingSampler) Description() string {
	return "recording sampler"
}

func generateSingleTraceSpan(
	t *testing.T,
	span *request.Span,
	optionalAttrs map[attr.Name]struct{},
) ptrace.Span {
	t.Helper()

	return generateTraceSpan(t, TraceSpanAndAttributes{
		Span:       span,
		Attributes: TraceAttributesSelector(span, optionalAttrs),
	})
}

func generateTraceSpan(t *testing.T, spanWithAttributes TraceSpanAndAttributes) ptrace.Span {
	t.Helper()

	span := spanWithAttributes.Span
	cache := expirable2.NewLRU[svc.UID, []attribute.KeyValue](10, nil, 0)
	traces := GenerateTracesWithAttributes(
		cache,
		&span.Service,
		nil,
		&meta.NodeMeta{},
		[]TraceSpanAndAttributes{spanWithAttributes},
		"obi",
	)

	require.Equal(t, 1, traces.ResourceSpans().Len())
	require.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
	spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
	require.Equal(t, 1, spans.Len())
	return spans.At(0)
}

func assertAttributeKeyAbsent(t *testing.T, attrs []attribute.KeyValue, key string) {
	t.Helper()

	for i := range attrs {
		assert.NotEqual(t, key, string(attrs[i].Key))
	}
}

func assertSpanStringAttribute(
	t *testing.T,
	span ptrace.Span,
	key attribute.Key,
	expected string,
) {
	t.Helper()

	value, ok := span.Attributes().Get(string(key))
	require.True(t, ok)
	assert.Equal(t, expected, value.Str())
}

func assertSpanAttributeAbsent(t *testing.T, span ptrace.Span, key string) {
	t.Helper()

	_, ok := span.Attributes().Get(key)
	assert.False(t, ok)
}

func TestGenerateTracesWithAttributesManualOTelJSON(t *testing.T) {
	payload := manualOTelPayload(t)
	service := &svc.Attrs{
		UID:         svc.UID{Name: "checkout"},
		SDKLanguage: svc.InstrumentableGolang,
	}
	cache := expirable2.NewLRU[svc.UID, []attribute.KeyValue](10, nil, 0)

	traces := GenerateTracesWithAttributes(
		cache,
		service,
		nil,
		&meta.NodeMeta{},
		[]TraceSpanAndAttributes{{
			Span: &request.Span{
				Type:           request.EventTypeManualSpan,
				SpanKind:       trace2.SpanKindServer,
				Method:         "manual-json",
				ManualOTelJSON: payload,
			},
		}},
		"obi",
	)

	require.Equal(t, 1, traces.ResourceSpans().Len())
	rs := traces.ResourceSpans().At(0)
	serviceName, ok := rs.Resource().Attributes().Get(string(semconv.ServiceNameKey))
	require.True(t, ok)
	assert.Equal(t, "checkout", serviceName.Str())
	_, ok = rs.Resource().Attributes().Get("payload.resource")
	assert.False(t, ok)

	require.Equal(t, 1, rs.ScopeSpans().Len())
	ss := rs.ScopeSpans().At(0)
	assert.Equal(t, "manual-scope", ss.Scope().Name())
	assert.Equal(t, "v1.0.0", ss.Scope().Version())
	assert.Equal(t, "https://opentelemetry.io/schemas/1.30.0", ss.SchemaUrl())
	scopeAttr, ok := ss.Scope().Attributes().Get("scope.foo")
	require.True(t, ok)
	assert.Equal(t, "scope-bar", scopeAttr.Str())
	assert.Equal(t, uint32(6), ss.Scope().DroppedAttributesCount())

	require.Equal(t, 1, ss.Spans().Len())
	span := ss.Spans().At(0)
	assert.Equal(t, "manual-json", span.Name())
	assert.Equal(t, ptrace.SpanKindServer, span.Kind())
	assert.Equal(t, "00000000000000000000000000000001", span.TraceID().String())
	assert.Equal(t, "0000000000000002", span.SpanID().String())
	assert.Equal(t, "0000000000000003", span.ParentSpanID().String())
	assert.Equal(t, "tenant=a", span.TraceState().AsRaw())
	assert.Equal(t, uint32(1), span.Flags())
	assert.Equal(t, pcommon.Timestamp(946684800000000000), span.StartTimestamp())
	assert.Equal(t, pcommon.Timestamp(946684801000000000), span.EndTimestamp())
	assert.Equal(t, ptrace.StatusCodeError, span.Status().Code())
	assert.Equal(t, "boom", span.Status().Message())
	assert.Equal(t, uint32(7), span.DroppedAttributesCount())
	assert.Equal(t, uint32(8), span.DroppedEventsCount())
	assert.Equal(t, uint32(9), span.DroppedLinksCount())

	foo, ok := span.Attributes().Get("foo")
	require.True(t, ok)
	assert.Equal(t, "bar", foo.Str())

	require.Equal(t, 1, span.Events().Len())
	event := span.Events().At(0)
	assert.Equal(t, "event-a", event.Name())
	assert.Equal(t, pcommon.Timestamp(946684800100000000), event.Timestamp())
	eventFoo, ok := event.Attributes().Get("event.foo")
	require.True(t, ok)
	assert.Equal(t, "event-bar", eventFoo.Str())
	assert.Equal(t, uint32(10), event.DroppedAttributesCount())

	require.Equal(t, 1, span.Links().Len())
	link := span.Links().At(0)
	assert.Equal(t, "00000000000000000000000000000004", link.TraceID().String())
	assert.Equal(t, "0000000000000005", link.SpanID().String())
	assert.Equal(t, "link=b", link.TraceState().AsRaw())
	assert.Equal(t, uint32(1), link.Flags())
	linkFoo, ok := link.Attributes().Get("link.foo")
	require.True(t, ok)
	assert.Equal(t, "link-bar", linkFoo.Str())
	assert.Equal(t, uint32(11), link.DroppedAttributesCount())
}

func TestGenerateTracesWithAttributesDropsInvalidManualOTelJSON(t *testing.T) {
	service := &svc.Attrs{UID: svc.UID{Name: "checkout"}}
	cache := expirable2.NewLRU[svc.UID, []attribute.KeyValue](10, nil, 0)

	traces := GenerateTracesWithAttributes(
		cache,
		service,
		nil,
		&meta.NodeMeta{},
		[]TraceSpanAndAttributes{{
			Span: &request.Span{
				Type:           request.EventTypeManualSpan,
				Method:         "fallback",
				RequestStart:   1,
				Start:          1,
				End:            2,
				TraceID:        trace2.TraceID{1},
				SpanID:         trace2.SpanID{2},
				ManualOTelJSON: []byte("{"),
			},
		}},
		"obi",
	)

	require.Equal(t, 1, traces.ResourceSpans().Len())
	ss := traces.ResourceSpans().At(0).ScopeSpans()
	assert.Equal(t, 0, ss.Len())
}

func TestAppendManualOTelJSONRejectsInvalidShape(t *testing.T) {
	tests := []struct {
		name    string
		payload func() []byte
	}{
		{name: "empty", payload: func() []byte { return nil }},
		{name: "invalid JSON", payload: func() []byte { return []byte("{") }},
		{
			name: "no resource spans",
			payload: func() []byte {
				return marshalTracesJSON(t, ptrace.NewTraces())
			},
		},
		{
			name: "multiple resource spans",
			payload: func() []byte {
				traces := ptrace.NewTraces()
				traces.ResourceSpans().AppendEmpty()
				traces.ResourceSpans().AppendEmpty()
				return marshalTracesJSON(t, traces)
			},
		},
		{
			name: "no scope spans",
			payload: func() []byte {
				traces := ptrace.NewTraces()
				traces.ResourceSpans().AppendEmpty()
				return marshalTracesJSON(t, traces)
			},
		},
		{
			name: "multiple scope spans",
			payload: func() []byte {
				traces := ptrace.NewTraces()
				scopes := traces.ResourceSpans().AppendEmpty().ScopeSpans()
				scopes.AppendEmpty().Spans().AppendEmpty()
				scopes.AppendEmpty().Spans().AppendEmpty()
				return marshalTracesJSON(t, traces)
			},
		},
		{
			name: "no spans",
			payload: func() []byte {
				traces := ptrace.NewTraces()
				traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty()
				return marshalTracesJSON(t, traces)
			},
		},
		{
			name: "multiple spans",
			payload: func() []byte {
				traces := ptrace.NewTraces()
				spans := traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans()
				spans.AppendEmpty()
				spans.AppendEmpty()
				return marshalTracesJSON(t, traces)
			},
		},
		{
			name: "invalid span metadata",
			payload: func() []byte {
				traces := ptrace.NewTraces()
				traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
				return marshalTracesJSON(t, traces)
			},
		},
		{
			name: "invalid timestamps",
			payload: func() []byte {
				traces := ptrace.NewTraces()
				span := traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
				span.SetTraceID(pcommon.TraceID{1})
				span.SetSpanID(pcommon.SpanID{1})
				span.SetStartTimestamp(1)
				span.SetEndTimestamp(pcommon.Timestamp(math.MaxUint64))
				return marshalTracesJSON(t, traces)
			},
		},
		{
			name: "invalid status",
			payload: func() []byte {
				traces := ptrace.NewTraces()
				span := traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
				span.SetTraceID(pcommon.TraceID{1})
				span.SetSpanID(pcommon.SpanID{1})
				span.SetStartTimestamp(1)
				span.SetEndTimestamp(2)
				span.Status().SetCode(99)
				return marshalTracesJSON(t, traces)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := ptrace.NewResourceSpans()
			require.Error(t, appendManualOTelJSON(rs, tt.payload()))
			assert.Equal(t, 0, rs.ScopeSpans().Len())
		})
	}
}

func TestAppendManualOTelJSONNormalizesSpanKind(t *testing.T) {
	tests := []struct {
		name string
		kind ptrace.SpanKind
		want ptrace.SpanKind
	}{
		{name: "unspecified", kind: ptrace.SpanKindUnspecified, want: ptrace.SpanKindInternal},
		{name: "unknown", kind: ptrace.SpanKind(99), want: ptrace.SpanKindInternal},
		{name: "client", kind: ptrace.SpanKindClient, want: ptrace.SpanKindClient},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			traces := ptrace.NewTraces()
			span := traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
			span.SetTraceID(pcommon.TraceID{1})
			span.SetSpanID(pcommon.SpanID{1})
			span.SetStartTimestamp(1)
			span.SetEndTimestamp(2)
			span.SetKind(tt.kind)

			rs := ptrace.NewResourceSpans()
			require.NoError(t, appendManualOTelJSON(rs, marshalTracesJSON(t, traces)))
			require.Equal(t, 1, rs.ScopeSpans().Len())
			assert.Equal(t, tt.want, rs.ScopeSpans().At(0).Spans().At(0).Kind())
		})
	}
}

func TestManualSpanKind(t *testing.T) {
	assert.Equal(t, trace2.SpanKindServer, spanKind(&request.Span{
		Type:     request.EventTypeManualSpan,
		SpanKind: trace2.SpanKindServer,
	}))
	assert.Equal(t, trace2.SpanKindInternal, spanKind(&request.Span{
		Type: request.EventTypeManualSpan,
	}))
}

func manualOTelPayload(t *testing.T) []byte {
	t.Helper()

	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr(string(semconv.ServiceNameKey), "payload-service")
	rs.Resource().Attributes().PutStr("payload.resource", "discarded")

	ss := rs.ScopeSpans().AppendEmpty()
	ss.Scope().SetName("manual-scope")
	ss.Scope().SetVersion("v1.0.0")
	ss.Scope().Attributes().PutStr("scope.foo", "scope-bar")
	ss.Scope().SetDroppedAttributesCount(6)
	ss.SetSchemaUrl("https://opentelemetry.io/schemas/1.30.0")

	span := ss.Spans().AppendEmpty()
	span.SetTraceID(pcommon.TraceID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	span.SetSpanID(pcommon.SpanID{0, 0, 0, 0, 0, 0, 0, 2})
	span.SetParentSpanID(pcommon.SpanID{0, 0, 0, 0, 0, 0, 0, 3})
	span.TraceState().FromRaw("tenant=a")
	span.SetFlags(1)
	span.SetName("manual-json")
	span.SetKind(ptrace.SpanKindServer)
	span.SetStartTimestamp(946684800000000000)
	span.SetEndTimestamp(946684801000000000)
	span.Attributes().PutStr("foo", "bar")
	span.SetDroppedAttributesCount(7)
	span.SetDroppedEventsCount(8)
	span.SetDroppedLinksCount(9)
	span.Status().SetCode(ptrace.StatusCodeError)
	span.Status().SetMessage("boom")

	event := span.Events().AppendEmpty()
	event.SetTimestamp(946684800100000000)
	event.SetName("event-a")
	event.Attributes().PutStr("event.foo", "event-bar")
	event.SetDroppedAttributesCount(10)

	link := span.Links().AppendEmpty()
	link.SetTraceID(pcommon.TraceID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4})
	link.SetSpanID(pcommon.SpanID{0, 0, 0, 0, 0, 0, 0, 5})
	link.TraceState().FromRaw("link=b")
	link.SetFlags(1)
	link.Attributes().PutStr("link.foo", "link-bar")
	link.SetDroppedAttributesCount(11)

	return marshalTracesJSON(t, traces)
}

func marshalTracesJSON(t *testing.T, traces ptrace.Traces) []byte {
	t.Helper()

	var marshaler ptrace.JSONMarshaler
	payload, err := marshaler.MarshalTraces(traces)
	require.NoError(t, err)
	return payload
}

func TestTraceAttributesSelector_GenAIUsageAvailability(t *testing.T) {
	defaultAttrs, err := UserSelectedAttributes(&attributes.SelectorConfig{})
	require.NoError(t, err)

	var usage request.OpenAIUsage
	require.NoError(t, json.Unmarshal([]byte(`{"prompt_tokens":0,"completion_tokens":0}`), &usage))
	span := &request.Span{
		Type:    request.EventTypeHTTPClient,
		SubType: request.HTTPSubtypeOpenAI,
		GenAI:   &request.GenAI{OpenAI: &request.VendorOpenAI{Usage: usage}},
	}

	selected := AttrsToMap(TraceAttributesSelector(span, defaultAttrs))
	input, ok := selected.Get("gen_ai.usage.input_tokens")
	require.True(t, ok)
	assert.Zero(t, input.Int())
	output, ok := selected.Get("gen_ai.usage.output_tokens")
	require.True(t, ok)
	assert.Zero(t, output.Int())

	require.NoError(t, json.Unmarshal([]byte(`{}`), &usage))
	span.GenAI.OpenAI.Usage = usage
	selected = AttrsToMap(TraceAttributesSelector(span, defaultAttrs))
	_, ok = selected.Get("gen_ai.usage.input_tokens")
	assert.False(t, ok)
	_, ok = selected.Get("gen_ai.usage.output_tokens")
	assert.False(t, ok)
}

func TestTraceAttributesSelector_GenAITokenDetailAvailability(t *testing.T) {
	defaultAttrs, err := UserSelectedAttributes(&attributes.SelectorConfig{})
	require.NoError(t, err)

	const (
		reasoningKey     = "gen_ai.usage.reasoning.output_tokens"
		cacheReadKey     = "gen_ai.usage.cache_read.input_tokens"
		cacheCreationKey = "gen_ai.usage.cache_creation.input_tokens"
	)

	for _, tt := range []struct {
		name    string
		subType int
		genAI   func(request.TokenCount) *request.GenAI
		keys    []string
	}{
		{
			name:    "OpenAI",
			subType: request.HTTPSubtypeOpenAI,
			genAI: func(count request.TokenCount) *request.GenAI {
				return &request.GenAI{OpenAI: &request.VendorOpenAI{Usage: request.OpenAIUsage{
					OutputDetails: &request.OpenAIOutputTokensDetails{ReasoningTokens: count},
					InputDetails: &request.OpenAIInputTokensDetails{
						CachedTokens:        count,
						CacheCreationTokens: count,
					},
				}}}
			},
			keys: []string{reasoningKey, cacheReadKey, cacheCreationKey},
		},
		{
			name:    "Anthropic",
			subType: request.HTTPSubtypeAnthropic,
			genAI: func(count request.TokenCount) *request.GenAI {
				return &request.GenAI{Anthropic: &request.VendorAnthropic{Output: request.AnthropicResponse{
					Usage: request.AnthropicUsage{
						CacheCreationInputTokens: count,
						CacheReadInputTokens:     count,
						ReasoningOutputTokens:    count,
					},
				}}}
			},
			keys: []string{reasoningKey, cacheReadKey, cacheCreationKey},
		},
		{
			name:    "Qwen",
			subType: request.HTTPSubtypeQwen,
			genAI: func(count request.TokenCount) *request.GenAI {
				return &request.GenAI{Qwen: &request.VendorOpenAI{Usage: request.OpenAIUsage{
					OutputDetails: &request.OpenAIOutputTokensDetails{ReasoningTokens: count},
					InputDetails: &request.OpenAIInputTokensDetails{
						CachedTokens:        count,
						CacheCreationTokens: count,
					},
				}}}
			},
			keys: []string{reasoningKey, cacheReadKey, cacheCreationKey},
		},
		{
			name:    "OpenAI compatible",
			subType: request.HTTPSubtypeOpenAICompatible,
			genAI: func(count request.TokenCount) *request.GenAI {
				return &request.GenAI{OpenAICompatible: &request.VendorOpenAI{Usage: request.OpenAIUsage{
					OutputDetails: &request.OpenAIOutputTokensDetails{ReasoningTokens: count},
					InputDetails: &request.OpenAIInputTokensDetails{
						CachedTokens:        count,
						CacheCreationTokens: count,
					},
				}}}
			},
			keys: []string{reasoningKey, cacheReadKey, cacheCreationKey},
		},
		{
			name:    "Gemini",
			subType: request.HTTPSubtypeGemini,
			genAI: func(count request.TokenCount) *request.GenAI {
				return &request.GenAI{Gemini: &request.VendorGemini{Output: request.GeminiResponse{
					UsageMetadata: request.GeminiUsage{
						CachedContentTokenCount: count,
						ThoughtsTokenCount:      count,
					},
				}}}
			},
			keys: []string{reasoningKey, cacheReadKey},
		},
		{
			name:    "Bedrock",
			subType: request.HTTPSubtypeAWSBedrock,
			genAI: func(count request.TokenCount) *request.GenAI {
				return &request.GenAI{Bedrock: &request.VendorBedrock{Output: request.BedrockResponse{
					Usage: request.BedrockUsage{
						CacheReadInputTokens:  count,
						CacheWriteInputTokens: count,
					},
				}}}
			},
			keys: []string{cacheReadKey, cacheCreationKey},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			span := &request.Span{
				Type:    request.EventTypeHTTPClient,
				SubType: tt.subType,
				GenAI:   tt.genAI(request.NewTokenCount(0)),
			}

			selected := AttrsToMap(TraceAttributesSelector(span, defaultAttrs))
			for _, key := range tt.keys {
				value, ok := selected.Get(key)
				require.True(t, ok, key)
				assert.Zero(t, value.Int(), key)
			}

			span.GenAI = tt.genAI(request.TokenCount{})
			selected = AttrsToMap(TraceAttributesSelector(span, defaultAttrs))
			for _, key := range tt.keys {
				_, ok := selected.Get(key)
				assert.False(t, ok, key)
			}
		})
	}
}
