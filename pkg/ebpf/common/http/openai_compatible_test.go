// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
)

const compatibleChatRequestBody = `{
  "model":"gpt-4o-mini",
  "messages":[
    {"role":"system","content":"You are a helpful assistant."},
    {"role":"user","content":"Hello!"}
  ],
  "temperature":0.7
}`

const compatibleChatResponseBody = `{
  "id":"chatcmpl-gw-001",
  "object":"chat.completion",
  "model":"gpt-4o-mini-2024-07-18",
  "choices":[
    {"index":0,"message":{"role":"assistant","content":"Hi there! How can I help you?"},"finish_reason":"stop"}
  ],
  "usage":{"prompt_tokens":10,"completion_tokens":8,"total_tokens":18}
}`

const compatibleEmbeddingsRequestBody = `{"input":"The food was delicious","model":"text-embedding-3-small","dimensions":256}`

const compatibleEmbeddingsResponseBody = `{
  "object":"list",
  "data":[
    {"object":"embedding","embedding":[0.0023,-0.0093],"index":0}
  ],
  "model":"text-embedding-3-small",
  "usage":{"prompt_tokens":5,"total_tokens":5}
}`

const compatibleSSEResponseBody = `data: {"id":"chatcmpl-sse-001","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":"Hello"},"finish_reason":null}]}

data: {"id":"chatcmpl-sse-001","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":" world!"},"finish_reason":null}]}

data: {"id":"chatcmpl-sse-001","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":3,"total_tokens":13}}

data: [DONE]

`

const htmlResponseBody = `<html><body><h1>Welcome</h1></body></html>`

func makeCompatibleResponse(body string) *http.Response {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestOpenAICompatibleSpan_HostMatchWithoutPort(t *testing.T) {
	gateways := []config.OpenAICompatibleGateway{
		{Host: "litellm.local", Provider: "litellm"},
	}
	req := makeRequest(t, http.MethodPost, "http://litellm.local:443/v1/chat/completions", compatibleChatRequestBody)
	resp := makeCompatibleResponse(compatibleChatResponseBody)

	base := &request.Span{}
	span, ok := OpenAICompatibleSpan(base, req, resp, gateways)

	require.True(t, ok)
	assert.Equal(t, request.HTTPSubtypeOpenAICompatible, span.SubType)
}

func TestOpenAICompatibleSpan_HostMatchWithPort(t *testing.T) {
	gateways := []config.OpenAICompatibleGateway{
		{Host: "localhost", Port: 8080, Provider: "litellm"},
	}
	req := makeRequest(t, http.MethodPost, "http://localhost:8080/v1/chat/completions", compatibleChatRequestBody)
	resp := makeCompatibleResponse(compatibleChatResponseBody)

	base := &request.Span{}
	span, ok := OpenAICompatibleSpan(base, req, resp, gateways)

	require.True(t, ok)
	assert.Equal(t, request.HTTPSubtypeOpenAICompatible, span.SubType)
}

func TestOpenAICompatibleSpan_PortMismatch(t *testing.T) {
	gateways := []config.OpenAICompatibleGateway{
		{Host: "localhost", Port: 8080},
	}
	req := makeRequest(t, http.MethodPost, "http://localhost:9090/v1/chat/completions", compatibleChatRequestBody)
	resp := makeCompatibleResponse(compatibleChatResponseBody)

	base := &request.Span{}
	_, ok := OpenAICompatibleSpan(base, req, resp, gateways)

	assert.False(t, ok)
}

func TestOpenAICompatibleSpan_HostMismatch(t *testing.T) {
	gateways := []config.OpenAICompatibleGateway{
		{Host: "litellm.local"},
	}
	req := makeRequest(t, http.MethodPost, "http://api.openai.com/v1/chat/completions", compatibleChatRequestBody)
	resp := makeCompatibleResponse(compatibleChatResponseBody)

	base := &request.Span{}
	_, ok := OpenAICompatibleSpan(base, req, resp, gateways)

	assert.False(t, ok)
}

func TestOpenAICompatibleSpan_MatchedButInvalidBody(t *testing.T) {
	gateways := []config.OpenAICompatibleGateway{
		{Host: "litellm.local", Provider: "litellm"},
	}
	req := makeRequest(t, http.MethodPost, "http://litellm.local/v1/chat/completions", `{}`)
	resp := makeCompatibleResponse(htmlResponseBody)

	base := &request.Span{}
	_, ok := OpenAICompatibleSpan(base, req, resp, gateways)

	assert.False(t, ok)
}

func TestOpenAICompatibleSpan_ChatCompletions(t *testing.T) {
	gateways := []config.OpenAICompatibleGateway{
		{Host: "litellm.local", Provider: "litellm"},
	}
	req := makeRequest(t, http.MethodPost, "http://litellm.local/v1/chat/completions", compatibleChatRequestBody)
	resp := makeCompatibleResponse(compatibleChatResponseBody)

	base := &request.Span{}
	span, ok := OpenAICompatibleSpan(base, req, resp, gateways)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.OpenAICompatible)
	assert.Equal(t, request.HTTPSubtypeOpenAICompatible, span.SubType)

	ai := span.GenAI.OpenAICompatible
	assert.Equal(t, "chatcmpl-gw-001", ai.ID)
	assert.Equal(t, request.ChatOperationName, ai.OperationName)
	assert.Equal(t, "chat_completions", ai.APIType)
	assert.Equal(t, "gpt-4o-mini-2024-07-18", ai.ResponseModel)
	assert.Equal(t, 10, ai.Usage.GetInputTokens())
	assert.Equal(t, 8, ai.Usage.GetOutputTokens())
	assert.NotEmpty(t, ai.GetOutput())
}

func TestOpenAICompatibleSpan_Embeddings(t *testing.T) {
	gateways := []config.OpenAICompatibleGateway{
		{Host: "litellm.local", Provider: "litellm"},
	}
	req := makeRequest(t, http.MethodPost, "http://litellm.local/v1/embeddings", compatibleEmbeddingsRequestBody)
	resp := makeCompatibleResponse(compatibleEmbeddingsResponseBody)

	base := &request.Span{}
	span, ok := OpenAICompatibleSpan(base, req, resp, gateways)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.OpenAICompatible)

	ai := span.GenAI.OpenAICompatible
	assert.Equal(t, request.EmbeddingOperationName, ai.OperationName)
	assert.Equal(t, "embeddings", ai.APIType)
	assert.Equal(t, "text-embedding-3-small", ai.ResponseModel)
	assert.Equal(t, 5, ai.Usage.GetInputTokens())
	assert.Equal(t, 256, ai.GetEmbeddingDimensions())
}

func TestOpenAICompatibleSpan_SSEStream(t *testing.T) {
	gateways := []config.OpenAICompatibleGateway{
		{Host: "litellm.local", Provider: "litellm"},
	}
	req := makeRequest(t, http.MethodPost, "http://litellm.local/v1/chat/completions", compatibleChatRequestBody)
	resp := makeCompatibleResponse(compatibleSSEResponseBody)

	base := &request.Span{}
	span, ok := OpenAICompatibleSpan(base, req, resp, gateways)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.OpenAICompatible)

	ai := span.GenAI.OpenAICompatible
	assert.Equal(t, "chatcmpl-sse-001", ai.ID)
	assert.Equal(t, request.ChatOperationName, ai.OperationName)
	assert.Equal(t, "gpt-4o-mini", ai.ResponseModel)
	assert.Equal(t, 10, ai.Usage.GetInputTokens())
	assert.Equal(t, 3, ai.Usage.GetOutputTokens())

	reasons := ai.GetFinishReasons()
	require.Len(t, reasons, 1)
	assert.Equal(t, "stop", reasons[0])

	output := ai.GetOutput()
	assert.Contains(t, output, "Hello")
	assert.Contains(t, output, "world!")
}

func TestOpenAICompatibleSpan_ProviderNameSet(t *testing.T) {
	gateways := []config.OpenAICompatibleGateway{
		{Host: "litellm.local", Provider: "litellm"},
	}
	req := makeRequest(t, http.MethodPost, "http://litellm.local/v1/chat/completions", compatibleChatRequestBody)
	resp := makeCompatibleResponse(compatibleChatResponseBody)

	base := &request.Span{}
	span, ok := OpenAICompatibleSpan(base, req, resp, gateways)

	require.True(t, ok)
	ai := span.GenAI.OpenAICompatible
	assert.Equal(t, "litellm", ai.ProviderName)
}

func TestOpenAICompatibleSpan_ProviderNameEmptyFallback(t *testing.T) {
	gateways := []config.OpenAICompatibleGateway{
		{Host: "litellm.local"},
	}
	req := makeRequest(t, http.MethodPost, "http://litellm.local/v1/chat/completions", compatibleChatRequestBody)
	resp := makeCompatibleResponse(compatibleChatResponseBody)

	base := &request.Span{}
	span, ok := OpenAICompatibleSpan(base, req, resp, gateways)

	require.True(t, ok)
	ai := span.GenAI.OpenAICompatible
	assert.Empty(t, ai.ProviderName)

	span.Type = request.EventTypeHTTPClient
	assert.Equal(t, "custom", span.GenAIProviderName())
}

func TestOpenAICompatibleSpan_CaseInsensitiveHost(t *testing.T) {
	gateways := []config.OpenAICompatibleGateway{
		{Host: "LiteLLM.Local", Provider: "litellm"},
	}
	req := makeRequest(t, http.MethodPost, "http://litellm.local/v1/chat/completions", compatibleChatRequestBody)
	resp := makeCompatibleResponse(compatibleChatResponseBody)

	base := &request.Span{}
	span, ok := OpenAICompatibleSpan(base, req, resp, gateways)

	require.True(t, ok)
	assert.Equal(t, request.HTTPSubtypeOpenAICompatible, span.SubType)
	assert.Equal(t, "litellm", span.GenAI.OpenAICompatible.ProviderName)
}

func TestOpenAICompatibleSpan_EmptyGateways(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://litellm.local/v1/chat/completions", compatibleChatRequestBody)
	resp := makeCompatibleResponse(compatibleChatResponseBody)

	base := &request.Span{}
	_, ok := OpenAICompatibleSpan(base, req, resp, nil)

	assert.False(t, ok)
}

func TestOpenAICompatibleSpan_TextCompletions(t *testing.T) {
	gateways := []config.OpenAICompatibleGateway{
		{Host: "litellm.local", Provider: "litellm"},
	}
	reqBody := `{"model":"gpt-3.5-turbo-instruct","prompt":"Say hello"}`
	respBody := `{"id":"cmpl-001","object":"text_completion","model":"gpt-3.5-turbo-instruct","choices":[{"text":"Hello!","finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":2,"total_tokens":4}}`
	req := makeRequest(t, http.MethodPost, "http://litellm.local/v1/completions", reqBody)
	resp := makeCompatibleResponse(respBody)

	base := &request.Span{}
	span, ok := OpenAICompatibleSpan(base, req, resp, gateways)

	require.True(t, ok)
	ai := span.GenAI.OpenAICompatible
	assert.Equal(t, request.CompletionOperationName, ai.OperationName)
	assert.Equal(t, "text_completions", ai.APIType)
}

// TestOpenAICompatibleSpan_NamedProviderWins verifies that when a response
// carries OpenAI-specific headers, OpenAISpan matches first (ok=true) and the
// resulting span is classified as the named OpenAI provider, not as
// OpenAICompatible. This confirms the dispatch priority: named providers are
// checked before the generic OpenAI-compatible fallback.
func TestOpenAICompatibleSpan_NamedProviderWins(t *testing.T) {
	gateways := []config.OpenAICompatibleGateway{
		{Host: "api.openai.com", Provider: "openai"},
	}
	req := makeRequest(t, http.MethodPost, "http://api.openai.com/v1/chat/completions", compatibleChatRequestBody)
	// Response carries OpenAI-specific headers (gzip-encoded body).
	resp := makeGzipResponse(t, http.StatusOK, openAIHeaders(), compatibleChatResponseBody)

	base := &request.Span{}
	span, ok := OpenAISpan(base, req, resp)

	require.True(t, ok, "OpenAISpan should match when OpenAI headers are present")
	assert.Equal(t, request.HTTPSubtypeOpenAI, span.SubType,
		"named provider should be classified as OpenAI, not OpenAICompatible")
	require.NotNil(t, span.GenAI.OpenAI)
	assert.Nil(t, span.GenAI.OpenAICompatible)

	// Additionally verify that OpenAICompatibleSpan would also match the host,
	// confirming the priority is what makes the difference (not host exclusion).
	base2 := &request.Span{}
	_, okCompat := OpenAICompatibleSpan(base2, req, makeCompatibleResponse(compatibleChatResponseBody), gateways)
	assert.True(t, okCompat, "host should also match the OpenAI-compatible gateway")
}

const compatibleResponsesRequestBody = `{"input":"Hello","model":"gpt-4o-mini"}`

const compatibleResponsesResponseBody = `{
  "id":"resp-gw-001",
  "object":"response",
  "model":"gpt-4o-mini",
  "output":[
    {"type":"message","status":"completed","content":[{"type":"output_text","text":"Hi there!"}],"role":"assistant"}
  ],
  "usage":{"input_tokens":5,"output_tokens":3,"total_tokens":8}
}`

func TestOpenAICompatibleSpan_ResponsesAPI(t *testing.T) {
	gateways := []config.OpenAICompatibleGateway{
		{Host: "litellm.local", Provider: "litellm"},
	}
	req := makeRequest(t, http.MethodPost, "http://litellm.local/v1/responses", compatibleResponsesRequestBody)
	resp := makeCompatibleResponse(compatibleResponsesResponseBody)

	base := &request.Span{}
	span, ok := OpenAICompatibleSpan(base, req, resp, gateways)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.OpenAICompatible)

	ai := span.GenAI.OpenAICompatible
	assert.Equal(t, "responses", ai.APIType)
	assert.Equal(t, "resp-gw-001", ai.ID)
	assert.Equal(t, "gpt-4o-mini", ai.ResponseModel)
	assert.NotEmpty(t, ai.Output)
	assert.Equal(t, 5, ai.Usage.GetInputTokens())
	assert.Equal(t, 3, ai.Usage.GetOutputTokens())
}

const compatibleSSEToolCallsResponseBody = `data: {"id":"chatcmpl-tc-001","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_001","type":"function","function":{"name":"get_weather","arguments":"{}"}}]},"finish_reason":null}]}

data: {"id":"chatcmpl-tc-001","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":10,"completion_tokens":0,"total_tokens":10}}

data: [DONE]

`

func TestOpenAICompatibleSpan_SSEToolCalls(t *testing.T) {
	gateways := []config.OpenAICompatibleGateway{
		{Host: "litellm.local", Provider: "litellm"},
	}
	req := makeRequest(t, http.MethodPost, "http://litellm.local/v1/chat/completions", compatibleChatRequestBody)
	resp := makeCompatibleResponse(compatibleSSEToolCallsResponseBody)

	base := &request.Span{}
	span, ok := OpenAICompatibleSpan(base, req, resp, gateways)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.OpenAICompatible)

	ai := span.GenAI.OpenAICompatible
	assert.Equal(t, request.ChatOperationName, ai.OperationName)
	assert.Equal(t, "chatcmpl-tc-001", ai.ID)
	assert.Equal(t, "gpt-4o-mini", ai.ResponseModel)

	require.NotEmpty(t, ai.ToolCalls, "tool calls should be extracted from SSE stream")
	assert.Equal(t, "call_001", ai.ToolCalls[0].ID)
	assert.Equal(t, "get_weather", ai.ToolCalls[0].Name)

	reasons := ai.GetFinishReasons()
	require.Len(t, reasons, 1)
	assert.Equal(t, "tool_calls", reasons[0])
}

func TestOpenAICompatibleSpan_GatewayPortWithUnknownRequestPort(t *testing.T) {
	gateways := []config.OpenAICompatibleGateway{
		{Host: "gateway.example.com", Port: 443, Provider: "custom"},
	}
	// URL without explicit port — port will be 0 (unknown)
	req := makeRequest(t, http.MethodPost, "http://gateway.example.com/v1/chat/completions", compatibleChatRequestBody)
	resp := makeCompatibleResponse(compatibleChatResponseBody)

	base := &request.Span{}
	span, ok := OpenAICompatibleSpan(base, req, resp, gateways)

	require.True(t, ok, "gateway should match when request port is unknown (0)")
	assert.Equal(t, request.HTTPSubtypeOpenAICompatible, span.SubType)
	assert.Equal(t, "custom", span.GenAI.OpenAICompatible.ProviderName)
}

func TestOpenAICompatibleSpan_ResponsesAPIWithoutTotalTokens(t *testing.T) {
	gateways := []config.OpenAICompatibleGateway{
		{Host: "litellm.local", Provider: "litellm"},
	}
	// /v1/responses response with output but no total_tokens — should not be rejected
	respBody := `{
  "id":"resp-gw-002",
  "object":"response",
  "model":"gpt-4o-mini",
  "output":[
    {"type":"message","status":"completed","content":[{"type":"output_text","text":"Hello!"}],"role":"assistant"}
  ]
}`
	req := makeRequest(t, http.MethodPost, "http://litellm.local/v1/responses", compatibleResponsesRequestBody)
	resp := makeCompatibleResponse(respBody)

	base := &request.Span{}
	span, ok := OpenAICompatibleSpan(base, req, resp, gateways)

	require.True(t, ok, "response with output but no total_tokens should not be rejected")
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.OpenAICompatible)

	ai := span.GenAI.OpenAICompatible
	assert.Equal(t, "responses", ai.APIType)
	assert.Equal(t, "resp-gw-002", ai.ID)
	assert.NotEmpty(t, ai.Output)
}
