// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// --- Non-streaming /api/chat ---

const ollamaChatRequest = `{"model":"llama3.2","messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"Hello!"}],"stream":false}`

const ollamaChatResponse = `{
  "model": "llama3.2",
  "message": {"role":"assistant","content":"Hello! How can I help you today?"},
  "done": true,
  "done_reason": "stop",
  "prompt_eval_count": 26,
  "eval_count": 9
}`

func TestOllamaSpan_ChatNonStreaming(t *testing.T) {
	span, ok := runOllamaSpan(t, "/api/chat", ollamaChatRequest, ollamaChatResponse)
	require.True(t, ok)

	assert.Equal(t, request.HTTPSubtypeOllama, span.SubType)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Ollama)

	ai := span.GenAI.Ollama
	assert.Equal(t, "chat", ai.OperationName)
	assert.Equal(t, "llama3.2", ai.Request.Model)
	assert.Equal(t, "llama3.2", ai.ResponseModel)
	assert.Equal(t, "ollama", ai.ProviderName)
	assert.Equal(t, 26, tokenValue(ai.Usage.InputTokens))
	assert.Equal(t, 9, tokenValue(ai.Usage.OutputTokens))
	assert.Equal(t, []string{"stop"}, ai.GetFinishReasons())
	assert.False(t, ai.Request.Stream)
}

func TestOllamaSpan_ExplicitZeroUsage(t *testing.T) {
	response := `{"model":"llama3.2","message":{"role":"assistant","content":""},"done":true,"prompt_eval_count":0,"eval_count":0}`
	span, ok := runOllamaSpan(t, "/api/chat", ollamaChatRequest, response)
	require.True(t, ok)

	assert.True(t, isReported(span.GenAIInputTokenCount()))
	assert.True(t, isReported(span.GenAIOutputTokenCount()))
	assert.Zero(t, reportedValue(span.GenAIInputTokenCount()))
	assert.Zero(t, reportedValue(span.GenAIOutputTokenCount()))
}

func TestOllamaSpan_MissingUsage(t *testing.T) {
	response := `{"model":"llama3.2","message":{"role":"assistant","content":""},"done":true}`
	span, ok := runOllamaSpan(t, "/api/chat", ollamaChatRequest, response)
	require.True(t, ok)

	assert.False(t, isReported(span.GenAIInputTokenCount()))
	assert.False(t, isReported(span.GenAIOutputTokenCount()))
}

func TestOllamaSpan_InvalidUsage(t *testing.T) {
	for _, tt := range []struct {
		name  string
		usage string
	}{
		{name: "strings", usage: `"prompt_eval_count":"7","eval_count":"3"`},
		{name: "fractions", usage: `"prompt_eval_count":7.5,"eval_count":3.5`},
		{name: "exponents", usage: `"prompt_eval_count":7e2,"eval_count":3e2`},
		{name: "overflow", usage: `"prompt_eval_count":999999999999999999999999,"eval_count":999999999999999999999999`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			response := `{"model":"llama3.2","message":{"role":"assistant","content":""},"done":true,` + tt.usage + `}`
			span, ok := runOllamaSpan(t, "/api/chat", ollamaChatRequest, response)
			require.True(t, ok)
			assert.False(t, isReported(span.GenAIInputTokenCount()))
			assert.False(t, isReported(span.GenAIOutputTokenCount()))
		})
	}
}

func TestOllamaSpan_InvalidUsagePreservesValidSibling(t *testing.T) {
	response := `{"model":"llama3.2","message":{"role":"assistant","content":""},"done":true,"prompt_eval_count":7,"eval_count":3.5}`
	span, ok := runOllamaSpan(t, "/api/chat", ollamaChatRequest, response)
	require.True(t, ok)
	assert.True(t, isReported(span.GenAIInputTokenCount()))
	assert.Equal(t, 7, reportedValue(span.GenAIInputTokenCount()))
	assert.False(t, isReported(span.GenAIOutputTokenCount()))
}

func TestOllamaSpan_UsageAfterMalformedEnvelopeField(t *testing.T) {
	response := `{"model":"llama3.2","done":{},"prompt_eval_count":0,"eval_count":7}`
	span, ok := runOllamaSpan(t, "/api/chat", ollamaChatRequest, response)
	require.True(t, ok)
	assert.True(t, isReported(span.GenAIInputTokenCount()))
	assert.Zero(t, reportedValue(span.GenAIInputTokenCount()))
	assert.Equal(t, 7, reportedValue(span.GenAIOutputTokenCount()))
}

// --- Streaming /api/chat ---

const ollamaChatStreamResponse = `{"model":"llama3.2","message":{"role":"assistant","content":"Hello"},"done":false}
{"model":"llama3.2","message":{"role":"assistant","content":"!"},"done":false}
{"model":"llama3.2","message":{"role":"assistant","content":""},"done":true,"done_reason":"stop","prompt_eval_count":26,"eval_count":2}`

func TestOllamaSpan_StreamUsageAfterMalformedEnvelopeField(t *testing.T) {
	response := `{"model":"llama3.2","message":{"role":"assistant","content":"Hi"},"done":false}
{"model":"llama3.2","done":{},"prompt_eval_count":0,"eval_count":0}`
	span, ok := runOllamaSpanRaw(t, "/api/chat", ollamaChatRequest, response)
	require.True(t, ok)
	assert.True(t, isReported(span.GenAIInputTokenCount()))
	assert.True(t, isReported(span.GenAIOutputTokenCount()))
	assert.Zero(t, reportedValue(span.GenAIInputTokenCount()))
	assert.Zero(t, reportedValue(span.GenAIOutputTokenCount()))
}

func TestOllamaSpan_ChatStreaming(t *testing.T) {
	reqBody := `{"model":"llama3.2","messages":[{"role":"user","content":"Hi"}],"stream":true}`
	span, ok := runOllamaSpanRaw(t, "/api/chat", reqBody, ollamaChatStreamResponse)
	require.True(t, ok)

	ai := span.GenAI.Ollama
	assert.Equal(t, "chat", ai.OperationName)
	assert.Equal(t, "llama3.2", ai.ResponseModel)
	assert.Equal(t, 26, tokenValue(ai.Usage.InputTokens))
	assert.Equal(t, 2, tokenValue(ai.Usage.OutputTokens))
	assert.Equal(t, []string{"stop"}, ai.GetFinishReasons())
	assert.True(t, ai.Request.Stream)
}

// --- Default streaming (stream field omitted, defaults to true per Ollama API) ---

func TestOllamaSpan_ChatDefaultStream(t *testing.T) {
	reqBody := `{"model":"llama3.2","messages":[{"role":"user","content":"Hi"}]}`
	span, ok := runOllamaSpanRaw(t, "/api/chat", reqBody, ollamaChatStreamResponse)
	require.True(t, ok)

	ai := span.GenAI.Ollama
	assert.True(t, ai.Request.Stream, "stream defaults to true when omitted")
}

// --- Non-streaming /api/generate ---

const ollamaGenerateRequest = `{"model":"llama3.2","prompt":"Why is the sky blue?","system":"Be concise.","stream":false}`

const ollamaGenerateResponse = `{
  "model": "llama3.2",
  "response": "The sky appears blue due to Rayleigh scattering.",
  "done": true,
  "done_reason": "stop",
  "prompt_eval_count": 12,
  "eval_count": 15
}`

func TestOllamaSpan_GenerateNonStreaming(t *testing.T) {
	span, ok := runOllamaSpan(t, "/api/generate", ollamaGenerateRequest, ollamaGenerateResponse)
	require.True(t, ok)

	ai := span.GenAI.Ollama
	assert.Equal(t, "text_completion", ai.OperationName)
	assert.Equal(t, "llama3.2", ai.Request.Model)
	assert.Equal(t, "llama3.2", ai.ResponseModel)
	assert.Equal(t, 12, tokenValue(ai.Usage.InputTokens))
	assert.Equal(t, 15, tokenValue(ai.Usage.OutputTokens))
	assert.Equal(t, []string{"stop"}, ai.GetFinishReasons())
	// System instruction should be in Request.Instructions for generate
	assert.Equal(t, "Be concise.", ai.Request.Instructions)
}

// --- Streaming /api/generate ---

const ollamaGenerateStreamResponse = `{"model":"llama3.2","response":"The ","done":false}
{"model":"llama3.2","response":"sky ","done":false}
{"model":"llama3.2","response":"is blue.","done":false}
{"model":"llama3.2","response":"","done":true,"done_reason":"stop","prompt_eval_count":10,"eval_count":8}`

func TestOllamaSpan_GenerateStreaming(t *testing.T) {
	reqBody := `{"model":"llama3.2","prompt":"Why is the sky blue?","stream":true}`
	span, ok := runOllamaSpanRaw(t, "/api/generate", reqBody, ollamaGenerateStreamResponse)
	require.True(t, ok)

	ai := span.GenAI.Ollama
	assert.Equal(t, "text_completion", ai.OperationName)
	assert.Equal(t, 10, tokenValue(ai.Usage.InputTokens))
	assert.Equal(t, 8, tokenValue(ai.Usage.OutputTokens))
	assert.Equal(t, []string{"stop"}, ai.GetFinishReasons())
	assert.True(t, ai.Request.Stream)
}

func TestOllamaSpan_StreamingMergesCumulativeUsageFields(t *testing.T) {
	stream := `{"model":"llama3.2","response":"ok","done":false,"prompt_eval_count":6,"eval_count":3}
{"model":"llama3.2","response":"","done":true,"done_reason":"stop","eval_count":0}`

	span, ok := runOllamaSpanRaw(t, "/api/generate", ollamaGenerateRequest, stream)
	require.True(t, ok)

	assertTokenCount(t, span.GenAI.Ollama.Usage.InputTokens, 6, true)
	assertTokenCount(t, span.GenAI.Ollama.Usage.OutputTokens, 0, true)
}

func TestOllamaSpan_StreamingUsageSurvivesMalformedAndTruncatedSiblings(t *testing.T) {
	stream := `{"model":"llama3.2","prompt_eval_count":7,"done":"yes"}
{"model":"llama3.2","eval_count":0,"message":`

	span, ok := runOllamaSpanRaw(t, "/api/generate", ollamaGenerateRequest, stream)
	require.True(t, ok)

	assertTokenCount(t, span.GenAI.Ollama.Usage.InputTokens, 7, true)
	assertTokenCount(t, span.GenAI.Ollama.Usage.OutputTokens, 0, true)
}

// --- Tool calls ---

const ollamaChatToolCallResponse = `{
  "model": "llama3.2",
  "message": {"role":"assistant","content":"","tool_calls":[{"function":{"name":"get_weather","arguments":{"location":"Paris"}}}]},
  "done": true,
  "done_reason": "stop",
  "prompt_eval_count": 50,
  "eval_count": 20
}`

func TestOllamaSpan_ToolCalls(t *testing.T) {
	reqBody := `{"model":"llama3.2","messages":[{"role":"user","content":"What is the weather in Paris?"}],"tools":[{"type":"function","function":{"name":"get_weather"}}],"stream":false}`
	span, ok := runOllamaSpan(t, "/api/chat", reqBody, ollamaChatToolCallResponse)
	require.True(t, ok)

	ai := span.GenAI.Ollama
	require.Len(t, ai.ToolCalls, 1)
	assert.Equal(t, "get_weather", ai.ToolCalls[0].Name)
}

// --- Request and response model differences ---

const ollamaModelDiffResponse = `{
  "model": "llama3.2:latest",
  "message": {"role":"assistant","content":"Hi"},
  "done": true,
  "done_reason": "stop",
  "prompt_eval_count": 5,
  "eval_count": 2
}`

func TestOllamaSpan_ModelDifference(t *testing.T) {
	reqBody := `{"model":"llama3.2","messages":[{"role":"user","content":"Hi"}],"stream":false}`
	span, ok := runOllamaSpan(t, "/api/chat", reqBody, ollamaModelDiffResponse)
	require.True(t, ok)

	ai := span.GenAI.Ollama
	assert.Equal(t, "llama3.2", ai.Request.Model)
	assert.Equal(t, "llama3.2:latest", ai.ResponseModel)
}

// --- Negative: unrelated path ---

func TestOllamaSpan_UnrelatedPath(t *testing.T) {
	_, ok := runOllamaSpan(t, "/v1/chat/completions", ollamaChatRequest, ollamaChatResponse)
	assert.False(t, ok)
}

// --- Negative: malformed response ---

func TestOllamaSpan_MalformedPayload(t *testing.T) {
	_, ok := runOllamaSpanRaw(t, "/api/chat", `{"model":"llama3.2"}`, "not json at all{broken")
	assert.False(t, ok)
}

// --- TraceName ---

func TestOllamaSpan_TraceName(t *testing.T) {
	span, ok := runOllamaSpan(t, "/api/chat", ollamaChatRequest, ollamaChatResponse)
	require.True(t, ok)
	assert.Equal(t, "chat llama3.2", span.TraceName())
}

func TestOllamaSpan_TraceNameGenerate(t *testing.T) {
	span, ok := runOllamaSpan(t, "/api/generate", ollamaGenerateRequest, ollamaGenerateResponse)
	require.True(t, ok)
	assert.Equal(t, "text_completion llama3.2", span.TraceName())
}

// --- GenAI helpers ---

func TestOllamaSpan_GenAIHelpers(t *testing.T) {
	span, ok := runOllamaSpan(t, "/api/chat", ollamaChatRequest, ollamaChatResponse)
	require.True(t, ok)

	assert.Equal(t, "chat", span.GenAIOperationName())
	assert.Equal(t, "ollama", span.GenAIProviderName())
	assert.Equal(t, "llama3.2", span.GenAIRequestModel())
	assert.Equal(t, "llama3.2", span.GenAIResponseModel())
	assert.Equal(t, 26, reportedValue(span.GenAIInputTokenCount()))
	assert.Equal(t, 9, reportedValue(span.GenAIOutputTokenCount()))
}

// --- /api/embed and legacy /api/embeddings ---

const (
	ollamaEmbedModel        = "all-minilm:l6-v2"
	ollamaEmbedRequest      = `{"model":"all-minilm:l6-v2","input":"why is the sky blue?"}`
	ollamaEmbedResponse     = `{"model":"all-minilm:l6-v2","embeddings":[[0.0100353705,-0.0017759022,0.05005609,0.04692976]],"total_duration":301430470,"load_duration":283978494,"prompt_eval_count":8}`
	ollamaLegacyRequest     = `{"model":"all-minilm:l6-v2","prompt":"why is the sky blue?"}`
	ollamaLegacyResponse    = `{"embedding":[0.0100353705,-0.0017759022,0.05005609]}`
	ollamaEmbedErrorMissing = `{"error":"model \"nope\" not found, try pulling it first"}`
)

func TestOllamaSpan_Embed(t *testing.T) {
	span, ok := runOllamaSpan(t, "/api/embed", ollamaEmbedRequest, ollamaEmbedResponse)
	require.True(t, ok)

	assert.Equal(t, request.HTTPSubtypeOllama, span.SubType)
	ai := span.GenAI.Ollama
	assert.Equal(t, request.EmbeddingOperationName, ai.OperationName)
	assert.Equal(t, "ollama", ai.ProviderName)
	assert.Equal(t, ollamaEmbedModel, ai.Request.Model)
	assert.Equal(t, ollamaEmbedModel, ai.ResponseModel)
	assert.Equal(t, "why is the sky blue?", ai.Request.Input)
	assert.Equal(t, 8, tokenValue(ai.Usage.InputTokens))
	assert.False(t, isReported(ai.Usage.OutputTokens.Get()))
	assert.Equal(t, 4, ai.GetEmbeddingDimensions())
	assert.Empty(t, ai.GetFinishReasons())
	assert.Empty(t, ai.GetOutput(), "vectors must not be exported as output messages")
	assert.False(t, ai.Request.Stream, "a missing stream flag means streaming on chat, but embeddings never stream")
}

func TestOllamaSpan_EmbedIgnoresStreamFlag(t *testing.T) {
	reqBody := `{"model":"all-minilm:l6-v2","input":"x","stream":true}`
	span, ok := runOllamaSpan(t, "/api/embed", reqBody, ollamaEmbedResponse)
	require.True(t, ok)

	assert.False(t, span.GenAI.Ollama.Request.Stream)
}

func TestOllamaSpan_EmbedBatchUsesFirstVector(t *testing.T) {
	reqBody := `{"input":["a","b"],"model":"all-minilm"}`
	respBody := `{"model":"all-minilm:l6-v2","embeddings":[[0.1,0.2,0.3],[0.4,0.5,0.6]],"prompt_eval_count":6}`
	span, ok := runOllamaSpan(t, "/api/embed", reqBody, respBody)
	require.True(t, ok)

	ai := span.GenAI.Ollama
	assert.Equal(t, "all-minilm", ai.Request.Model)
	assert.Empty(t, ai.Request.Input)
	assert.Equal(t, 3, ai.GetEmbeddingDimensions())
	assert.Equal(t, 6, tokenValue(ai.Usage.InputTokens))
}

func TestOllamaSpan_LegacyEmbeddings(t *testing.T) {
	span, ok := runOllamaSpan(t, "/api/embeddings", ollamaLegacyRequest, ollamaLegacyResponse)
	require.True(t, ok)

	ai := span.GenAI.Ollama
	assert.Equal(t, request.EmbeddingOperationName, ai.OperationName)
	assert.Equal(t, ollamaEmbedModel, ai.Request.Model)
	assert.Equal(t, ollamaEmbedModel, ai.ResponseModel, "the legacy response has no model, so it falls back to the request")
	assert.Equal(t, "why is the sky blue?", ai.Request.Prompt)
	assert.Equal(t, 3, ai.GetEmbeddingDimensions())
	assert.False(t, isReported(span.GenAIInputTokenCount()), "the legacy response has no token counts")
}

func TestOllamaSpan_EmbedEmptyVectors(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		reqBody  string
		respBody string
	}{
		{name: "embed", path: "/api/embed", reqBody: `{"model":"all-minilm:l6-v2","input":""}`, respBody: `{"model":"all-minilm:l6-v2","embeddings":[]}`},
		{name: "legacy", path: "/api/embeddings", reqBody: `{"model":"all-minilm:l6-v2","prompt":""}`, respBody: `{"embedding":[]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span, ok := runOllamaSpan(t, tt.path, tt.reqBody, tt.respBody)
			require.True(t, ok)
			assert.Zero(t, span.GenAI.Ollama.GetEmbeddingDimensions())
		})
	}
}

func TestOllamaSpan_EmbedError(t *testing.T) {
	for _, path := range []string{"/api/embed", "/api/embeddings"} {
		t.Run(path, func(t *testing.T) {
			span, ok := runOllamaSpan(t, path, `{"model":"nope","input":"x"}`, ollamaEmbedErrorMissing)
			require.True(t, ok)

			ai := span.GenAI.Ollama
			assert.Equal(t, request.EmbeddingOperationName, ai.OperationName)
			assert.Equal(t, "nope", ai.Request.Model)
			assert.Zero(t, ai.GetEmbeddingDimensions())
		})
	}
}

func TestOllamaSpan_EmbedRejectsOtherProviders(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		respBody string
	}{
		{name: "OpenAI on legacy path", path: "/api/embeddings", respBody: `{"object":"list","data":[{"object":"embedding","embedding":[0.1,0.2],"index":0}],"model":"m","usage":{"prompt_tokens":5,"total_tokens":5}}`},
		{name: "OpenAI on embed path", path: "/proxy/api/embed", respBody: `{"object":"list","data":[{"object":"embedding","embedding":[0.1,0.2],"index":0}],"model":"m"}`},
		{name: "OpenAI error", path: "/api/embeddings", respBody: `{"error":{"message":"bad key","type":"invalid_request_error"}}`},
		{name: "DashScope", path: "/api/embed", respBody: `{"output":{"embeddings":[{"embedding":[0.1,0.2],"text_index":0}]},"usage":{"total_tokens":5}}`},
		{name: "array of objects", path: "/api/embed", respBody: `{"embeddings":[{"values":[0.1,0.2]}]}`},
		{name: "object of arrays", path: "/api/embed", respBody: `{"embeddings":{"float":[[0.1,0.2]]}}`},
		{name: "legacy array of objects", path: "/api/embeddings", respBody: `{"embedding":[{"values":[0.1,0.2]}]}`},
		{name: "legacy array of strings", path: "/api/embeddings", respBody: `{"embedding":["a","b"]}`},
		{name: "unrelated JSON", path: "/api/embed", respBody: `{"status":"ok"}`},
		{name: "not JSON", path: "/api/embed", respBody: `upstream connect error`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span, ok := runOllamaSpan(t, tt.path, `{"model":"m","input":"x"}`, tt.respBody)
			assert.False(t, ok)
			assert.Nil(t, span.GenAI)
		})
	}
}

func TestOllamaSpan_EmbedTruncatedResponse(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		reqBody  string
		respBody string
		wantDims int
	}{
		{
			name:     "embed inside first vector",
			path:     "/api/embed",
			reqBody:  ollamaEmbedRequest,
			respBody: `{"model":"all-minilm:l6-v2","embeddings":[[0.0100353705,-0.00177`,
		},
		{
			name:     "embed inside second vector",
			path:     "/api/embed",
			reqBody:  ollamaEmbedRequest,
			respBody: `{"model":"all-minilm:l6-v2","embeddings":[[0.1,0.2,0.3],[0.4,0.5`,
			wantDims: 3,
		},
		{
			name:     "embed right after first vector",
			path:     "/api/embed",
			reqBody:  ollamaEmbedRequest,
			respBody: `{"model":"all-minilm:l6-v2","embeddings":[[0.1,0.2,0.3]`,
			wantDims: 3,
		},
		{
			name:     "legacy inside vector",
			path:     "/api/embeddings",
			reqBody:  ollamaLegacyRequest,
			respBody: `{"embedding":[0.0100353705,-0.00177`,
		},
		{
			name:     "legacy right after opening bracket",
			path:     "/api/embeddings",
			reqBody:  ollamaLegacyRequest,
			respBody: `{"embedding":[`,
		},
		{
			name:     "legacy inside first number",
			path:     "/api/embeddings",
			reqBody:  ollamaLegacyRequest,
			respBody: `{"embedding":[-`,
		},
		{
			name:     "requested dimensions survive truncation",
			path:     "/api/embed",
			reqBody:  `{"model":"all-minilm:l6-v2","input":"x","dimensions":128}`,
			respBody: `{"model":"all-minilm:l6-v2","embeddings":[[0.0100353705,-0.00177`,
			wantDims: 128,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span, ok := runOllamaSpan(t, tt.path, tt.reqBody, tt.respBody)
			require.True(t, ok)

			ai := span.GenAI.Ollama
			assert.Equal(t, request.EmbeddingOperationName, ai.OperationName)
			assert.Equal(t, ollamaEmbedModel, ai.Request.Model)
			assert.Equal(t, tt.wantDims, ai.GetEmbeddingDimensions())
			assert.False(t, isReported(span.GenAIInputTokenCount()), "prompt_eval_count follows the vectors")
		})
	}
}

func TestOllamaSpan_ShapeCheckOnlyAppliesToEmbeddings(t *testing.T) {
	span, ok := runOllamaSpan(t, "/api/chat", ollamaChatRequest, `{"model":"llama3.2","done":true}`)
	require.True(t, ok)
	assert.Equal(t, request.ChatOperationName, span.GenAI.Ollama.OperationName)
}

// --- Helpers ---

func runOllamaSpan(t *testing.T, path, reqBody, respBody string) (request.Span, bool) {
	t.Helper()
	return runOllamaSpanRaw(t, path, reqBody, respBody)
}

func runOllamaSpanRaw(t *testing.T, path, reqBody, respBody string) (request.Span, bool) {
	t.Helper()

	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: path},
		Body:   io.NopCloser(strings.NewReader(reqBody)),
		Header: http.Header{"Content-Type": []string{"application/json"}},
	}

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(respBody)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}

	baseSpan := &request.Span{
		Type:   request.EventTypeHTTPClient,
		Method: http.MethodPost,
		Path:   path,
	}

	return OllamaSpan(baseSpan, req, resp)
}
