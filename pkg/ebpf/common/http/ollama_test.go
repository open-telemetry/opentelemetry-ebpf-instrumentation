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
	assert.Equal(t, 26, ai.Usage.InputTokens)
	assert.Equal(t, 9, ai.Usage.OutputTokens)
	assert.Equal(t, []string{"stop"}, ai.GetFinishReasons())
	assert.False(t, ai.Request.Stream)
}

// --- Streaming /api/chat ---

const ollamaChatStreamResponse = `{"model":"llama3.2","message":{"role":"assistant","content":"Hello"},"done":false}
{"model":"llama3.2","message":{"role":"assistant","content":"!"},"done":false}
{"model":"llama3.2","message":{"role":"assistant","content":""},"done":true,"done_reason":"stop","prompt_eval_count":26,"eval_count":2}`

func TestOllamaSpan_ChatStreaming(t *testing.T) {
	reqBody := `{"model":"llama3.2","messages":[{"role":"user","content":"Hi"}],"stream":true}`
	span, ok := runOllamaSpanRaw(t, "/api/chat", reqBody, ollamaChatStreamResponse)
	require.True(t, ok)

	ai := span.GenAI.Ollama
	assert.Equal(t, "chat", ai.OperationName)
	assert.Equal(t, "llama3.2", ai.ResponseModel)
	assert.Equal(t, 26, ai.Usage.InputTokens)
	assert.Equal(t, 2, ai.Usage.OutputTokens)
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
	assert.Equal(t, 12, ai.Usage.InputTokens)
	assert.Equal(t, 15, ai.Usage.OutputTokens)
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
	assert.Equal(t, 10, ai.Usage.InputTokens)
	assert.Equal(t, 8, ai.Usage.OutputTokens)
	assert.Equal(t, []string{"stop"}, ai.GetFinishReasons())
	assert.True(t, ai.Request.Stream)
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
	assert.Equal(t, 26, span.GenAIInputTokens())
	assert.Equal(t, 9, span.GenAIOutputTokens())
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
