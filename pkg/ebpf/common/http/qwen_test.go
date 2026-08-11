// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const qwenCompatibleRequestBody = `{
  "model":"qwen-plus",
  "messages":[
    {"role":"system","content":"You are a helpful assistant."},
    {"role":"user","content":"Explain eBPF in one sentence."}
  ],
  "temperature":0.7
}`

const qwenCompatibleResponseBody = `{
  "id":"chatcmpl-123",
  "object":"chat.completion",
  "model":"qwen-plus",
  "choices":[{"index":0,"message":{"role":"assistant","content":"eBPF runs safe programs in the Linux kernel."},"finish_reason":"stop"}],
  "usage":{"prompt_tokens":11,"completion_tokens":9,"total_tokens":20}
}`

const qwenGenerationRequestBody = `{
  "model":"qwen-turbo",
  "prompt":"What is eBPF?"
}`

const qwenGenerationResponseBody = `{
  "request_id":"req-123",
  "output":{"text":"eBPF is a kernel programmability technology.","finish_reason":"stop"},
  "usage":{"input_tokens":12,"output_tokens":10,"total_tokens":22}
}`

func qwenHeaders() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-DashScope-Request-Id", "req-header")
	return h
}

type partialReadCloser struct {
	data []byte
	err  error
	read bool
}

func (p *partialReadCloser) Read(dst []byte) (int, error) {
	if p.read {
		return 0, io.EOF
	}
	p.read = true
	n := copy(dst, p.data)
	return n, p.err
}

func (p *partialReadCloser) Close() error {
	return nil
}

func TestQwenSpan_CompatibleMode(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions", qwenCompatibleRequestBody)
	resp := makePlainResponse(http.StatusOK, qwenHeaders(), qwenCompatibleResponseBody)

	base := &request.Span{}
	span, ok := QwenSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Qwen)
	assert.Equal(t, request.HTTPSubtypeQwen, span.SubType)

	ai := span.GenAI.Qwen
	assert.Equal(t, "chatcmpl-123", ai.ID)
	assert.Equal(t, "chat", ai.OperationName)
	assert.Equal(t, "qwen-plus", ai.Request.Model)
	assert.Equal(t, "qwen-plus", ai.ResponseModel)
	assert.Equal(t, 11, reportedValue(ai.Usage.InputTokenCount()))
	assert.Equal(t, 9, reportedValue(ai.Usage.OutputTokenCount()))
	assert.NotEmpty(t, ai.GetOutput())
}

func TestQwenSpan_DashScopeGeneration(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation", qwenGenerationRequestBody)
	resp := makePlainResponse(http.StatusOK, qwenHeaders(), qwenGenerationResponseBody)

	base := &request.Span{}
	span, ok := QwenSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Qwen)

	ai := span.GenAI.Qwen
	assert.Equal(t, "req-123", ai.ID)
	assert.Equal(t, "generation", ai.OperationName)
	assert.Equal(t, "qwen-turbo", ai.Request.Model)
	assert.Equal(t, "qwen-turbo", ai.ResponseModel)
	assert.Equal(t, 12, reportedValue(ai.Usage.InputTokenCount()))
	assert.Equal(t, 10, reportedValue(ai.Usage.OutputTokenCount()))
	assert.JSONEq(t, `{"text":"eBPF is a kernel programmability technology.","finish_reason":"stop"}`, ai.GetOutput())
}

// Native DashScope text-embedding bodies: input under input.texts, dimension
// under parameters.dimension, vectors under output.embeddings[].embedding.
const dashScopeEmbeddingRequestBody = `{
  "model":"text-embedding-v2",
  "input":{"texts":["Hello world","Goodbye world"]},
  "parameters":{"dimension":1024,"output_type":"dense","text_type":"query"}
}`

const dashScopeEmbeddingResponseBody = `{
  "output":{"embeddings":[
    {"embedding":[0.1,0.2,0.3],"text_index":0},
    {"embedding":[0.4,0.5,0.6],"text_index":1}
  ]},
  "usage":{"total_tokens":8},
  "request_id":"req-emb-1"
}`

func TestQwenSpan_DashScopeNativeEmbedding(t *testing.T) {
	req := makeRequest(t, http.MethodPost,
		"https://dashscope.aliyuncs.com/api/v1/services/embeddings/text-embedding/text-embedding",
		dashScopeEmbeddingRequestBody)
	resp := makePlainResponse(http.StatusOK, qwenHeaders(), dashScopeEmbeddingResponseBody)

	base := &request.Span{}
	span, ok := QwenSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Qwen)

	ai := span.GenAI.Qwen
	assert.Equal(t, "embeddings", ai.OperationName)
	assert.Equal(t, "text-embedding-v2", ai.Request.Model)
	// Requested dimension comes from parameters.dimension (takes precedence).
	assert.Equal(t, 1024, ai.GetEmbeddingDimensions())
	// input_tokens falls back to total_tokens for embeddings.
	assert.Equal(t, 8, reportedValue(span.GenAIInputTokenCount()))
	assert.True(t, isReported(span.GenAIInputTokenCount()))
}

func TestQwenSpan_DashScopeNativeEmbedding_DimensionFromResponse(t *testing.T) {
	// No parameters.dimension in the request: dimension is derived from the
	// response output.embeddings[0].embedding vector length.
	reqBody := `{"model":"text-embedding-v2","input":{"texts":["hi"]}}`
	req := makeRequest(t, http.MethodPost,
		"https://dashscope.aliyuncs.com/api/v1/services/embeddings/text-embedding/text-embedding",
		reqBody)
	resp := makePlainResponse(http.StatusOK, qwenHeaders(), dashScopeEmbeddingResponseBody)

	base := &request.Span{}
	span, ok := QwenSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.Qwen)
	assert.Equal(t, 3, span.GenAI.Qwen.GetEmbeddingDimensions())
}

func TestQwenSpan_CompatibleModeBase64Embedding(t *testing.T) {
	// OpenAI SDKs default to encoding_format=base64: data[].embedding is a
	// base64 string of packed float32 values (1024 dims = 4096 bytes).
	vec := base64.StdEncoding.EncodeToString(make([]byte, 1024*4))
	respBody := fmt.Sprintf(
		`{"data":[{"embedding":"%s","index":0,"object":"embedding"}],"model":"text-embedding-v3","usage":{"prompt_tokens":6,"total_tokens":6},"id":"eb4ea05e-18c5-9554-9234-78a1528e7be3"}`,
		vec)
	reqBody := `{"model":"text-embedding-v3","input":["hello"],"encoding_format":"base64"}`

	req := makeRequest(t, http.MethodPost, "https://dashscope.aliyuncs.com/compatible-mode/v1/embeddings", reqBody)
	resp := makePlainResponse(http.StatusOK, qwenHeaders(), respBody)

	base := &request.Span{}
	span, ok := QwenSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.Qwen)
	ai := span.GenAI.Qwen
	assert.Equal(t, "embeddings", ai.OperationName)
	// Dimension resolved from the base64-decoded vector: 4096 bytes / 4 = 1024.
	assert.Equal(t, 1024, ai.GetEmbeddingDimensions())
	assert.Equal(t, "base64", ai.Request.EncodingFormat)
	assert.Equal(t, 6, reportedValue(span.GenAIInputTokenCount()))
}

func TestQwenSpan_IDFallbackFromHeadersWhenBodyMissingID(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions", qwenCompatibleRequestBody)
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-DashScope-Request-Id", "chatcmpl-from-header")
	resp := makePlainResponse(http.StatusOK, h, `{"choices":[]}`)

	base := &request.Span{}
	span, ok := QwenSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Qwen)
	assert.Equal(t, "chatcmpl-from-header", span.GenAI.Qwen.ID)
}

func TestQwenSpan_UsesPartialRequestBodyWhenReadFails(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Body = &partialReadCloser{
		data: []byte(`{"model":"qwen-plus","messages":[{"role":"user","content":"hi"}]`),
		err:  io.ErrUnexpectedEOF,
	}

	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-DashScope-Request-Id", "chatcmpl-from-header")
	resp := makePlainResponse(http.StatusOK, h, `{"choices":[]}`)

	base := &request.Span{}
	span, ok := QwenSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Qwen)
	assert.Equal(t, "chatcmpl-from-header", span.GenAI.Qwen.ID)
	assert.Equal(t, "qwen-plus", span.GenAI.Qwen.Request.Model)
}

func TestQwenSpan_CompatibleModeRealResponseHeaders(t *testing.T) {
	contentLength := strconv.Itoa(len(qwenCompatibleRequestBody))
	rawReq := "POST /compatible-mode/v1/chat/completions HTTP/1.1\r\n" +
		"Host: dashscope.aliyuncs.com\r\n" +
		"Content-Type: application/json\r\n" +
		"Authorization: Bearer test-token\r\n" +
		"Content-Length: " + contentLength + "\r\n" +
		"\r\n" +
		qwenCompatibleRequestBody
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawReq)))
	require.NoError(t, err)

	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type":             []string{"application/json"},
		"X-Request-Id":             []string{"a1ad370d-b4b0-90bb-9a87-a131fd0687d6"},
		"X-Dashscope-Call-Gateway": []string{"true"},
	}, qwenCompatibleResponseBody)

	base := &request.Span{}
	span, ok := QwenSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Qwen)
	assert.Equal(t, request.HTTPSubtypeQwen, span.SubType)
	assert.Equal(t, "chat", span.GenAI.Qwen.OperationName)
	assert.Equal(t, "qwen-plus", span.GenAI.Qwen.Request.Model)
}

func TestQwenSpan_NotQwen(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "https://api.openai.com/v1/chat/completions", qwenCompatibleRequestBody)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, qwenCompatibleResponseBody)

	base := &request.Span{}
	_, ok := QwenSpan(base, req, resp)

	assert.False(t, ok)
}

const qwenToolCallRequestBody = `{
  "model":"qwen-plus",
  "messages":[{"role":"user","content":"What is the weather in Beijing?"}],
  "tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object","properties":{"location":{"type":"string"}}}}}]
}`

const qwenToolCallResponseBody = `{
  "id":"chatcmpl-tool-456",
  "object":"chat.completion",
  "model":"qwen-plus",
  "choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_abc","type":"function","function":{"name":"get_weather"}}]},"finish_reason":"tool_calls"}],
  "usage":{"prompt_tokens":20,"completion_tokens":5,"total_tokens":25}
}`

func TestQwenSpan_ToolCalls(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions", qwenToolCallRequestBody)
	resp := makePlainResponse(http.StatusOK, qwenHeaders(), qwenToolCallResponseBody)

	base := &request.Span{}
	span, ok := QwenSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Qwen)
	assert.Equal(t, request.HTTPSubtypeQwen, span.SubType)

	ai := span.GenAI.Qwen
	assert.Equal(t, "chatcmpl-tool-456", ai.ID)
	assert.Equal(t, "chat", ai.OperationName)
	assert.Equal(t, "qwen-plus", ai.Request.Model)
	require.Len(t, ai.ToolCalls, 1)
	assert.Equal(t, "call_abc", ai.ToolCalls[0].ID)
	assert.Equal(t, "get_weather", ai.ToolCalls[0].Name)
}

func TestQwenSpan_NoToolCalls(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions", qwenCompatibleRequestBody)
	resp := makePlainResponse(http.StatusOK, qwenHeaders(), qwenCompatibleResponseBody)

	base := &request.Span{}
	span, ok := QwenSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Qwen)
	assert.Empty(t, span.GenAI.Qwen.ToolCalls)
}

func TestExtractQwenOperation(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "chat completions",
			url:  "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
			want: "chat",
		},
		{
			name: "completions",
			url:  "https://dashscope.aliyuncs.com/compatible-mode/v1/completions",
			want: "text_completion",
		},
		{
			name: "embeddings",
			url:  "https://dashscope.aliyuncs.com/compatible-mode/v1/embeddings",
			want: "embeddings",
		},
		{
			name: "generation",
			url:  "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation",
			want: "generation",
		},
		{
			name: "unknown path defaults",
			url:  "https://dashscope.aliyuncs.com/api/v1/unknown",
			want: "generation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := makeRequest(t, http.MethodPost, tt.url, "{}")
			assert.Equal(t, tt.want, extractQwenOperation(req))
		})
	}
}
