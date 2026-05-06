// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bufio"
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
	assert.Equal(t, "chat.completion", ai.OperationName)
	assert.Equal(t, "qwen-plus", ai.Request.Model)
	assert.Equal(t, "qwen-plus", ai.ResponseModel)
	assert.Equal(t, 11, ai.Usage.GetInputTokens())
	assert.Equal(t, 9, ai.Usage.GetOutputTokens())
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
	assert.Equal(t, 12, ai.Usage.GetInputTokens())
	assert.Equal(t, 10, ai.Usage.GetOutputTokens())
	assert.JSONEq(t, `{"text":"eBPF is a kernel programmability technology.","finish_reason":"stop"}`, ai.GetOutput())
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
	assert.Equal(t, "chat.completion", span.GenAI.Qwen.OperationName)
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

func TestExtractQwenOperation(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "chat completions",
			url:  "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
			want: "chat.completion",
		},
		{
			name: "completions",
			url:  "https://dashscope.aliyuncs.com/compatible-mode/v1/completions",
			want: "completion",
		},
		{
			name: "embeddings",
			url:  "https://dashscope.aliyuncs.com/compatible-mode/v1/embeddings",
			want: "embedding",
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
