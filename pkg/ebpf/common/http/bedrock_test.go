// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bufio"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// Claude (Anthropic Messages API) request/response bodies as sent via Bedrock
const bedrockClaudeRequestBody = `{
  "anthropic_version": "bedrock-2023-05-31",
  "max_tokens": 1024,
  "system": "You are a helpful assistant.",
  "messages": [{"role": "user", "content": [{"type": "text", "text": "Explain eBPF briefly."}]}],
  "temperature": 0.7,
  "top_p": 0.9
}`

const bedrockClaudeResponseBody = `{
  "content": [{"type": "text", "text": "eBPF is a technology that allows running sandboxed programs in the Linux kernel."}],
  "stop_reason": "end_turn",
  "usage": {"input_tokens": 25, "output_tokens": 18}
}`

// Titan (Amazon) request/response
const bedrockTitanRequestBody = `{
  "inputText": "Explain eBPF briefly.",
  "textGenerationConfig": {"maxTokenCount": 512, "temperature": 0.7, "topP": 0.9}
}`

const bedrockTitanResponseBody = `{
  "results": [{"outputText": "eBPF is a kernel technology.", "completionReason": "FINISH"}]
}`

// Llama (Meta) request/response
const bedrockLlamaRequestBody = `{
  "prompt": "Explain eBPF briefly.",
  "max_gen_len": 512,
  "temperature": 0.7,
  "top_p": 0.9
}`

const bedrockLlamaResponseBody = `{
  "generation": "eBPF enables safe kernel-level programs.",
  "prompt_token_count": 10,
  "generation_token_count": 8,
  "stop_reason": "stop"
}`

// Error response (Bedrock ValidationException)
const bedrockErrorResponseBody = `{
  "__type": "ValidationException",
  "message": "The provided model identifier is invalid."
}`

func bedrockSuccessHeaders() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-Amzn-Requestid", "abc-123-def-456")
	h.Set("X-Amzn-Bedrock-Input-Token-Count", "25")
	h.Set("X-Amzn-Bedrock-Output-Token-Count", "18")
	return h
}

func bedrockErrorHeaders() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-Amzn-Requestid", "err-123-abc-456")
	// Note: token-count headers are absent on error responses
	return h
}

func TestBedrockSpan_Claude(t *testing.T) {
	req := makeRequest(t, http.MethodPost,
		"https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-5-sonnet-20241022-v1:0/invoke",
		bedrockClaudeRequestBody)
	resp := makePlainResponse(http.StatusOK, bedrockSuccessHeaders(), bedrockClaudeResponseBody)

	base := &request.Span{}
	span, ok := BedrockSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Bedrock)

	ai := span.GenAI.Bedrock
	assert.Equal(t, request.HTTPSubtypeAWSBedrock, span.SubType)
	assert.Equal(t, "anthropic.claude-3-5-sonnet-20241022-v1:0", ai.Model)
	assert.Equal(t, 25, ai.Output.InputTokens)
	assert.Equal(t, 18, ai.Output.OutputTokens)
	assert.Equal(t, "end_turn", ai.Output.StopReason)
	assert.NotEmpty(t, ai.GetInput())
	assert.NotEmpty(t, ai.GetOutput())
	assert.Equal(t, "You are a helpful assistant.", ai.GetSystemInstruction())
	assert.Equal(t, "end_turn", ai.GetStopReason())
}

func TestBedrockSpan_Titan(t *testing.T) {
	h := bedrockSuccessHeaders()
	h.Set("X-Amzn-Bedrock-Input-Token-Count", "8")
	h.Set("X-Amzn-Bedrock-Output-Token-Count", "6")

	req := makeRequest(t, http.MethodPost,
		"https://bedrock-runtime.us-east-1.amazonaws.com/model/amazon.titan-text-premier-v1:0/invoke",
		bedrockTitanRequestBody)
	resp := makePlainResponse(http.StatusOK, h, bedrockTitanResponseBody)

	base := &request.Span{}
	span, ok := BedrockSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.Bedrock)

	ai := span.GenAI.Bedrock
	assert.Equal(t, "amazon.titan-text-premier-v1:0", ai.Model)
	assert.Equal(t, 8, ai.Output.InputTokens)
	assert.Equal(t, 6, ai.Output.OutputTokens)
	assert.Equal(t, "Explain eBPF briefly.", ai.GetInput())
	assert.Equal(t, "eBPF is a kernel technology.", ai.GetOutput())
}

func TestBedrockSpan_Llama(t *testing.T) {
	h := bedrockSuccessHeaders()
	h.Set("X-Amzn-Bedrock-Input-Token-Count", "10")
	h.Set("X-Amzn-Bedrock-Output-Token-Count", "8")

	req := makeRequest(t, http.MethodPost,
		"https://bedrock-runtime.us-west-2.amazonaws.com/model/meta.llama3-1-70b-instruct-v1:0/invoke",
		bedrockLlamaRequestBody)
	resp := makePlainResponse(http.StatusOK, h, bedrockLlamaResponseBody)

	base := &request.Span{}
	span, ok := BedrockSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.Bedrock)

	ai := span.GenAI.Bedrock
	assert.Equal(t, "meta.llama3-1-70b-instruct-v1:0", ai.Model)
	assert.Equal(t, 10, ai.Output.InputTokens)
	assert.Equal(t, 8, ai.Output.OutputTokens)
	assert.Equal(t, "Explain eBPF briefly.", ai.GetInput())
	assert.Equal(t, "eBPF enables safe kernel-level programs.", ai.GetOutput())
}

func TestBedrockSpan_ErrorResponse(t *testing.T) {
	req := makeRequest(t, http.MethodPost,
		"https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-nonexistent/invoke",
		bedrockClaudeRequestBody)
	// Error responses include x-amzn-requestid but not token-count headers.
	// isBedrock falls back to host check.
	resp := makePlainResponse(http.StatusBadRequest, bedrockErrorHeaders(), bedrockErrorResponseBody)

	base := &request.Span{}
	span, ok := BedrockSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.Bedrock)

	ai := span.GenAI.Bedrock
	assert.Equal(t, "anthropic.claude-nonexistent", ai.Model)
	assert.Equal(t, 0, ai.Output.InputTokens)
	assert.Equal(t, 0, ai.Output.OutputTokens)
	assert.Equal(t, "ValidationException", ai.Output.ErrorType)
	assert.NotEmpty(t, ai.Output.ErrorMessage)
}

func TestBedrockSpan_NotBedrock(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "https://api.example.com/chat", `{"message":"hello"}`)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, `{"reply":"hi"}`)

	base := &request.Span{}
	_, ok := BedrockSpan(base, req, resp)

	assert.False(t, ok)
}

func TestBedrockSpan_RelativeURL(t *testing.T) {
	rawReq := "POST /model/anthropic.claude-3-5-sonnet-20241022-v1:0/invoke HTTP/1.1\r\n" +
		"Host: bedrock-runtime.us-east-1.amazonaws.com\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		bedrockClaudeRequestBody
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawReq)))
	require.NoError(t, err)

	resp := makePlainResponse(http.StatusOK, bedrockSuccessHeaders(), bedrockClaudeResponseBody)

	base := &request.Span{}
	span, ok := BedrockSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.Bedrock)
	assert.Equal(t, "anthropic.claude-3-5-sonnet-20241022-v1:0", span.GenAI.Bedrock.Model)
}

func TestExtractBedrockModel(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "standard invoke",
			url:  "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-5-sonnet-20241022-v1:0/invoke",
			want: "anthropic.claude-3-5-sonnet-20241022-v1:0",
		},
		{
			name: "invoke-with-response-stream",
			url:  "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-5-sonnet-20241022-v1:0/invoke-with-response-stream",
			want: "anthropic.claude-3-5-sonnet-20241022-v1:0",
		},
		{
			name: "titan model",
			url:  "https://bedrock-runtime.us-east-1.amazonaws.com/model/amazon.titan-text-premier-v1:0/invoke",
			want: "amazon.titan-text-premier-v1:0",
		},
		{
			name: "llama model in different region",
			url:  "https://bedrock-runtime.us-west-2.amazonaws.com/model/meta.llama3-1-70b-instruct-v1:0/invoke",
			want: "meta.llama3-1-70b-instruct-v1:0",
		},
		{
			name: "no model in path",
			url:  "https://bedrock-runtime.us-east-1.amazonaws.com/foundation-models",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := makeRequest(t, http.MethodPost, tt.url, "{}")
			assert.Equal(t, tt.want, extractBedrockModel(req))
		})
	}
}
