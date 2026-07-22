// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestGenAIHTTP2BodyHeuristics(t *testing.T) {
	openAIChatReq := []byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`)
	openAIChatResp := []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0}],"usage":{"prompt_tokens":1}}`)
	openAIRespReq := []byte(`{"model":"gpt-5-mini","input":"hi","instructions":"be terse"}`)
	openAIEmbedReq := []byte(`{"model":"text-embedding-3-small","input":"Your text string goes here","encoding_format":"float"}`)
	openAIEmbedResp := []byte(`{"object":"list","model":"text-embedding-3-small","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2]}],"usage":{"prompt_tokens":5,"total_tokens":5}}`)
	// OpenAI-compatible shape but a non-"gpt" model: OpenAI is no longer a
	// catch-all, so these must not be claimed.
	unknownModelReq := []byte(`{"model":"mistral-large","messages":[]}`)
	unknownModelResp := []byte(`{"object":"chat.completion","model":"mistral-large","choices":[]}`)

	qwenReq := []byte(`{"model":"qwen-plus","messages":[{"role":"user","content":"hi"}]}`)
	qwenReqIDResp := []byte(`{"output":{},"request_id":"abc"}`)

	anthropicReq := []byte(`{"model":"claude-3-5-sonnet","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}`)
	anthropicResp := []byte(`{"id":"msg_1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":2}}`)
	anthropicStream := []byte("event: message_start\ndata: {\"type\":\"message_start\"}\n\n")

	bedrockReq := []byte(`{"anthropic_version":"bedrock-2023-05-31","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}`)

	geminiReq := []byte(`{"modelVersion":"gemini-2.0-flash","contents":[{"role":"user","parts":[{"text":"hi"}]}]}`)
	geminiReqNoModel := []byte(`{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`)
	geminiRespNoModel := []byte(`{"candidates":[{"content":{"parts":[]}}],"usageMetadata":{"promptTokenCount":1}}`)

	t.Run("openai", func(t *testing.T) {
		assert.True(t, looksLikeOpenAIBody(openAIChatReq, openAIChatResp, "/v1/responses"), "gpt model in request")
		assert.True(t, looksLikeOpenAIBody(openAIRespReq, nil, "/v1/responses"), "gpt model, responses API request only")
		assert.True(t, looksLikeOpenAIBody(nil, openAIChatResp, "/v1/responses"), "gpt model taken from response")
		assert.True(t, looksLikeOpenAIBody(openAIEmbedReq, nil, "/v1/embeddings"), "text-embedding model in request")
		assert.True(t, looksLikeOpenAIBody(nil, openAIEmbedResp, "/v1/embeddings"), "text-embedding model taken from response")
		// Non-gpt models are left for their own providers / not claimed.
		assert.False(t, looksLikeOpenAIBody(qwenReq, nil, "/v1/responses"), "qwen model must not be claimed by openai")
		assert.False(t, looksLikeOpenAIBody(anthropicReq, anthropicResp, "/v1/responses"), "claude model must not be claimed by openai")
		assert.False(t, looksLikeOpenAIBody(unknownModelReq, unknownModelResp, "/v1/responses"), "unknown model is not a catch-all match")
		assert.False(t, looksLikeOpenAIBody(nil, nil, "/v1/responses"))
		assert.False(t, looksLikeOpenAIBody(openAIEmbedReq, nil, "/v1/responses"), "text-embedding model in request but not embeddings call")
	})

	t.Run("qwen", func(t *testing.T) {
		assert.True(t, looksLikeQwenBody(qwenReq, nil), "qwen model in request")
		assert.True(t, looksLikeQwenBody(nil, qwenReqIDResp), "DashScope request_id in response")
		assert.False(t, looksLikeQwenBody(openAIChatReq, openAIChatResp))
	})

	t.Run("anthropic", func(t *testing.T) {
		assert.True(t, looksLikeAnthropicBody(anthropicReq, anthropicResp), "claude model + messages")
		assert.True(t, looksLikeAnthropicBody(nil, anthropicResp), "message-type response")
		assert.True(t, looksLikeAnthropicBody(nil, anthropicStream), "SSE stream")
		// Yields to Bedrock: same message shape but anthropic_version in the body.
		assert.False(t, looksLikeAnthropicBody(bedrockReq, anthropicResp), "bedrock body must not be claimed by anthropic")
		assert.False(t, looksLikeAnthropicBody(openAIChatReq, openAIChatResp))
	})

	t.Run("bedrock", func(t *testing.T) {
		assert.True(t, looksLikeBedrockBody(bedrockReq), "anthropic_version=bedrock-* marker")
		assert.False(t, looksLikeBedrockBody(anthropicReq), "direct Anthropic has no anthropic_version body field")
		assert.False(t, looksLikeBedrockBody(openAIChatReq))
	})

	t.Run("gemini", func(t *testing.T) {
		const geminiPath = "/v1beta/models/gemini-2.0-flash:generateContent"
		assert.True(t, looksLikeGeminiBody(geminiReq, nil, ""), "gemini model in request body")
		// A real generateContent body omits the model (it lives in the URL), so
		// the path supplies it.
		assert.True(t, looksLikeGeminiBody(geminiReqNoModel, geminiRespNoModel, geminiPath), "gemini model taken from URL path")
		assert.False(t, looksLikeGeminiBody(geminiReqNoModel, geminiRespNoModel, ""), "no model in body or path is not matched")
		assert.False(t, looksLikeGeminiBody(openAIChatReq, openAIChatResp, "/v1/chat/completions"))
	})
}

// TestGenAIHTTP2Gate confirms the body fallback fires only for HTTP/2 requests
// (ProtoMajor 2) whose path matches the provider, and never for HTTP/1.1.
func TestGenAIHTTP2Gate(t *testing.T) {
	openAIReq := []byte(`{"model":"gpt-4o-mini","messages":[]}`)
	openAIResp := []byte(`{"object":"chat.completion","model":"gpt-4o-mini","choices":[]}`)

	newReq := func(proto int) *http.Request {
		return &http.Request{
			ProtoMajor: proto,
			Header:     http.Header{},
			Body:       io.NopCloser(bytes.NewReader(openAIReq)),
			URL:        &url.URL{Path: "/v1/chat/completions"},
		}
	}
	newResp := func() *http.Response {
		return &http.Response{Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(openAIResp))}
	}
	// The OpenAI HTTP/2 fallback is gated on baseSpan.Path containing "/v1/".
	baseSpan := func() *request.Span { return &request.Span{Path: "/v1/chat/completions"} }

	// HTTP/1.1: heuristic gated off regardless of body -> not detected.
	_, ok := OpenAISpan(baseSpan(), newReq(1), newResp())
	assert.False(t, ok, "HTTP/1.1 must not trigger the body fallback")

	// HTTP/2 with a matching path and gpt model -> detected.
	span, ok := OpenAISpan(baseSpan(), newReq(2), newResp())
	assert.True(t, ok, "HTTP/2 OpenAI gpt-model body should be detected")
	assert.Equal(t, request.HTTPSubtypeOpenAI, span.SubType)
}
