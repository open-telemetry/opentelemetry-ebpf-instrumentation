// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// payloads match those served by internal/test/integration/components/ai/openai/mock-server/main.go

const responsesRequestBody = `{"input":"How do I check if a Python object is an instance of a class?","instructions":"You are a coding assistant that talks like a pirate.","model":"gpt-5-mini"}`

const responsesResponseBody = `{
  "id": "resp_09687a288637e2be006998ad7af05481a2bb0938f77da5a9db",
  "object": "response",
  "created_at": 1771613562,
  "status": "completed",
  "error": null,
  "frequency_penalty": 0.0,
  "instructions": "You are a coding assistant that talks like a pirate.",
  "model": "gpt-5-mini-2025-08-07",
  "output": [
    {
      "id": "msg_09687a288637e2be006998ad810cc881a2b84e1ea5a5decd75",
      "type": "message",
      "status": "completed",
      "content": [{"type":"output_text","text":"Arrr! To check if an object be an instance of a class in Python, use isinstance."}],
      "role": "assistant"
    }
  ],
  "temperature": 1.0,
  "top_p": 1.0,
  "usage": {
    "input_tokens": 36,
    "output_tokens": 691,
    "total_tokens": 727
  }
}`

const completionsRequestBody = `{"messages":[{"role":"system","content":"You are a helpful travel assistant."},{"role":"user","content":"Plan a 6-day luxury trip to London for 3 people with a $4400 budget."}],"model":"gpt-4o-mini","temperature":1.0}`

const completionsResponseBody = `{
  "id": "chatcmpl-DBTg5Ms2mJhaAhZ56Wq8QSf2djw3S",
  "object": "chat.completion",
  "created": 1771628061,
  "model": "gpt-4o-mini-2024-07-18",
  "choices": [
    {
      "index": 0,
      "message": {"role":"assistant","content":"I now can give a great answer"},
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 396,
    "completion_tokens": 816,
    "total_tokens": 1212
  },
  "service_tier": "default"
}`

const quotaErrorResponseBody = `{
    "error": {
        "message": "You exceeded your current quota, please check your plan and billing details.",
        "type": "insufficient_quota",
        "param": null,
        "code": "insufficient_quota"
    }
}`

func gzipBody(t *testing.T, body string) io.ReadCloser {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err := gz.Write([]byte(body))
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	return io.NopCloser(&buf)
}

//nolint:unparam
func makeRequest(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func openAIHeaders() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Content-Encoding", "gzip")
	h.Set("Openai-Version", "2020-10-01")
	h.Set("Openai-Organization", "user-kunmtqznir9mbekxyegxrwo8")
	h.Set("Openai-Project", "proj_HKghDmlTiTtE4xukGeSiuu2s")
	h.Set("Openai-Processing-Ms", "9377")
	return h
}

func makeGzipResponse(t *testing.T, statusCode int, headers http.Header, body string) *http.Response {
	t.Helper()
	return &http.Response{
		StatusCode: statusCode,
		Header:     headers,
		Body:       gzipBody(t, body),
	}
}

func makePlainResponse(statusCode int, headers http.Header, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Header:     headers,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestOpenAISpan_Responses(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://api.openai.com/v1/responses", responsesRequestBody)
	resp := makeGzipResponse(t, http.StatusOK, openAIHeaders(), responsesResponseBody)

	base := &request.Span{}
	span, ok := OpenAISpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.OpenAI)
	assert.Equal(t, request.HTTPSubtypeOpenAI, span.SubType)

	ai := span.OpenAI
	assert.Equal(t, "resp_09687a288637e2be006998ad7af05481a2bb0938f77da5a9db", ai.ID)
	assert.Equal(t, "response", ai.OperationName)
	assert.Equal(t, "gpt-5-mini-2025-08-07", ai.ResponseModel)
	assert.Equal(t, 36, ai.Usage.GetInputTokens())
	assert.Equal(t, 691, ai.Usage.GetOutputTokens())
	assert.InEpsilon(t, 1.0, 0.01, ai.Temperature)
	assert.InEpsilon(t, 1.0, 0.01, ai.TopP)
	assert.NotEmpty(t, ai.Output)

	// request fields
	assert.Equal(t, "How do I check if a Python object is an instance of a class?", ai.Request.Input)
	assert.Equal(t, "You are a coding assistant that talks like a pirate.", ai.Request.Instructions)
	assert.Equal(t, "gpt-5-mini", ai.Request.Model)
}

func TestOpenAISpan_ChatCompletions(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://api.openai.com/v1/chat/completions", completionsRequestBody)
	resp := makeGzipResponse(t, http.StatusOK, openAIHeaders(), completionsResponseBody)

	base := &request.Span{}
	span, ok := OpenAISpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.OpenAI)

	ai := span.OpenAI
	assert.Equal(t, "chatcmpl-DBTg5Ms2mJhaAhZ56Wq8QSf2djw3S", ai.ID)
	assert.Equal(t, "chat.completion", ai.OperationName)
	assert.Equal(t, "gpt-4o-mini-2024-07-18", ai.ResponseModel)
	assert.Equal(t, 396, ai.Usage.GetInputTokens())
	assert.Equal(t, 816, ai.Usage.GetOutputTokens())
	assert.NotEmpty(t, ai.Choices)

	// request fields
	assert.Equal(t, "gpt-4o-mini", ai.Request.Model)
	assert.NotEmpty(t, ai.Request.Messages)
}

func TestOpenAISpan_ErrorResponse(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Openai-Version", "2020-10-01")
	// error responses are plain JSON (no gzip)
	resp := makePlainResponse(http.StatusTooManyRequests, h, quotaErrorResponseBody)

	req := makeRequest(t, http.MethodPost, "http://api.openai.com/v1/responses", responsesRequestBody)
	base := &request.Span{}
	span, ok := OpenAISpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.OpenAI)

	ai := span.OpenAI
	assert.Equal(t, "insufficient_quota", ai.Error.Type)
	assert.NotEmpty(t, ai.Error.Message)
}

func TestOpenAISpan_NotOpenAI(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://example.com/api", `{"query":"hello"}`)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, `{"result":"ok"}`)

	base := &request.Span{}
	_, ok := OpenAISpan(base, req, resp)

	assert.False(t, ok, "should not be detected as OpenAI when no OpenAI headers are present")
}

func TestOpenAISpan_OnlyOneOpenAIHeaderSuffices(t *testing.T) {
	for _, header := range []string{"Openai-Version", "Openai-Organization", "Openai-Project", "Openai-Processing-Ms"} {
		t.Run(header, func(t *testing.T) {
			h := http.Header{}
			h.Set("Content-Type", "application/json")
			h.Set(header, "some-value")
			resp := makePlainResponse(http.StatusOK, h, responsesResponseBody)
			req := makeRequest(t, http.MethodPost, "http://api.openai.com/v1/responses", responsesRequestBody)

			base := &request.Span{}
			_, ok := OpenAISpan(base, req, resp)
			assert.True(t, ok, "header %q alone should be enough to identify an OpenAI response", header)
		})
	}
}

func TestOpenAISpan_MalformedResponseBody(t *testing.T) {
	h := openAIHeaders()
	h.Del("Content-Encoding") // plain, but invalid JSON
	resp := makePlainResponse(http.StatusOK, h, `not-json`)

	req := makeRequest(t, http.MethodPost, "http://api.openai.com/v1/responses", responsesRequestBody)
	base := &request.Span{}
	span, ok := OpenAISpan(base, req, resp)

	// Still detected as OpenAI (headers present), span returned even if JSON is junk
	assert.True(t, ok)
	assert.NotNil(t, span.OpenAI)
	// but no meaningful fields are populated
	assert.Empty(t, span.OpenAI.ID)
}

func TestOpenAISpan_UsageTokenHelpers(t *testing.T) {
	// /v1/responses uses input_tokens / output_tokens
	u := request.OpenAIUsage{InputTokens: 10, OutputTokens: 20, TotalTokens: 30}
	assert.Equal(t, 10, u.GetInputTokens())
	assert.Equal(t, 20, u.GetOutputTokens())

	// /v1/chat/completions uses prompt_tokens / completion_tokens
	u2 := request.OpenAIUsage{PromptTokens: 5, CompletionTokens: 15}
	assert.Equal(t, 5, u2.GetInputTokens())
	assert.Equal(t, 15, u2.GetOutputTokens())
}

func TestOpenAISpan_GetOutput(t *testing.T) {
	// output field populated (responses API)
	ai := &request.OpenAI{Output: []byte(`[{"type":"message"}]`)}
	assert.JSONEq(t, `[{"type":"message"}]`, ai.GetOutput())

	// items fallback
	ai2 := &request.OpenAI{Items: []byte(`[{"item":1}]`)}
	assert.JSONEq(t, `[{"item":1}]`, ai2.GetOutput())

	// data fallback
	ai3 := &request.OpenAI{Data: []byte(`[{"id":"emb-1"}]`)}
	assert.JSONEq(t, `[{"id":"emb-1"}]`, ai3.GetOutput())

	// choices fallback (completions API)
	ai4 := &request.OpenAI{Choices: []byte(`[{"index":0}]`)}
	assert.JSONEq(t, `[{"index":0}]`, ai4.GetOutput())
}

func TestOpenAIInput_GetInput(t *testing.T) {
	// direct input string
	inp := &request.OpenAIInput{Input: "hello"}
	assert.Equal(t, "hello", inp.GetInput())

	// prompt fallback (completions v1)
	inp2 := &request.OpenAIInput{Prompt: "pirate prompt"}
	assert.Equal(t, "pirate prompt", inp2.GetInput())

	// messages fallback
	inp3 := &request.OpenAIInput{Messages: []byte(`[{"role":"user"}]`)}
	assert.JSONEq(t, `[{"role":"user"}]`, inp3.GetInput())

	// items fallback
	inp4 := &request.OpenAIInput{Items: []byte(`[{"item":1}]`)}
	assert.JSONEq(t, `[{"item":1}]`, inp4.GetInput())
}
