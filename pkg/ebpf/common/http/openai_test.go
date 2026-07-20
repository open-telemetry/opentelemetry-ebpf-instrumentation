// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
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
	require.NotNil(t, span.GenAI.OpenAI)
	assert.Equal(t, request.HTTPSubtypeOpenAI, span.SubType)

	ai := span.GenAI.OpenAI
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
	require.NotNil(t, span.GenAI.OpenAI)

	ai := span.GenAI.OpenAI
	assert.Equal(t, "chatcmpl-DBTg5Ms2mJhaAhZ56Wq8QSf2djw3S", ai.ID)
	assert.Equal(t, "chat", ai.OperationName)
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
	require.NotNil(t, span.GenAI.OpenAI)

	ai := span.GenAI.OpenAI
	assert.Equal(t, "insufficient_quota", ai.Error.Type)
	assert.NotEmpty(t, ai.Error.Message)

	// The error body carries no `object` field, so the operation name must be
	// derived from the request path: gen_ai.operation.name is required on the
	// gen_ai client metrics, so failed calls must carry it too.
	assert.Equal(t, request.ResponseOperationName, ai.OperationName)
	assert.Equal(t, "responses", ai.APIType)
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
	assert.NotNil(t, span.GenAI.OpenAI)
	// but no meaningful fields are populated
	assert.Empty(t, span.GenAI.OpenAI.ID)
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

func TestOpenAISpan_PartialRequestBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://api.openai.com/v1/chat/completions", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(completionsRequestBody))

	truncated := completionsRequestBody[:len(completionsRequestBody)-len(`,"temperature":1.0}`)]
	req.Body = &partialReadCloser{
		data: []byte(truncated),
		err:  io.ErrUnexpectedEOF,
	}

	resp := makeGzipResponse(t, http.StatusOK, openAIHeaders(), completionsResponseBody)
	base := &request.Span{ContentLength: int64(len(completionsRequestBody))}
	span, ok := OpenAISpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.OpenAI)
	assert.Equal(t, "gpt-4o-mini", span.GenAI.OpenAI.Request.Model)
	assert.Equal(t, "chatcmpl-DBTg5Ms2mJhaAhZ56Wq8QSf2djw3S", span.GenAI.OpenAI.ID)
}

func TestOpenAISpan_PartialResponseBody(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://api.openai.com/v1/chat/completions", completionsRequestBody)

	truncated := completionsResponseBody[:300]
	h := openAIHeaders()
	h.Del("Content-Encoding")
	resp := makePlainResponse(http.StatusOK, h, truncated)

	base := &request.Span{}
	span, ok := OpenAISpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.OpenAI)
	assert.Equal(t, "chatcmpl-DBTg5Ms2mJhaAhZ56Wq8QSf2djw3S", span.GenAI.OpenAI.ID)
	assert.Equal(t, request.ChatOperationName, span.GenAI.OpenAI.OperationName)
	assert.Equal(t, "gpt-4o-mini-2024-07-18", span.GenAI.OpenAI.ResponseModel)
	assert.Equal(t, 0, span.GenAI.OpenAI.Usage.GetInputTokens())
}

func TestOpenAISpan_GetOutput(t *testing.T) {
	// output field populated (responses API) - normalized to semconv schema
	ai := &request.VendorOpenAI{Output: []byte(`[{"type":"message","status":"completed","content":[{"type":"output_text","text":"Arrr!"}],"role":"assistant"}]`)}
	assert.JSONEq(t, `[{"role":"assistant","parts":[{"type":"text","content":"Arrr!"}],"finish_reason":"completed"}]`, ai.GetOutput())

	// items fallback
	ai2 := &request.VendorOpenAI{Items: []byte(`[{"item":1}]`)}
	assert.JSONEq(t, `[{"item":1}]`, ai2.GetOutput())

	// data fallback
	ai3 := &request.VendorOpenAI{Data: []byte(`[{"id":"emb-1"}]`)}
	assert.JSONEq(t, `[{"id":"emb-1"}]`, ai3.GetOutput())

	// choices fallback (completions API) - normalized to semconv schema
	ai4 := &request.VendorOpenAI{Choices: []byte(`[{"index":0,"message":{"role":"assistant","content":"test"},"finish_reason":"stop"}]`)}
	assert.JSONEq(t, `[{"role":"assistant","parts":[{"type":"text","content":"test"}],"finish_reason":"stop"}]`, ai4.GetOutput())
}

func TestOpenAIInput_GetInput(t *testing.T) {
	// direct input string - wrapped as input message
	inp := &request.OpenAIInput{Input: "hello"}
	assert.JSONEq(t, `[{"role":"user","parts":[{"type":"text","content":"hello"}]}]`, inp.GetInput())

	// prompt fallback (completions v1) - wrapped as input message
	inp2 := &request.OpenAIInput{Prompt: "pirate prompt"}
	assert.JSONEq(t, `[{"role":"user","parts":[{"type":"text","content":"pirate prompt"}]}]`, inp2.GetInput())

	// messages fallback - normalized to semconv schema (null parts when no content)
	inp3 := &request.OpenAIInput{Messages: []byte(`[{"role":"user"}]`)}
	assert.JSONEq(t, `[{"role":"user","parts":null}]`, inp3.GetInput())

	// items fallback
	inp4 := &request.OpenAIInput{Items: []byte(`[{"item":1}]`)}
	assert.JSONEq(t, `[{"item":1}]`, inp4.GetInput())
}

const embeddingsRequestBody = `{"input":"The food was delicious","model":"text-embedding-3-small","dimensions":256}`

const embeddingsResponseBody = `{
  "object": "list",
  "data": [
    {
      "object": "embedding",
      "embedding": [0.0023064255, -0.009327292],
      "index": 0
    }
  ],
  "model": "text-embedding-3-small",
  "usage": {
    "prompt_tokens": 5,
    "total_tokens": 5
  }
}`

func TestOpenAIToolCalls(t *testing.T) {
	t.Run("single tool call", func(t *testing.T) {
		choices := json.RawMessage(`[{"message":{"tool_calls":[{"id":"call_1","type":"function","function":{"name":"get_weather"}}]},"finish_reason":"tool_calls"}]`)
		result := extractToolCalls(choices)
		require.Len(t, result, 1)
		assert.Equal(t, "call_1", result[0].ID)
		assert.Equal(t, "get_weather", result[0].Name)
	})

	t.Run("multiple tool calls", func(t *testing.T) {
		choices := json.RawMessage(`[{"message":{"tool_calls":[{"id":"call_1","type":"function","function":{"name":"get_weather"}},{"id":"call_2","type":"function","function":{"name":"get_time"}}]},"finish_reason":"tool_calls"}]`)
		result := extractToolCalls(choices)
		require.Len(t, result, 2)
		assert.Equal(t, "call_1", result[0].ID)
		assert.Equal(t, "get_weather", result[0].Name)
		assert.Equal(t, "call_2", result[1].ID)
		assert.Equal(t, "get_time", result[1].Name)
	})

	t.Run("no tool calls", func(t *testing.T) {
		choices := json.RawMessage(`[{"message":{"content":"Hello"},"finish_reason":"stop"}]`)
		result := extractToolCalls(choices)
		assert.Empty(t, result)
	})

	t.Run("empty or nil choices", func(t *testing.T) {
		assert.Nil(t, extractToolCalls(nil))
		assert.Nil(t, extractToolCalls(json.RawMessage{}))
	})
}

func TestOpenAISpan_Embeddings(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://api.openai.com/v1/embeddings", embeddingsRequestBody)
	resp := makeGzipResponse(t, http.StatusOK, openAIHeaders(), embeddingsResponseBody)

	base := &request.Span{}
	span, ok := OpenAISpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.OpenAI)
	assert.Equal(t, request.HTTPSubtypeOpenAI, span.SubType)

	ai := span.GenAI.OpenAI
	assert.Equal(t, "embeddings", ai.OperationName)
	assert.Equal(t, "text-embedding-3-small", ai.ResponseModel)
	assert.Equal(t, 5, ai.Usage.GetInputTokens())

	// request fields
	assert.Equal(t, "text-embedding-3-small", ai.Request.Model)
	assert.Equal(t, 256, ai.Request.Dimensions)
	assert.Equal(t, "The food was delicious", ai.Request.Input) // raw field
	assert.JSONEq(t, `[{"role":"user","parts":[{"type":"text","content":"The food was delicious"}]}]`, ai.Request.GetInput())
}
