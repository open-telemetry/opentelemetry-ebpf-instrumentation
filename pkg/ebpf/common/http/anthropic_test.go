// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const anthropicRequestBody = `{
  "messages": [{"role":"user","content":"Explain quantum computing in simple terms"}],
  "model": "claude-sonnet-4-6",
  "max_tokens": 128,
  "stream": false,
  "system": "Be concise."
}`

const anthropicResponseBody = `{
  "model":"claude-sonnet-4-6",
  "id":"msg_01QCj5VkxPS3NQUtrt5Npjcr",
  "type":"message",
  "role":"assistant",
  "content":[{"type":"text","text":"Quantum computing uses quantum mechanical phenomena like superposition and entanglement to process information."}],
  "stop_reason":"end_turn",
  "stop_sequence":null,
  "usage":{"input_tokens":15,"output_tokens":35,"service_tier":"standard","inference_geo":"global"}
}`

const anthropicStreamingResponseBody = `event: message_start
data: {"type":"message_start","message":{"model":"claude-sonnet-4-6","id":"msg_017VX1VDFNbm2uGebyvLmHwv","type":"message","role":"assistant","content":[],"stop_reason":null,"stop_sequence":null}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: ping
data: {"type":"ping"}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"With elegant syntax and indentation true,"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"\nPython turns complex problems into something you can do."}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"input_tokens":17,"output_tokens":37}}

event: message_stop
data: {"type":"message_stop"}

`

const anthropicErrorResponseBody = `{
  "type":"error",
  "error":{"type":"authentication_error","message":"invalid x-api-key"},
  "request_id":"req_011CZLkWqu2dABS8vFB9G6Lz"
}`

func anthropicHeaders() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Content-Encoding", "gzip")
	h.Set("Anthropic-Organization-Id", "ed46523f-a4ac-48c5-9bc3-415a29c51d84")
	h.Set("Anthropic-Ratelimit-Input-Tokens-Limit", "30000")
	return h
}

func TestIsAnthropic(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    bool
	}{
		{
			name: "organization id header",
			headers: http.Header{
				"Anthropic-Organization-Id": []string{"org_123"},
			},
			want: true,
		},
		{
			name: "input tokens remaining header",
			headers: http.Header{
				"Anthropic-Ratelimit-Input-Tokens-Remaining": []string{"100"},
			},
			want: true,
		},
		{
			name: "output tokens limit header",
			headers: http.Header{
				"Anthropic-Ratelimit-Output-Tokens-Limit": []string{"8000"},
			},
			want: true,
		},
		{
			name: "input tokens limit header",
			headers: http.Header{
				"Anthropic-Ratelimit-Input-Tokens-Limit": []string{"30000"},
			},
			want: true,
		},
		{
			name: "requests limit header",
			headers: http.Header{
				"Anthropic-Ratelimit-Requests-Limit": []string{"50"},
			},
			want: true,
		},
		{
			name: "api domain in header value",
			headers: http.Header{
				"Set-Cookie": []string{"session=abc; Domain=api.anthropic.com; Path=/; HttpOnly; Secure"},
			},
			want: true,
		},
		{
			name: "non anthropic headers",
			headers: http.Header{
				"Content-Type": []string{"application/json"},
				"Server":       []string{"example"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isAnthropic(tt.headers))
		})
	}
}

func TestAnthropicSpan_JSONResponse(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://api.anthropic.com/v1/messages", anthropicRequestBody)
	resp := makeGzipResponse(t, http.StatusOK, anthropicHeaders(), anthropicResponseBody)

	base := &request.Span{}
	span, ok := AnthropicSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Anthropic)

	assert.Equal(t, request.HTTPSubtypeAnthropic, span.SubType)
	assert.Equal(t, "claude-sonnet-4-6", span.GenAI.Anthropic.Input.Model)
	assert.Equal(t, 128, span.GenAI.Anthropic.Input.MaxTokens)
	assert.False(t, span.GenAI.Anthropic.Input.Stream)
	assert.Equal(t, "Be concise.", span.GenAI.Anthropic.Input.System)
	assert.JSONEq(t, `[{"role":"user","content":"Explain quantum computing in simple terms"}]`, string(span.GenAI.Anthropic.Input.Messages))

	assert.Equal(t, "msg_01QCj5VkxPS3NQUtrt5Npjcr", span.GenAI.Anthropic.Output.ID)
	assert.Equal(t, "claude-sonnet-4-6", span.GenAI.Anthropic.Output.Model)
	assert.Equal(t, "message", span.GenAI.Anthropic.Output.Type)
	assert.Equal(t, "assistant", span.GenAI.Anthropic.Output.Role)
	assert.Equal(t, "end_turn", span.GenAI.Anthropic.Output.StopReason)
	assert.Equal(t, 15, span.GenAI.Anthropic.Output.Usage.InputTokens)
	assert.Equal(t, 35, span.GenAI.Anthropic.Output.Usage.OutputTokens)
	assert.JSONEq(t, `[{"type":"text","text":"Quantum computing uses quantum mechanical phenomena like superposition and entanglement to process information."}]`, string(span.GenAI.Anthropic.Output.Content))
}

func TestAnthropicSpan_StreamingResponse(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://api.anthropic.com/v1/messages", `{
  "messages": [{"role":"user","content":"Write a short poem about Python"}],
  "model": "claude-sonnet-4-6",
  "max_tokens": 128,
  "stream": true
}`)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type":                           []string{"text/event-stream"},
		"Anthropic-Ratelimit-Input-Tokens-Limit": []string{"30000"},
	}, anthropicStreamingResponseBody)

	base := &request.Span{}
	span, ok := AnthropicSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Anthropic)

	assert.Equal(t, request.HTTPSubtypeAnthropic, span.SubType)
	assert.True(t, span.GenAI.Anthropic.Input.Stream)
	assert.Equal(t, "claude-sonnet-4-6", span.GenAI.Anthropic.Output.Model)
	assert.Equal(t, "msg_017VX1VDFNbm2uGebyvLmHwv", span.GenAI.Anthropic.Output.ID)
	assert.Equal(t, "assistant", span.GenAI.Anthropic.Output.Role)
	assert.Equal(t, "message", span.GenAI.Anthropic.Output.Type)
	assert.Equal(t, "end_turn", span.GenAI.Anthropic.Output.StopReason)
	assert.Equal(t, 17, span.GenAI.Anthropic.Output.Usage.InputTokens)
	assert.Equal(t, 37, span.GenAI.Anthropic.Output.Usage.OutputTokens)
	assert.Equal(t, "With elegant syntax and indentation true,\nPython turns complex problems into something you can do.", string(span.GenAI.Anthropic.Output.Content))
}

func TestParseAnthropicStream_AddsInputAndOutputTokensAcrossEvents(t *testing.T) {
	stream := `event: message_start
data: {"type":"message_start","message":{"model":"claude-sonnet-4-6","id":"msg_sum","type":"message","role":"assistant","usage":{"input_tokens":11,"output_tokens":2}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"input_tokens":3,"output_tokens":5}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"input_tokens":7,"output_tokens":13}}

event: message_stop
data: {"type":"message_stop"}

`

	resp, err := parseAnthropicStream(strings.NewReader(stream))

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "msg_sum", resp.ID)
	assert.Equal(t, "claude-sonnet-4-6", resp.Model)
	assert.Equal(t, "message", resp.Type)
	assert.Equal(t, "assistant", resp.Role)
	assert.Equal(t, "end_turn", resp.StopReason)
	assert.Equal(t, 21, resp.Usage.InputTokens)
	assert.Equal(t, 20, resp.Usage.OutputTokens)
	assert.Equal(t, "hello", string(resp.Content))
}

func TestAnthropicSpan_ErrorResponseDetectedFromHeaderValue(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://api.anthropic.com/v1/messages", anthropicRequestBody)
	resp := makeGzipResponse(t, http.StatusServiceUnavailable, http.Header{
		"Content-Type":     []string{"application/json"},
		"Content-Encoding": []string{"gzip"},
		"Set-Cookie":       []string{"session=abc; Domain=api.anthropic.com; Path=/; HttpOnly; Secure"},
	}, anthropicErrorResponseBody)

	base := &request.Span{}
	span, ok := AnthropicSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Anthropic)

	assert.Equal(t, "authentication_error", span.GenAI.Anthropic.Output.Error.Type)
	assert.Equal(t, "invalid x-api-key", span.GenAI.Anthropic.Output.Error.Message)
	assert.Equal(t, "req_011CZLkWqu2dABS8vFB9G6Lz", span.GenAI.Anthropic.Output.RequestID)
}

func TestAnthropicSpan_NotAnthropic(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://example.com/api", `{"query":"hello"}`)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, `{"result":"ok"}`)

	base := &request.Span{}
	_, ok := AnthropicSpan(base, req, resp)

	assert.False(t, ok)
}
