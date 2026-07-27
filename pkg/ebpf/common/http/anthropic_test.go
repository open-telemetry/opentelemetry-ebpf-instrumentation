// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/json"
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
	assert.Equal(t, 15, tokenValue(span.GenAI.Anthropic.Output.Usage.InputTokens))
	assert.Equal(t, 35, tokenValue(span.GenAI.Anthropic.Output.Usage.OutputTokens))
	assert.JSONEq(t, `[{"type":"text","text":"Quantum computing uses quantum mechanical phenomena like superposition and entanglement to process information."}]`, string(span.GenAI.Anthropic.Output.Content))
}

func TestAnthropicSpan_UsageAfterMalformedEnvelopeField(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://api.anthropic.com/v1/messages", anthropicRequestBody)
	resp := makeGzipResponse(t, http.StatusOK, anthropicHeaders(),
		`{"stop_reason":{},"usage":{"input_tokens":0,"output_tokens":7}}`)

	span, ok := AnthropicSpan(&request.Span{}, req, resp)
	require.True(t, ok)
	assertTokenCount(t, span.GenAI.Anthropic.Output.Usage.InputTokens, 0, true)
	assertTokenCount(t, span.GenAI.Anthropic.Output.Usage.OutputTokens, 7, true)
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
	assert.Equal(t, 17, tokenValue(span.GenAI.Anthropic.Output.Usage.InputTokens))
	assert.Equal(t, 37, tokenValue(span.GenAI.Anthropic.Output.Usage.OutputTokens))
	assert.Equal(t, "With elegant syntax and indentation true,\nPython turns complex problems into something you can do.", string(span.GenAI.Anthropic.Output.Content))
}

func TestParseAnthropicStream_UsesLatestCumulativeUsage(t *testing.T) {
	stream := `event: message_start
data: {"type":"message_start","message":{"model":"claude-sonnet-4-6","id":"msg_sum","type":"message","role":"assistant","usage":{"input_tokens":11,"output_tokens":1,"cache_read_input_tokens":3}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":5}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":13}}

event: message_stop
data: {"type":"message_stop"}

`

	resp, _, err := parseAnthropicStream(strings.NewReader(stream))

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "msg_sum", resp.ID)
	assert.Equal(t, "claude-sonnet-4-6", resp.Model)
	assert.Equal(t, "message", resp.Type)
	assert.Equal(t, "assistant", resp.Role)
	assert.Equal(t, "end_turn", resp.StopReason)
	assert.Equal(t, 11, tokenValue(resp.Usage.InputTokens))
	assert.Equal(t, 3, tokenValue(resp.Usage.CacheReadInputTokens))
	assert.Equal(t, 13, tokenValue(resp.Usage.OutputTokens))
	assert.Equal(t, "hello", string(resp.Content))
}

func TestParseAnthropicStream_ExplicitZeroUsage(t *testing.T) {
	stream := `event: message_start
data: {"type":"message_start","message":{"id":"msg_zero","usage":{"input_tokens":0,"output_tokens":2}}}

event: message_delta
data: {"type":"message_delta","usage":{"output_tokens":0}}

event: message_stop
data: {"type":"message_stop"}

`

	resp, _, err := parseAnthropicStream(strings.NewReader(stream))
	require.NoError(t, err)

	input, inputReported := resp.Usage.InputTokenCount()
	output, outputReported := resp.Usage.OutputTokenCount()
	assert.True(t, inputReported)
	assert.True(t, outputReported)
	assert.Zero(t, input)
	assert.Zero(t, output)
}

func TestParseAnthropicStream_MergesSupplementaryUsage(t *testing.T) {
	stream := `event: message_start
data: {"type":"message_start","message":{"id":"msg_usage","usage":{"cache_read_input_tokens":4,"reasoning_output_tokens":3}}}

event: message_delta
data: {"type":"message_delta","usage":{"cache_creation_input_tokens":0,"reasoning_output_tokens":0}}

event: message_stop
data: {"type":"message_stop"}

`

	resp, _, err := parseAnthropicStream(strings.NewReader(stream))
	require.NoError(t, err)

	assertTokenCount(t, resp.Usage.CacheReadInputTokens, 4, true)
	assertTokenCount(t, resp.Usage.CacheCreationInputTokens, 0, true)
	assertTokenCount(t, resp.Usage.ReasoningOutputTokens, 0, true)
}

func TestParseAnthropicStream_FlushesFinalUndelimitedUsageEvent(t *testing.T) {
	stream := `event: message_delta
data: {"type":"message_delta","usage":{"output_tokens":0,"reasoning_output_tokens":0}}`

	resp, _, err := parseAnthropicStream(strings.NewReader(stream))
	require.NoError(t, err)

	assertTokenCount(t, resp.Usage.OutputTokens, 0, true)
	assertTokenCount(t, resp.Usage.ReasoningOutputTokens, 0, true)
}

func TestParseAnthropicStream_FinalNoSpaceUsageAfterMalformedSibling(t *testing.T) {
	stream := `event:message_delta
data:{"type":"message_delta","delta":[],"usage":{"output_tokens":0,"reasoning_output_tokens":0}}`

	resp, _, err := parseAnthropicStream(strings.NewReader(stream))
	require.NoError(t, err)
	assertTokenCount(t, resp.Usage.OutputTokens, 0, true)
	assertTokenCount(t, resp.Usage.ReasoningOutputTokens, 0, true)
}

func TestParseAnthropicStream_UsageSurvivesMalformedEvents(t *testing.T) {
	stream := `event: message_start
data: {"type":"message_start","message":{"id":"msg_partial","usage":{"input_tokens":7},"model":{}}}

event: message_delta
data: {"type":"message_delta","usage":{"output_tokens":0,"reasoning_output_tokens":0},"malformed":[

event: content_block_delta
data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"ignored"}}
`

	resp, _, err := parseAnthropicStream(strings.NewReader(stream))
	require.NoError(t, err)

	assert.Equal(t, "msg_partial", resp.ID)
	assertTokenCount(t, resp.Usage.InputTokens, 7, true)
	assertTokenCount(t, resp.Usage.OutputTokens, 0, true)
	assertTokenCount(t, resp.Usage.ReasoningOutputTokens, 0, true)
}

func TestAnthropicStream_PreservesUsageBeforeOversizedEvent(t *testing.T) {
	stream := `event: message_delta
data: {"type":"message_delta","usage":{"output_tokens":0,"reasoning_output_tokens":0}}

event: content_block_delta
data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"` +
		strings.Repeat("x", 256*1024) + `"}}`

	parsed, _, err := parseAnthropicStream(strings.NewReader(stream))
	require.Error(t, err)
	assertTokenCount(t, parsed.Usage.OutputTokens, 0, true)
	assertTokenCount(t, parsed.Usage.ReasoningOutputTokens, 0, true)

	req := makeRequest(t, http.MethodPost, "http://api.anthropic.com/v1/messages", `{
		"model":"claude-sonnet-4-6","messages":[],"stream":true
	}`)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type":                           []string{"text/event-stream"},
		"Anthropic-Ratelimit-Input-Tokens-Limit": []string{"30000"},
	}, stream)
	span, ok := AnthropicSpan(&request.Span{}, req, resp)
	require.True(t, ok)
	assertTokenCount(t, span.GenAI.Anthropic.Output.Usage.OutputTokens, 0, true)
	assertTokenCount(t, span.GenAI.Anthropic.Output.Usage.ReasoningOutputTokens, 0, true)
}

func TestParseAnthropicStream_MissingUsage(t *testing.T) {
	stream := `event: message_start
data: {"type":"message_start","message":{"id":"msg_missing"}}

event: message_stop
data: {"type":"message_stop"}

`

	resp, _, err := parseAnthropicStream(strings.NewReader(stream))
	require.NoError(t, err)

	_, inputReported := resp.Usage.InputTokenCount()
	_, outputReported := resp.Usage.OutputTokenCount()
	assert.False(t, inputReported)
	assert.False(t, outputReported)
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

func TestAnthropicToolCalls(t *testing.T) {
	t.Run("single tool_use", func(t *testing.T) {
		content := json.RawMessage(`[{"type":"tool_use","id":"toolu_01","name":"get_weather","input":{}}]`)
		result := extractAnthropicToolCalls(content)
		require.Len(t, result, 1)
		assert.Equal(t, "toolu_01", result[0].ID)
		assert.Equal(t, "get_weather", result[0].Name)
	})

	t.Run("mixed content text and tool_use", func(t *testing.T) {
		content := json.RawMessage(`[{"type":"text","text":"hello"},{"type":"tool_use","id":"toolu_01","name":"get_weather","input":{}},{"type":"tool_use","id":"toolu_02","name":"get_time","input":{}}]`)
		result := extractAnthropicToolCalls(content)
		require.Len(t, result, 2)
		assert.Equal(t, "toolu_01", result[0].ID)
		assert.Equal(t, "get_weather", result[0].Name)
		assert.Equal(t, "toolu_02", result[1].ID)
		assert.Equal(t, "get_time", result[1].Name)
	})

	t.Run("no tool calls", func(t *testing.T) {
		content := json.RawMessage(`[{"type":"text","text":"Hello"}]`)
		result := extractAnthropicToolCalls(content)
		assert.Empty(t, result)
	})

	t.Run("empty content", func(t *testing.T) {
		assert.Nil(t, extractAnthropicToolCalls(nil))
		assert.Nil(t, extractAnthropicToolCalls(json.RawMessage{}))
	})
}

func TestAnthropicStreamToolCalls(t *testing.T) {
	stream := `event: message_start
data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":null,"usage":{"input_tokens":100,"output_tokens":0}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Let me check the weather."}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_01","name":"get_weather"}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"location\":\"Beijing\"}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":1}

event: content_block_start
data: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_02","name":"get_time"}}

event: content_block_delta
data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"timezone\":\"UTC\"}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":2}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":50}}

event: message_stop
data: {"type":"message_stop"}

`

	resp, toolCalls, err := parseAnthropicStream(strings.NewReader(stream))

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "msg_01", resp.ID)
	assert.Equal(t, "claude-sonnet-4-20250514", resp.Model)

	require.Len(t, toolCalls, 2)
	assert.Equal(t, "toolu_01", toolCalls[0].ID)
	assert.Equal(t, "get_weather", toolCalls[0].Name)
	assert.Equal(t, "toolu_02", toolCalls[1].ID)
	assert.Equal(t, "get_time", toolCalls[1].Name)
}

func TestAnthropicStreamNoToolCalls(t *testing.T) {
	stream := `event: message_start
data: {"type":"message_start","message":{"id":"msg_02","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":null,"usage":{"input_tokens":50,"output_tokens":0}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello!"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":10}}

event: message_stop
data: {"type":"message_stop"}

`

	resp, toolCalls, err := parseAnthropicStream(strings.NewReader(stream))

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, toolCalls)
	assert.Equal(t, "msg_02", resp.ID)
}
