// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// --- Non-streaming /v2/chat ---

const cohereChatRequestBody = `{"model":"command-a-03-2025","messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":[{"type":"text","text":"Hello!"}]}],"max_tokens":256,"temperature":0.3,"p":0.75,"k":40,"stop_sequences":["END"],"seed":42,"frequency_penalty":0.1,"presence_penalty":0.2}`

const cohereChatResponseBody = `{
  "id": "c14c80c3-18eb-4519-9460-6c92edd8cfb4",
  "finish_reason": "COMPLETE",
  "message": {
    "role": "assistant",
    "content": [{"type": "text", "text": "Hello! How can I help you today?"}]
  },
  "usage": {
    "billed_units": {"input_tokens": 5, "output_tokens": 9},
    "tokens": {"input_tokens": 71, "output_tokens": 9}
  }
}`

func TestCohereSpan_ChatNonStreaming(t *testing.T) {
	span, ok := runCohereSpan(t, cohereHost, "/v2/chat", cohereChatRequestBody, cohereChatResponseBody)
	require.True(t, ok)

	assert.Equal(t, request.HTTPSubtypeCohere, span.SubType)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Cohere)

	ai := span.GenAI.Cohere
	assert.Equal(t, "chat", ai.OperationName)
	assert.Equal(t, "c14c80c3-18eb-4519-9460-6c92edd8cfb4", ai.ID)
	assert.Equal(t, "command-a-03-2025", ai.Request.Model)
	assert.Equal(t, 256, ai.Request.MaxTokens)
	assert.InDelta(t, 0.3, ai.Request.Temperature, 1e-9)
	assert.InDelta(t, 0.75, ai.TopP, 1e-9)
	assert.Equal(t, 40, ai.Request.TopK)
	assert.InDelta(t, 0.1, ai.Request.FrequencyPenalty, 1e-9)
	assert.InDelta(t, 0.2, ai.Request.PresencePenalty, 1e-9)
	require.NotNil(t, ai.Request.Seed)
	assert.Equal(t, 42, *ai.Request.Seed)
	assert.Equal(t, []string{"END"}, ai.Request.GetStopSequences())
	assert.False(t, ai.Request.Stream)
	assert.Equal(t, 71, tokenValue(ai.Usage.InputTokens))
	assert.Equal(t, 9, tokenValue(ai.Usage.OutputTokens))
	assert.Equal(t, []string{"COMPLETE"}, ai.GetFinishReasons())
	assert.Empty(t, ai.ToolCalls)
}

func TestCohereSpan_ChatNonStreamingOutput(t *testing.T) {
	span, ok := runCohereSpan(t, cohereHost, "/v2/chat", cohereChatRequestBody, cohereChatResponseBody)
	require.True(t, ok)

	assert.JSONEq(t,
		`[{"role":"assistant","parts":[{"type":"text","content":"Hello! How can I help you today?"}],"finish_reason":"COMPLETE"}]`,
		span.GenAI.Cohere.GetOutput())
	assert.JSONEq(t,
		`[{"role":"system","parts":[{"type":"text","content":"You are a helpful assistant."}]},{"role":"user","parts":[{"type":"text","content":"Hello!"}]}]`,
		span.GenAI.Cohere.Request.GetInput())
}

func TestCohereSpan_ToolCalls(t *testing.T) {
	response := `{
  "id": "4fca5c6c-a0bb-4a1c-a1e8-1bd4d9a1e1a6",
  "finish_reason": "TOOL_CALL",
  "message": {
    "role": "assistant",
    "tool_plan": "I will look up the sales report.",
    "tool_calls": [
      {"id": "query_daily_sales_report_0", "type": "function", "function": {"name": "query_daily_sales_report", "arguments": "{\"day\":\"2023-09-29\"}"}}
    ]
  },
  "usage": {"tokens": {"input_tokens": 120, "output_tokens": 30}}
}`
	span, ok := runCohereSpan(t, cohereHost, "/v2/chat", cohereChatRequestBody, response)
	require.True(t, ok)

	ai := span.GenAI.Cohere
	assert.Equal(t, []string{"TOOL_CALL"}, ai.GetFinishReasons())
	require.Len(t, ai.ToolCalls, 1)
	assert.Equal(t, "query_daily_sales_report_0", ai.ToolCalls[0].ID)
	assert.Equal(t, "query_daily_sales_report", ai.ToolCalls[0].Name)
	assert.Contains(t, ai.GetOutput(), `"name":"query_daily_sales_report"`)
}

func TestCohereSpan_ToolResultInput(t *testing.T) {
	reqBody := `{"model":"command-a-03-2025","messages":[
  {"role":"user","content":"What were the sales on 2023-09-29?"},
  {"role":"assistant","tool_plan":"I will look up the sales report.","tool_calls":[{"id":"query_daily_sales_report_0","type":"function","function":{"name":"query_daily_sales_report","arguments":"{\"day\":\"2023-09-29\"}"}}]},
  {"role":"tool","tool_call_id":"query_daily_sales_report_0","content":[{"type":"document","document":{"data":"{\"total_sales_amount\":10000}"}}]}
]}`
	span, ok := runCohereSpan(t, cohereHost, "/v2/chat", reqBody, cohereChatResponseBody)
	require.True(t, ok)

	assert.JSONEq(t, `[
  {"role":"user","parts":[{"type":"text","content":"What were the sales on 2023-09-29?"}]},
  {"role":"assistant","parts":[{"type":"tool_call","id":"query_daily_sales_report_0","name":"query_daily_sales_report","arguments":"{\"day\":\"2023-09-29\"}"}]},
  {"role":"tool","parts":[{"type":"tool_call_response","id":"query_daily_sales_report_0","result":"{\"total_sales_amount\":10000}"}]}
]`, span.GenAI.Cohere.Request.GetInput())
}

func TestCohereSpan_ToolResultObjectDocument(t *testing.T) {
	reqBody := `{"model":"command-a-03-2025","messages":[{"role":"tool","tool_call_id":"t0","content":[{"type":"document","document":{"data":{"total_sales_amount":10000}}}]}]}`
	span, ok := runCohereSpan(t, cohereHost, "/v2/chat", reqBody, cohereChatResponseBody)
	require.True(t, ok)

	assert.JSONEq(t,
		`[{"role":"tool","parts":[{"type":"tool_call_response","id":"t0","result":"{\"total_sales_amount\":10000}"}]}]`,
		span.GenAI.Cohere.Request.GetInput())
}

func TestCohereSpan_ThinkingOutput(t *testing.T) {
	response := `{"id":"x","finish_reason":"COMPLETE","message":{"role":"assistant","content":[{"type":"thinking","thinking":"The user greets me."},{"type":"text","text":"Hello!"}]}}`
	span, ok := runCohereSpan(t, cohereHost, "/v2/chat", cohereChatRequestBody, response)
	require.True(t, ok)

	assert.JSONEq(t,
		`[{"role":"assistant","parts":[{"type":"reasoning","content":"The user greets me."},{"type":"text","content":"Hello!"}],"finish_reason":"COMPLETE"}]`,
		span.GenAI.Cohere.GetOutput())
}

func TestCohereSpan_MissingUsage(t *testing.T) {
	response := `{"id":"x","finish_reason":"COMPLETE","message":{"role":"assistant","content":[]}}`
	span, ok := runCohereSpan(t, cohereHost, "/v2/chat", cohereChatRequestBody, response)
	require.True(t, ok)

	assert.False(t, isReported(span.GenAIInputTokenCount()))
	assert.False(t, isReported(span.GenAIOutputTokenCount()))
}

func TestCohereSpan_InvalidUsagePreservesValidSibling(t *testing.T) {
	response := `{"id":"x","finish_reason":"COMPLETE","usage":{"tokens":{"input_tokens":7,"output_tokens":3.5}}}`
	span, ok := runCohereSpan(t, cohereHost, "/v2/chat", cohereChatRequestBody, response)
	require.True(t, ok)

	assert.Equal(t, 7, reportedValue(span.GenAIInputTokenCount()))
	assert.False(t, isReported(span.GenAIOutputTokenCount()))
}

func TestCohereSpan_ErrorResponse(t *testing.T) {
	response := `{"id":"0a1b","message":"invalid request: model 'unknown' not found"}`
	span, ok := runCohereSpan(t, cohereHost, "/v2/chat", cohereChatRequestBody, response)
	require.True(t, ok)

	ai := span.GenAI.Cohere
	assert.Equal(t, "chat", ai.OperationName)
	assert.Equal(t, "command-a-03-2025", ai.Request.Model)
	assert.Equal(t, "invalid request: model 'unknown' not found", ai.Error.Message)
	assert.Empty(t, ai.GetFinishReasons())
	assert.Empty(t, ai.GetOutput())
	assert.Empty(t, ai.ToolCalls)
}

// --- Streaming /v2/chat ---

const cohereChatStreamResponseBody = `event: message-start
data: {"id":"29f14a5a-11de-4cae-9800-25e4747408ea","type":"message-start","delta":{"message":{"role":"assistant","content":[],"tool_plan":"","tool_calls":[],"citations":[]}}}

event: content-start
data: {"type":"content-start","index":0,"delta":{"message":{"content":{"type":"text","text":""}}}}

event: content-delta
data: {"type":"content-delta","index":0,"delta":{"message":{"content":{"text":"Hello"}}}}

event: content-delta
data: {"type":"content-delta","index":0,"delta":{"message":{"content":{"text":"!"}}}}

event: content-end
data: {"type":"content-end","index":0}

event: message-end
data: {"type":"message-end","delta":{"finish_reason":"COMPLETE","usage":{"billed_units":{"input_tokens":5,"output_tokens":2},"tokens":{"input_tokens":71,"output_tokens":2}}}}

data: [DONE]
`

func TestCohereSpan_ChatStreaming(t *testing.T) {
	reqBody := `{"model":"command-a-03-2025","messages":[{"role":"user","content":"Hi"}],"stream":true}`
	span, ok := runCohereSpan(t, cohereHost, "/v2/chat", reqBody, cohereChatStreamResponseBody)
	require.True(t, ok)

	ai := span.GenAI.Cohere
	assert.Equal(t, "chat", ai.OperationName)
	assert.Equal(t, "29f14a5a-11de-4cae-9800-25e4747408ea", ai.ID)
	assert.True(t, ai.Request.Stream)
	assert.Equal(t, 71, tokenValue(ai.Usage.InputTokens))
	assert.Equal(t, 2, tokenValue(ai.Usage.OutputTokens))
	assert.Equal(t, []string{"COMPLETE"}, ai.GetFinishReasons())
	assert.JSONEq(t,
		`[{"role":"assistant","parts":[{"type":"text","content":"Hello!"}],"finish_reason":"COMPLETE"}]`,
		ai.GetOutput())
}

func TestCohereSpan_ChatStreamingToolCalls(t *testing.T) {
	response := `event: message-start
data: {"id":"a1","type":"message-start","delta":{"message":{"role":"assistant"}}}

event: tool-plan-delta
data: {"type":"tool-plan-delta","delta":{"message":{"tool_plan":"I will check."}}}

event: tool-call-start
data: {"type":"tool-call-start","index":0,"delta":{"message":{"tool_calls":{"id":"query_daily_sales_report_0","type":"function","function":{"name":"query_daily_sales_report","arguments":""}}}}}

event: tool-call-delta
data: {"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"{\"day\":"}}}}}

event: tool-call-delta
data: {"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"\"2023-09-29\"}"}}}}}

event: tool-call-end
data: {"type":"tool-call-end","index":0}

event: message-end
data: {"type":"message-end","delta":{"finish_reason":"TOOL_CALL","usage":{"tokens":{"input_tokens":120,"output_tokens":30}}}}
`
	reqBody := `{"model":"command-a-03-2025","messages":[{"role":"user","content":"Sales on 2023-09-29?"}],"stream":true,"tools":[{"type":"function","function":{"name":"query_daily_sales_report","parameters":{"type":"object"}}}]}`
	span, ok := runCohereSpan(t, cohereHost, "/v2/chat", reqBody, response)
	require.True(t, ok)

	ai := span.GenAI.Cohere
	assert.Equal(t, []string{"TOOL_CALL"}, ai.GetFinishReasons())
	require.Len(t, ai.ToolCalls, 1)
	assert.Equal(t, "query_daily_sales_report", ai.ToolCalls[0].Name)

	var output []struct {
		Parts []struct {
			Type      string          `json:"type"`
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"parts"`
	}
	require.NoError(t, json.Unmarshal([]byte(ai.GetOutput()), &output))
	require.Len(t, output, 1)
	require.Len(t, output[0].Parts, 1)
	assert.Equal(t, "tool_call", output[0].Parts[0].Type)
	assert.Equal(t, "query_daily_sales_report", output[0].Parts[0].Name)
	assert.JSONEq(t, `"{\"day\":\"2023-09-29\"}"`, string(output[0].Parts[0].Arguments))
}

func TestCohereSpan_TruncatedStreamKeepsPartialFields(t *testing.T) {
	response := `event: message-start
data: {"id":"t1","type":"message-start","delta":{"message":{"role":"assistant"}}}

event: content-delta
data: {"type":"content-delta","index":0,"delta":{"message":{"content":{"text":"Partial"}}}}

event: content-delta
data: {"type":"content-delta","index":0,"delta":{"mess`
	span, ok := runCohereSpan(t, cohereHost, "/v2/chat", `{"model":"command-r","stream":true}`, response)
	require.True(t, ok)

	ai := span.GenAI.Cohere
	assert.Equal(t, "t1", ai.ID)
	assert.Empty(t, ai.GetFinishReasons())
	assert.False(t, isReported(span.GenAIInputTokenCount()))
	assert.Contains(t, ai.GetOutput(), "Partial")
}

// --- Request matching ---

func TestCohereSpan_Matching(t *testing.T) {
	for _, tt := range []struct {
		name  string
		host  string
		path  string
		match bool
	}{
		{name: "api host", host: "api.cohere.com", path: "/v2/chat", match: true},
		{name: "api host with port", host: "api.cohere.com:443", path: "/v2/chat", match: true},
		{name: "subdomain", host: "eu.api.cohere.com", path: "/v2/chat", match: true},
		{name: "trailing slash", host: "api.cohere.com", path: "/v2/chat/", match: true},
		{name: "proxy prefix", host: "api.cohere.com", path: "/cohere/v2/chat", match: true},
		{name: "embed endpoint", host: "api.cohere.com", path: "/v2/embed", match: false},
		{name: "rerank endpoint", host: "api.cohere.com", path: "/v2/rerank", match: false},
		{name: "v1 chat", host: "api.cohere.com", path: "/v1/chat", match: false},
		{name: "other host", host: "api.example.com", path: "/v2/chat", match: false},
		{name: "lookalike host", host: "notapi.cohere.com.evil.io", path: "/v2/chat", match: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := runCohereSpan(t, tt.host, tt.path, cohereChatRequestBody, cohereChatResponseBody)
			assert.Equal(t, tt.match, ok)
		})
	}
}

// --- GenAI helpers ---

func TestCohereSpan_GenAIHelpers(t *testing.T) {
	span, ok := runCohereSpan(t, cohereHost, "/v2/chat", cohereChatRequestBody, cohereChatResponseBody)
	require.True(t, ok)

	assert.True(t, request.IsGenAISubtype(span.SubType))
	assert.Equal(t, "chat", span.GenAIOperationName())
	assert.Equal(t, "cohere", span.GenAIProviderName())
	assert.Equal(t, "command-a-03-2025", span.GenAIRequestModel())
	assert.Equal(t, "command-a-03-2025", span.GenAIResponseModel())
	assert.Equal(t, 71, reportedValue(span.GenAIInputTokenCount()))
	assert.Equal(t, 9, reportedValue(span.GenAIOutputTokenCount()))
	assert.Equal(t, "chat command-a-03-2025", span.TraceName())
}

// --- Helpers ---

func runCohereSpan(t *testing.T, host, path, reqBody, respBody string) (request.Span, bool) {
	t.Helper()

	req := &http.Request{
		Method: http.MethodPost,
		Host:   host,
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

	return CohereSpan(baseSpan, req, resp)
}
