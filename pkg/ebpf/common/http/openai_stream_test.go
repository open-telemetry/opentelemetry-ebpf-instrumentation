// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseOpenAIStream_CompleteResponse(t *testing.T) {
	stream := "data: {\"id\":\"chatcmpl-abc123\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"chatcmpl-abc123\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"chatcmpl-abc123\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" world\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\n" +
		"data: [DONE]\n"

	resp, toolCalls := parseOpenAIStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	assert.Equal(t, "chatcmpl-abc123", resp.ID)
	assert.Equal(t, "gpt-4", resp.ResponseModel)
	assert.Equal(t, 10, tokenValue(resp.Usage.PromptTokens))
	assert.Equal(t, 5, tokenValue(resp.Usage.CompletionTokens))
	assert.Equal(t, 15, tokenValue(resp.Usage.TotalTokens))
	assert.Empty(t, toolCalls)

	reasons := resp.GetFinishReasons()
	require.Len(t, reasons, 1)
	assert.Equal(t, "stop", reasons[0])

	// Verify that the accumulated message content is exposed via Choices and
	// can be normalized into the semconv output messages format.
	assertChoiceMessage(t, resp.Choices, "Hello world", "stop")
	assertOutputContains(t, resp.GetOutput(), "Hello world", "stop")
}

func TestParseOpenAIStream_TruncatedNoDone(t *testing.T) {
	// Simulates a buffer truncation where [DONE] is never received.
	stream := "data: {\"id\":\"chatcmpl-trunc\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"chatcmpl-trunc\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"},\"finish_reason\":null}]}\n\n"

	resp, toolCalls := parseOpenAIStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	assert.Equal(t, "chatcmpl-trunc", resp.ID)
	assert.Equal(t, "gpt-4o", resp.ResponseModel)
	// No usage in truncated stream.
	assert.Equal(t, 0, tokenValue(resp.Usage.PromptTokens))
	assert.Equal(t, 0, tokenValue(resp.Usage.CompletionTokens))
	_, inputReported := resp.Usage.InputTokenCount()
	_, outputReported := resp.Usage.OutputTokenCount()
	assert.False(t, inputReported)
	assert.False(t, outputReported)
	// No finish_reason in the truncated stream, but partial content must
	// still be accumulated into Choices so the partial assistant message is
	// preserved for normalization.
	assert.Nil(t, resp.GetFinishReasons())
	assertChoiceMessage(t, resp.Choices, "partial", "")
	assertOutputContains(t, resp.GetOutput(), "partial", "")
	assert.Empty(t, toolCalls)
}

func TestParseOpenAIStream_ToolCalls(t *testing.T) {
	stream := "data: {\"id\":\"chatcmpl-tc\",\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"id\":\"call_abc\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]},\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"chatcmpl-tc\",\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"lo\"}}]},\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"chatcmpl-tc\",\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"cation\\\": \\\"NYC\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n" +
		"data: [DONE]\n"

	resp, toolCalls := parseOpenAIStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	assert.Equal(t, "chatcmpl-tc", resp.ID)
	assert.Equal(t, "gpt-4", resp.ResponseModel)

	reasons := resp.GetFinishReasons()
	require.Len(t, reasons, 1)
	assert.Equal(t, "tool_calls", reasons[0])

	require.Len(t, toolCalls, 1)
	assert.Equal(t, "call_abc", toolCalls[0].ID)
	assert.Equal(t, "get_weather", toolCalls[0].Name)
}

func TestParseOpenAIStream_EmptyStream(t *testing.T) {
	// Only [DONE] is present — no actual data chunks.
	stream := "data: [DONE]\n"

	resp, toolCalls := parseOpenAIStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	assert.Empty(t, resp.ID)
	assert.Empty(t, resp.ResponseModel)
	assert.Equal(t, 0, tokenValue(resp.Usage.PromptTokens))
	assert.Equal(t, 0, tokenValue(resp.Usage.CompletionTokens))
	assert.Nil(t, resp.GetFinishReasons())
	assert.Empty(t, toolCalls)
}

func TestParseOpenAIStream_WithUsageInLastChunk(t *testing.T) {
	// When stream_options: {include_usage: true}, the final chunk includes usage.
	stream := "data: {\"id\":\"chatcmpl-usage\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4-turbo\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"chatcmpl-usage\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4-turbo\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\"},\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"chatcmpl-usage\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4-turbo\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" there\"},\"finish_reason\":\"stop\"}]}\n\n" +
		"data: {\"id\":\"chatcmpl-usage\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4-turbo\",\"choices\":[],\"usage\":{\"prompt_tokens\":25,\"completion_tokens\":12,\"total_tokens\":37}}\n\n" +
		"data: [DONE]\n"

	resp, toolCalls := parseOpenAIStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	assert.Equal(t, "chatcmpl-usage", resp.ID)
	assert.Equal(t, "gpt-4-turbo", resp.ResponseModel)
	assert.Equal(t, 25, tokenValue(resp.Usage.PromptTokens))
	assert.Equal(t, 12, tokenValue(resp.Usage.CompletionTokens))
	assert.Equal(t, 37, tokenValue(resp.Usage.TotalTokens))
	assert.Empty(t, toolCalls)

	reasons := resp.GetFinishReasons()
	require.Len(t, reasons, 1)
	assert.Equal(t, "stop", reasons[0])

	assertChoiceMessage(t, resp.Choices, "Hi there", "stop")
	assertOutputContains(t, resp.GetOutput(), "Hi there", "stop")
}

func TestParseOpenAIStream_ExplicitZeroUsage(t *testing.T) {
	stream := "data: {\"id\":\"chatcmpl-zero\",\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":0,\"completion_tokens\":0,\"total_tokens\":0}}\n\n" +
		"data: [DONE]\n"

	resp, _ := parseOpenAIStream(strings.NewReader(stream))

	input, inputReported := resp.Usage.InputTokenCount()
	output, outputReported := resp.Usage.OutputTokenCount()
	assert.True(t, inputReported)
	assert.True(t, outputReported)
	assert.Zero(t, input)
	assert.Zero(t, output)
}

func TestParseOpenAIStream_MergesCumulativeUsageFields(t *testing.T) {
	stream := "data: {\"usage\":{\"prompt_tokens\":9,\"completion_tokens_details\":{\"reasoning_tokens\":4},\"prompt_tokens_details\":{\"cached_tokens\":3}}}\n\n" +
		"data: {\"usage\":{\"completion_tokens\":0,\"completion_tokens_details\":{\"reasoning_tokens\":0},\"prompt_tokens_details\":{\"cache_creation_tokens\":0}}}\n\n" +
		"data: [DONE]\n"

	resp, _ := parseOpenAIStream(strings.NewReader(stream))

	assertTokenCount(t, resp.Usage.PromptTokens, 9, true)
	assertTokenCount(t, resp.Usage.CompletionTokens, 0, true)
	require.NotNil(t, resp.Usage.OutputDetails)
	assertTokenCount(t, resp.Usage.OutputDetails.ReasoningTokens, 0, true)
	require.NotNil(t, resp.Usage.InputDetails)
	assertTokenCount(t, resp.Usage.InputDetails.CachedTokens, 3, true)
	assertTokenCount(t, resp.Usage.InputDetails.CacheCreationTokens, 0, true)
}

func TestParseOpenAIStream_ResponsesUsageSurvivesPartialEvent(t *testing.T) {
	stream := `data: {"type":"response.completed","choices":{},"response":{"id":"resp_1","model":"gpt-5","usage":{"input_tokens":0,"output_tokens":2,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}}}` + "\n" +
		`data: {"response":{"usage":{"output_tokens":0}},"truncated":[` + "\n"

	resp, _ := parseOpenAIStream(strings.NewReader(stream))

	assert.Equal(t, "resp_1", resp.ID)
	assert.Equal(t, "gpt-5", resp.ResponseModel)
	assertTokenCount(t, resp.Usage.InputTokens, 0, true)
	assertTokenCount(t, resp.Usage.OutputTokens, 0, true)
	require.NotNil(t, resp.Usage.InputDetails)
	assertTokenCount(t, resp.Usage.InputDetails.CachedTokens, 0, true)
	require.NotNil(t, resp.Usage.OutputDetails)
	assertTokenCount(t, resp.Usage.OutputDetails.ReasoningTokens, 0, true)
}

func TestParseOpenAIStream_TopLevelUsageSurvivesMalformedSibling(t *testing.T) {
	stream := "data: {\"usage\":{\"prompt_tokens\":7},\"choices\":{}}\n"

	resp, _ := parseOpenAIStream(strings.NewReader(stream))
	assertTokenCount(t, resp.Usage.PromptTokens, 7, true)
}

func TestParseOpenAIStream_FinalNoSpaceUsageAfterMalformedSibling(t *testing.T) {
	stream := `data:{"choices":{},"usage":{"prompt_tokens":0,"completion_tokens":0}}`

	resp, _ := parseOpenAIStream(strings.NewReader(stream))
	assertTokenCount(t, resp.Usage.PromptTokens, 0, true)
	assertTokenCount(t, resp.Usage.CompletionTokens, 0, true)
}

func TestParseOpenAIStream_InputOutputTokens(t *testing.T) {
	stream := "data: {\"id\":\"chatcmpl-dash\",\"object\":\"chat.completion.chunk\",\"model\":\"qwen-plus\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hi\"},\"finish_reason\":\"stop\"}],\"usage\":{\"input_tokens\":15,\"output_tokens\":3,\"total_tokens\":18}}\n\n" +
		"data: [DONE]\n"

	resp, toolCalls := parseOpenAIStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	assert.Equal(t, "chatcmpl-dash", resp.ID)
	assert.Equal(t, "qwen-plus", resp.ResponseModel)
	assert.Equal(t, 15, tokenValue(resp.Usage.InputTokens))
	assert.Equal(t, 3, tokenValue(resp.Usage.OutputTokens))
	assert.Equal(t, 18, tokenValue(resp.Usage.TotalTokens))
	assert.Equal(t, 15, reportedValue(resp.Usage.InputTokenCount()))
	assert.Equal(t, 3, reportedValue(resp.Usage.OutputTokenCount()))
	assert.Empty(t, toolCalls)

	assertChoiceMessage(t, resp.Choices, "hi", "stop")
}

func TestParseOpenAIStream_MixedTokenFields(t *testing.T) {
	stream := "data: {\"id\":\"chatcmpl-mix\",\"model\":\"qwen-plus\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2,\"total_tokens\":12,\"input_tokens\":10,\"output_tokens\":2}}\n\n" +
		"data: [DONE]\n"

	resp, _ := parseOpenAIStream(strings.NewReader(stream))

	assert.Equal(t, 10, tokenValue(resp.Usage.PromptTokens))
	assert.Equal(t, 2, tokenValue(resp.Usage.CompletionTokens))
	assert.Equal(t, 10, tokenValue(resp.Usage.InputTokens))
	assert.Equal(t, 2, tokenValue(resp.Usage.OutputTokens))
	assert.Equal(t, 10, reportedValue(resp.Usage.InputTokenCount()))
	assert.Equal(t, 2, reportedValue(resp.Usage.OutputTokenCount()))
}

// assertChoiceMessage decodes the streaming Choices JSON and verifies the
// aggregated assistant role, content, and finish_reason. This guards against
// regressions where the SSE parser would drop delta.content fragments.
func assertChoiceMessage(t *testing.T, raw []byte, content, finishReason string) {
	t.Helper()
	require.NotNil(t, raw, "choices JSON must be populated")

	var decoded []struct {
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	}
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.Len(t, decoded, 1)
	assert.Equal(t, "assistant", decoded[0].Message.Role)
	assert.Equal(t, content, decoded[0].Message.Content)
	assert.Equal(t, finishReason, decoded[0].FinishReason)
}

// assertOutputContains validates that VendorOpenAI.GetOutput() produces
// semconv-shaped output messages that include the aggregated text content
// (and finish_reason when present).
func assertOutputContains(t *testing.T, output, content, finishReason string) {
	t.Helper()
	require.NotEmpty(t, output, "GetOutput must not be empty")
	assert.Contains(t, output, content)
	if finishReason != "" {
		assert.Contains(t, output, finishReason)
	}
}
