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

func TestParseGeminiStream_CompleteResponse(t *testing.T) {
	stream := "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"AI \"}],\"role\":\"model\"}}],\"modelVersion\":\"gemini-2.0-flash\",\"responseId\":\"resp_abc\"}\n\n" +
		"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"uses \"}],\"role\":\"model\"}}],\"modelVersion\":\"gemini-2.0-flash\",\"responseId\":\"resp_abc\"}\n\n" +
		"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"machine learning.\"}],\"role\":\"model\"},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":10,\"candidatesTokenCount\":5,\"totalTokenCount\":15},\"modelVersion\":\"gemini-2.0-flash\",\"responseId\":\"resp_abc\"}\n\n"

	resp, toolCalls := parseGeminiStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	assert.Equal(t, "gemini-2.0-flash", resp.ModelVersion)
	assert.Equal(t, "resp_abc", resp.ResponseID)
	assert.Equal(t, 10, resp.UsageMetadata.PromptTokenCount)
	assert.Equal(t, 5, resp.UsageMetadata.CandidatesTokenCount)
	assert.Equal(t, 15, resp.UsageMetadata.TotalTokenCount)
	assert.Empty(t, toolCalls)

	require.Len(t, resp.Candidates, 1)
	assert.Equal(t, "STOP", resp.Candidates[0].FinishReason)
	assert.Equal(t, "model", resp.Candidates[0].Content.Role)

	var parts []struct {
		Text string `json:"text"`
	}
	require.NoError(t, json.Unmarshal(resp.Candidates[0].Content.Parts, &parts))
	require.Len(t, parts, 1)
	assert.Equal(t, "AI uses machine learning.", parts[0].Text)
}

func TestParseGeminiStream_TruncatedNoUsage(t *testing.T) {
	stream := "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hello\"}],\"role\":\"model\"}}],\"modelVersion\":\"gemini-2.0-flash\"}\n\n" +
		"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\" world\"}],\"role\":\"model\"}}],\"modelVersion\":\"gemini-2.0-flash\"}\n\n"

	resp, toolCalls := parseGeminiStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	assert.Equal(t, "gemini-2.0-flash", resp.ModelVersion)
	assert.Equal(t, 0, resp.UsageMetadata.TotalTokenCount)
	assert.Empty(t, toolCalls)

	require.Len(t, resp.Candidates, 1)
	assert.Empty(t, resp.Candidates[0].FinishReason)

	var parts []struct {
		Text string `json:"text"`
	}
	require.NoError(t, json.Unmarshal(resp.Candidates[0].Content.Parts, &parts))
	require.Len(t, parts, 1)
	assert.Equal(t, "Hello world", parts[0].Text)
}

func TestParseGeminiStream_ToolCalls(t *testing.T) {
	stream := "data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"get_weather\",\"args\":{\"location\":\"NYC\"}}}],\"role\":\"model\"},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":8,\"candidatesTokenCount\":3,\"totalTokenCount\":11},\"modelVersion\":\"gemini-2.0-flash\",\"responseId\":\"resp_tc\"}\n\n"

	resp, toolCalls := parseGeminiStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	assert.Equal(t, "resp_tc", resp.ResponseID)
	require.Len(t, toolCalls, 1)
	assert.Equal(t, "get_weather", toolCalls[0].Name)
	assert.Equal(t, "STOP", resp.Candidates[0].FinishReason)
}

func TestParseGeminiStream_EmptyStream(t *testing.T) {
	resp, toolCalls := parseGeminiStream(strings.NewReader(""))

	require.NotNil(t, resp)
	assert.Empty(t, resp.ModelVersion)
	assert.Empty(t, resp.ResponseID)
	assert.Equal(t, 0, resp.UsageMetadata.TotalTokenCount)
	assert.Empty(t, resp.Candidates)
	assert.Empty(t, toolCalls)
}

func TestParseGeminiStream_MultipleTextParts(t *testing.T) {
	stream := "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"First \"},{\"text\":\"and second.\"}],\"role\":\"model\"},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":5,\"candidatesTokenCount\":4,\"totalTokenCount\":9},\"modelVersion\":\"gemini-2.0-flash\",\"responseId\":\"resp_multi\"}\n\n"

	resp, toolCalls := parseGeminiStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	assert.Equal(t, "resp_multi", resp.ResponseID)
	assert.Empty(t, toolCalls)

	var parts []struct {
		Text string `json:"text"`
	}
	require.NoError(t, json.Unmarshal(resp.Candidates[0].Content.Parts, &parts))
	require.Len(t, parts, 1)
	assert.Equal(t, "First and second.", parts[0].Text)
}

func TestParseGeminiStream_MultipleCandidates(t *testing.T) {
	stream := "data: {\"candidates\":[{\"index\":0,\"content\":{\"parts\":[{\"text\":\"Answer A \"}],\"role\":\"model\"}},{\"index\":1,\"content\":{\"parts\":[{\"text\":\"Answer B \"}],\"role\":\"model\"}}],\"modelVersion\":\"gemini-2.0-flash\"}\n\n" +
		"data: {\"candidates\":[{\"index\":0,\"content\":{\"parts\":[{\"text\":\"continued.\"}],\"role\":\"model\"},\"finishReason\":\"STOP\"},{\"index\":1,\"content\":{\"parts\":[{\"text\":\"also done.\"}],\"role\":\"model\"},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":12,\"candidatesTokenCount\":8,\"totalTokenCount\":20},\"modelVersion\":\"gemini-2.0-flash\",\"responseId\":\"resp_mc\"}\n\n"

	resp, toolCalls := parseGeminiStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	assert.Equal(t, "resp_mc", resp.ResponseID)
	assert.Equal(t, 12, resp.UsageMetadata.PromptTokenCount)
	assert.Empty(t, toolCalls)

	require.Len(t, resp.Candidates, 2)

	// Candidate 0
	assert.Equal(t, "STOP", resp.Candidates[0].FinishReason)
	var parts0 []struct {
		Text string `json:"text"`
	}
	require.NoError(t, json.Unmarshal(resp.Candidates[0].Content.Parts, &parts0))
	require.Len(t, parts0, 1)
	assert.Equal(t, "Answer A continued.", parts0[0].Text)

	// Candidate 1
	assert.Equal(t, "STOP", resp.Candidates[1].FinishReason)
	var parts1 []struct {
		Text string `json:"text"`
	}
	require.NoError(t, json.Unmarshal(resp.Candidates[1].Content.Parts, &parts1))
	require.Len(t, parts1, 1)
	assert.Equal(t, "Answer B also done.", parts1[0].Text)
}

func TestParseGeminiStream_FunctionCallArguments(t *testing.T) {
	stream := "data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"get_weather\",\"args\":{\"location\":\"NYC\",\"unit\":\"celsius\"}}}],\"role\":\"model\"},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":10,\"candidatesTokenCount\":5,\"totalTokenCount\":15},\"modelVersion\":\"gemini-2.0-flash\",\"responseId\":\"resp_fca\"}\n\n"

	resp, toolCalls := parseGeminiStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	require.Len(t, toolCalls, 1)
	assert.Equal(t, "get_weather", toolCalls[0].Name)

	// Verify the function call arguments are preserved in the parts output.
	require.Len(t, resp.Candidates, 1)
	var parts []struct {
		FunctionCall *struct {
			Name string          `json:"name"`
			Args json.RawMessage `json:"args"`
		} `json:"functionCall"`
	}
	require.NoError(t, json.Unmarshal(resp.Candidates[0].Content.Parts, &parts))
	require.Len(t, parts, 1)
	require.NotNil(t, parts[0].FunctionCall)
	assert.Equal(t, "get_weather", parts[0].FunctionCall.Name)
	assert.Contains(t, string(parts[0].FunctionCall.Args), "NYC")
	assert.Contains(t, string(parts[0].FunctionCall.Args), "celsius")
}

func TestParseGeminiStream_PartialUsageMetadata(t *testing.T) {
	// Usage with promptTokenCount only (totalTokenCount is 0).
	stream := "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Done.\"}],\"role\":\"model\"},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":7,\"candidatesTokenCount\":0,\"totalTokenCount\":0},\"modelVersion\":\"gemini-2.0-flash\",\"responseId\":\"resp_pu\"}\n\n"

	resp, _ := parseGeminiStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	assert.Equal(t, 7, resp.UsageMetadata.PromptTokenCount)
	assert.Equal(t, 0, resp.UsageMetadata.CandidatesTokenCount)
}

func TestParseGeminiStream_DataPrefixWithoutSpace(t *testing.T) {
	// SSE "data:" without space after colon.
	stream := "data:{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"no space\"}],\"role\":\"model\"},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":2,\"totalTokenCount\":5},\"modelVersion\":\"gemini-2.0-flash\",\"responseId\":\"resp_ns\"}\n\n"

	resp, toolCalls := parseGeminiStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	assert.Equal(t, "gemini-2.0-flash", resp.ModelVersion)
	assert.Equal(t, "resp_ns", resp.ResponseID)
	assert.Equal(t, 5, resp.UsageMetadata.TotalTokenCount)
	assert.Empty(t, toolCalls)

	require.Len(t, resp.Candidates, 1)
	var parts []struct {
		Text string `json:"text"`
	}
	require.NoError(t, json.Unmarshal(resp.Candidates[0].Content.Parts, &parts))
	require.Len(t, parts, 1)
	assert.Equal(t, "no space", parts[0].Text)
}
