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
	assert.Equal(t, 10, tokenValue(resp.UsageMetadata.PromptTokenCount))
	assert.Equal(t, 5, tokenValue(resp.UsageMetadata.CandidatesTokenCount))
	assert.Equal(t, 15, tokenValue(resp.UsageMetadata.TotalTokenCount))
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
	assert.Equal(t, 0, tokenValue(resp.UsageMetadata.TotalTokenCount))
	_, inputReported := resp.UsageMetadata.InputTokenCount()
	_, outputReported := resp.UsageMetadata.OutputTokenCount()
	assert.False(t, inputReported)
	assert.False(t, outputReported)
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
	assert.Equal(t, 0, tokenValue(resp.UsageMetadata.TotalTokenCount))
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
	assert.Equal(t, 12, tokenValue(resp.UsageMetadata.PromptTokenCount))
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
	assert.Equal(t, 7, tokenValue(resp.UsageMetadata.PromptTokenCount))
	assert.Equal(t, 0, tokenValue(resp.UsageMetadata.CandidatesTokenCount))
	_, outputReported := resp.UsageMetadata.OutputTokenCount()
	assert.True(t, outputReported)
}

func TestParseGeminiStream_ExplicitZeroUsage(t *testing.T) {
	stream := "data: {\"candidates\":[],\"usageMetadata\":{\"promptTokenCount\":0,\"candidatesTokenCount\":0,\"totalTokenCount\":0},\"responseId\":\"resp_zero\"}\n\n"

	resp, _ := parseGeminiStream(strings.NewReader(stream))

	input, inputReported := resp.UsageMetadata.InputTokenCount()
	output, outputReported := resp.UsageMetadata.OutputTokenCount()
	assert.True(t, inputReported)
	assert.True(t, outputReported)
	assert.Zero(t, input)
	assert.Zero(t, output)
}

func TestParseGeminiStream_MergesCumulativeUsageFields(t *testing.T) {
	stream := "data: {\"usageMetadata\":{\"promptTokenCount\":7,\"candidatesTokenCount\":4,\"thoughtsTokenCount\":3,\"cachedContentTokenCount\":2}}\n\n" +
		"data: {\"usageMetadata\":{\"candidatesTokenCount\":0,\"thoughtsTokenCount\":0,\"cachedContentTokenCount\":0,\"toolUsePromptTokenCount\":0,\"totalTokenCount\":7}}\n\n"

	resp, _ := parseGeminiStream(strings.NewReader(stream))

	assertTokenCount(t, resp.UsageMetadata.PromptTokenCount, 7, true)
	assertTokenCount(t, resp.UsageMetadata.CandidatesTokenCount, 0, true)
	assertTokenCount(t, resp.UsageMetadata.TotalTokenCount, 7, true)
	assertTokenCount(t, resp.UsageMetadata.ThoughtsTokenCount, 0, true)
	assertTokenCount(t, resp.UsageMetadata.CachedContentTokenCount, 0, true)
	assertTokenCount(t, resp.UsageMetadata.ToolUsePromptTokenCount, 0, true)
}

func TestParseGeminiStream_UsageSurvivesMalformedAndTruncatedSiblings(t *testing.T) {
	stream := "data: {\"usageMetadata\":{\"promptTokenCount\":7,\"thoughtsTokenCount\":2},\"candidates\":{}}\n" +
		"data: {\"usageMetadata\":{\"cachedContentTokenCount\":0},\"candidates\":[\n" +
		"data: {\"candidates\":{},\"usageMetadata\":{\"candidatesTokenCount\":0}}\n"

	resp, _ := parseGeminiStream(strings.NewReader(stream))

	assertTokenCount(t, resp.UsageMetadata.PromptTokenCount, 7, true)
	assertTokenCount(t, resp.UsageMetadata.ThoughtsTokenCount, 2, true)
	assertTokenCount(t, resp.UsageMetadata.CachedContentTokenCount, 0, true)
	assertTokenCount(t, resp.UsageMetadata.CandidatesTokenCount, 0, true)
}

func TestParseGeminiStream_DataPrefixWithoutSpace(t *testing.T) {
	// SSE "data:" without space after colon.
	stream := "data:{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"no space\"}],\"role\":\"model\"},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":2,\"totalTokenCount\":5},\"modelVersion\":\"gemini-2.0-flash\",\"responseId\":\"resp_ns\"}\n\n"

	resp, toolCalls := parseGeminiStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	assert.Equal(t, "gemini-2.0-flash", resp.ModelVersion)
	assert.Equal(t, "resp_ns", resp.ResponseID)
	assert.Equal(t, 5, tokenValue(resp.UsageMetadata.TotalTokenCount))
	assert.Empty(t, toolCalls)

	require.Len(t, resp.Candidates, 1)
	var parts []struct {
		Text string `json:"text"`
	}
	require.NoError(t, json.Unmarshal(resp.Candidates[0].Content.Parts, &parts))
	require.Len(t, parts, 1)
	assert.Equal(t, "no space", parts[0].Text)
}

func TestParseGeminiStream_NegativeCandidateIndex(t *testing.T) {
	// A malformed response with a negative candidate index must not panic.
	stream := "data: {\"candidates\":[{\"index\":-1,\"content\":{\"parts\":[{\"text\":\"bad\"}],\"role\":\"model\"}}],\"modelVersion\":\"gemini-2.0-flash\"}\n\n"

	resp, _ := parseGeminiStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	assert.Empty(t, resp.Candidates)
}

func TestParseGeminiStream_OversizedCandidateIndex(t *testing.T) {
	// A malformed response with an oversized candidate index must not cause
	// excessive allocation.
	stream := "data: {\"candidates\":[{\"index\":99999,\"content\":{\"parts\":[{\"text\":\"bad\"}],\"role\":\"model\"}}],\"modelVersion\":\"gemini-2.0-flash\"}\n\n"

	resp, _ := parseGeminiStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	assert.Empty(t, resp.Candidates)
}

func TestParseGeminiStream_InterleavedTextAndFunctionCall(t *testing.T) {
	// Parts arrive across chunks in order: text, functionCall, text.
	// The parser must preserve this ordering rather than emitting all
	// text first.
	stream := "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Before call \"}],\"role\":\"model\"}}],\"modelVersion\":\"gemini-2.0-flash\"}\n\n" +
		"data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"get_weather\",\"args\":{\"location\":\"NYC\"}}}],\"role\":\"model\"}}],\"modelVersion\":\"gemini-2.0-flash\"}\n\n" +
		"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"after call.\"}],\"role\":\"model\"},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":10,\"candidatesTokenCount\":8,\"totalTokenCount\":18},\"modelVersion\":\"gemini-2.0-flash\",\"responseId\":\"resp_interleave\"}\n\n"

	resp, toolCalls := parseGeminiStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	require.Len(t, toolCalls, 1)
	assert.Equal(t, "get_weather", toolCalls[0].Name)

	require.Len(t, resp.Candidates, 1)
	var parts []struct {
		Text         string `json:"text"`
		FunctionCall *struct {
			Name string          `json:"name"`
			Args json.RawMessage `json:"args"`
		} `json:"functionCall"`
	}
	require.NoError(t, json.Unmarshal(resp.Candidates[0].Content.Parts, &parts))
	require.Len(t, parts, 3)

	// Part 0: text "Before call "
	assert.Equal(t, "Before call ", parts[0].Text)
	assert.Nil(t, parts[0].FunctionCall)

	// Part 1: function call
	assert.NotNil(t, parts[1].FunctionCall)
	assert.Equal(t, "get_weather", parts[1].FunctionCall.Name)
	assert.Empty(t, parts[1].Text)

	// Part 2: text "after call."
	assert.Equal(t, "after call.", parts[2].Text)
	assert.Nil(t, parts[2].FunctionCall)
}

func TestParseGeminiStream_ManyTextChunks(t *testing.T) {
	const chunk = `data: {"candidates":[{"content":{"parts":[{"text":"chunk "}],"role":"model"}}]}` + "\n\n"

	var stream strings.Builder
	for range 1000 {
		stream.WriteString(chunk)
	}

	resp, _ := parseGeminiStream(strings.NewReader(stream.String()))

	require.NotNil(t, resp)
	require.Len(t, resp.Candidates, 1)

	var parts []struct {
		Text string `json:"text"`
	}
	require.NoError(t, json.Unmarshal(resp.Candidates[0].Content.Parts, &parts))
	require.Len(t, parts, 1)
	assert.Equal(t, strings.Repeat("chunk ", 1000), parts[0].Text)
}

func TestParseGeminiStream_ErrorEnvelopeBare(t *testing.T) {
	// Bare error JSON record (not wrapped in "data:" prefix) after valid data.
	stream := "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"partial\"}],\"role\":\"model\"}}],\"modelVersion\":\"gemini-2.0-flash\"}\n\n" +
		"{\"error\":{\"code\":429,\"message\":\"Resource exhausted\",\"status\":\"RESOURCE_EXHAUSTED\"}}\n"

	resp, _ := parseGeminiStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Equal(t, 429, resp.Error.Code)
	assert.Equal(t, "RESOURCE_EXHAUSTED", resp.Error.Status)
	assert.Equal(t, "Resource exhausted", resp.Error.Message)

	// The valid data chunk before the error should still be captured.
	require.Len(t, resp.Candidates, 1)
}

func TestParseGeminiStream_ErrorEnvelopeInDataLine(t *testing.T) {
	// Error envelope arriving inside a "data:" SSE line (no candidates).
	stream := "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hello\"}],\"role\":\"model\"}}],\"modelVersion\":\"gemini-2.0-flash\"}\n\n" +
		"data: {\"usageMetadata\":[],\"error\":{\"code\":500,\"message\":\"Internal error\",\"status\":\"INTERNAL\"}}\n\n"

	resp, _ := parseGeminiStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Equal(t, 500, resp.Error.Code)
	assert.Equal(t, "INTERNAL", resp.Error.Status)
}

func TestParseGeminiStream_StreamingFunctionCallArguments(t *testing.T) {
	// Vertex AI streamFunctionCallArguments: the name arrives first, then
	// partialArgs arrive as arrays of {jsonPath, <typed value>} objects in
	// subsequent chunks, with willContinue absent on the final fragment.
	chunk1 := `data: {"candidates":[{"content":{"parts":[{"functionCall":{"name":"get_weather","partialArgs":[{"jsonPath":"$.location","stringValue":"NYC"}],"willContinue":true}}],"role":"model"}}],"modelVersion":"gemini-2.0-flash"}` + "\n\n"
	chunk2 := `data: {"candidates":[{"content":{"parts":[{"functionCall":{"partialArgs":[{"jsonPath":"$.unit","stringValue":"celsius"}],"willContinue":true}}],"role":"model"}}],"modelVersion":"gemini-2.0-flash"}` + "\n\n"
	chunk3 := `data: {"candidates":[{"content":{"parts":[{"functionCall":{"partialArgs":[{"jsonPath":"$.days","numberValue":3}]}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":3,"totalTokenCount":8},"modelVersion":"gemini-2.0-flash","responseId":"resp_sfc"}` + "\n\n"
	stream := chunk1 + chunk2 + chunk3

	resp, toolCalls := parseGeminiStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	require.Len(t, toolCalls, 1)
	assert.Equal(t, "get_weather", toolCalls[0].Name)

	// The aggregated function call should reconstruct args from the paths and
	// typed values across all fragments.
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

	var args map[string]any
	require.NoError(t, json.Unmarshal(parts[0].FunctionCall.Args, &args))
	assert.Equal(t, "NYC", args["location"])
	assert.Equal(t, "celsius", args["unit"])
	assert.InEpsilon(t, float64(3), args["days"], 0.0001)
}

func TestParseGeminiStream_ThoughtToAnswerBoundary(t *testing.T) {
	// Gemini thinking model: thought parts (thought:true) followed by
	// answer parts (no thought flag). They must NOT be coalesced.
	stream := "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Let me think...\",\"thought\":true}],\"role\":\"model\"}}],\"modelVersion\":\"gemini-2.0-flash\"}\n\n" +
		"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\" reasoning step.\",\"thought\":true}],\"role\":\"model\"}}],\"modelVersion\":\"gemini-2.0-flash\"}\n\n" +
		"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"The answer is 42.\"}],\"role\":\"model\"},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":5,\"candidatesTokenCount\":10,\"totalTokenCount\":15},\"modelVersion\":\"gemini-2.0-flash\",\"responseId\":\"resp_think\"}\n\n"

	resp, _ := parseGeminiStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	require.Len(t, resp.Candidates, 1)

	var parts []struct {
		Text    string `json:"text"`
		Thought bool   `json:"thought"`
	}
	require.NoError(t, json.Unmarshal(resp.Candidates[0].Content.Parts, &parts))
	// Should have 2 parts: thought (coalesced) and answer (separate).
	require.Len(t, parts, 2)

	// Part 0: coalesced thought
	assert.Equal(t, "Let me think... reasoning step.", parts[0].Text)
	assert.True(t, parts[0].Thought)

	// Part 1: answer (no thought flag)
	assert.Equal(t, "The answer is 42.", parts[1].Text)
	assert.False(t, parts[1].Thought)
}

func TestParseGeminiStream_StreamingFCNameOnly(t *testing.T) {
	// A function call with only name (no args at all) should still be captured.
	stream := "data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"list_items\"}}],\"role\":\"model\"},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":5,\"candidatesTokenCount\":2,\"totalTokenCount\":7},\"modelVersion\":\"gemini-2.0-flash\",\"responseId\":\"resp_noarg\"}\n\n"

	resp, toolCalls := parseGeminiStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	require.Len(t, toolCalls, 1)
	assert.Equal(t, "list_items", toolCalls[0].Name)

	require.Len(t, resp.Candidates, 1)
	var parts []struct {
		FunctionCall *struct {
			Name string `json:"name"`
		} `json:"functionCall"`
	}
	require.NoError(t, json.Unmarshal(resp.Candidates[0].Content.Parts, &parts))
	require.Len(t, parts, 1)
	require.NotNil(t, parts[0].FunctionCall)
	assert.Equal(t, "list_items", parts[0].FunctionCall.Name)
}

func TestParseGeminiStream_ThoughtSignaturePreserved(t *testing.T) {
	// Two thought parts with distinct thoughtSignatures must NOT be merged,
	// and each signature must be carried through to the output.
	stream := `data: {"candidates":[{"content":{"parts":[{"text":"step one","thought":true,"thoughtSignature":"sigA"}],"role":"model"}}],"modelVersion":"gemini-2.0-flash"}` + "\n\n" +
		`data: {"candidates":[{"content":{"parts":[{"text":"step two","thought":true,"thoughtSignature":"sigB"}],"role":"model"},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":4,"totalTokenCount":7},"modelVersion":"gemini-2.0-flash"}` + "\n\n"

	resp, _ := parseGeminiStream(strings.NewReader(stream))
	require.NotNil(t, resp)
	require.Len(t, resp.Candidates, 1)

	var parts []struct {
		Text             string `json:"text"`
		Thought          bool   `json:"thought"`
		ThoughtSignature string `json:"thoughtSignature"`
	}
	require.NoError(t, json.Unmarshal(resp.Candidates[0].Content.Parts, &parts))
	require.Len(t, parts, 2)
	assert.Equal(t, "step one", parts[0].Text)
	assert.Equal(t, "sigA", parts[0].ThoughtSignature)
	assert.Equal(t, "step two", parts[1].Text)
	assert.Equal(t, "sigB", parts[1].ThoughtSignature)
}

func TestParseGeminiStream_SignatureOnlyPart(t *testing.T) {
	// A part with empty text but a thoughtSignature must be preserved (not
	// dropped by the empty-text guard) and kept distinct from adjacent text.
	stream := `data: {"candidates":[{"content":{"parts":[{"text":"answer"},{"text":"","thoughtSignature":"sigOnly"}],"role":"model"},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1,"totalTokenCount":2},"modelVersion":"gemini-2.0-flash"}` + "\n\n"

	resp, _ := parseGeminiStream(strings.NewReader(stream))
	require.NotNil(t, resp)
	require.Len(t, resp.Candidates, 1)

	var parts []struct {
		Text             string `json:"text"`
		ThoughtSignature string `json:"thoughtSignature"`
	}
	require.NoError(t, json.Unmarshal(resp.Candidates[0].Content.Parts, &parts))
	require.Len(t, parts, 2)
	assert.Equal(t, "answer", parts[0].Text)
	assert.Empty(t, parts[0].ThoughtSignature)
	assert.Empty(t, parts[1].Text)
	assert.Equal(t, "sigOnly", parts[1].ThoughtSignature)
}

func TestParseGeminiStream_FunctionCallSignaturePreserved(t *testing.T) {
	// A function-call part carrying an outer thoughtSignature must retain it
	// when the response is rebuilt.
	stream := `data: {"candidates":[{"content":{"parts":[{"functionCall":{"name":"get_weather","args":{"location":"NYC"}},"thoughtSignature":"fcSig"}],"role":"model"},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":2,"candidatesTokenCount":2,"totalTokenCount":4},"modelVersion":"gemini-2.0-flash"}` + "\n\n"

	resp, toolCalls := parseGeminiStream(strings.NewReader(stream))
	require.NotNil(t, resp)
	require.Len(t, toolCalls, 1)
	require.Len(t, resp.Candidates, 1)

	var parts []struct {
		ThoughtSignature string `json:"thoughtSignature"`
		FunctionCall     *struct {
			Name string `json:"name"`
		} `json:"functionCall"`
	}
	require.NoError(t, json.Unmarshal(resp.Candidates[0].Content.Parts, &parts))
	require.Len(t, parts, 1)
	require.NotNil(t, parts[0].FunctionCall)
	assert.Equal(t, "get_weather", parts[0].FunctionCall.Name)
	assert.Equal(t, "fcSig", parts[0].ThoughtSignature)
}

func TestParseGeminiStream_SafetyRatingsPreserved(t *testing.T) {
	// safetyRatings present on a streamed candidate must be preserved in the
	// rebuilt response, matching the non-streaming path.
	stream := `data: {"candidates":[{"content":{"parts":[{"text":"hi"}],"role":"model"},"finishReason":"STOP","safetyRatings":[{"category":"HARM_CATEGORY_HATE_SPEECH","probability":"NEGLIGIBLE"}]}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1,"totalTokenCount":2},"modelVersion":"gemini-2.0-flash"}` + "\n\n"

	resp, _ := parseGeminiStream(strings.NewReader(stream))
	require.NotNil(t, resp)
	require.Len(t, resp.Candidates, 1)
	require.NotNil(t, resp.Candidates[0].SafetyRatings)
	assert.Contains(t, string(resp.Candidates[0].SafetyRatings), "HARM_CATEGORY_HATE_SPEECH")
}

func TestParseGeminiStream_StreamingFunctionCallArrayPath(t *testing.T) {
	// Vertex AI streamFunctionCallArguments with array segments in the
	// jsonPath. Array indices are part of the PartialArg contract (the schema
	// example uses $.foo.bar[0].data), so the reconstructed arguments must
	// place values inside real JSON arrays rather than under bracket-suffixed
	// object keys like "items[0]".
	chunk1 := `data: {"candidates":[{"content":{"parts":[{"functionCall":{"name":"create_order","partialArgs":[{"jsonPath":"$.items[0].id","numberValue":7}],"willContinue":true}}],"role":"model"}}],"modelVersion":"gemini-2.0-flash"}` + "\n\n"
	chunk2 := `data: {"candidates":[{"content":{"parts":[{"functionCall":{"partialArgs":[{"jsonPath":"$.items[0].name","stringValue":"widget"}],"willContinue":true}}],"role":"model"}}],"modelVersion":"gemini-2.0-flash"}` + "\n\n"
	chunk3 := `data: {"candidates":[{"content":{"parts":[{"functionCall":{"partialArgs":[{"jsonPath":"$.items[1].id","numberValue":9}]}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":3,"totalTokenCount":8},"modelVersion":"gemini-2.0-flash"}` + "\n\n"
	stream := chunk1 + chunk2 + chunk3

	resp, toolCalls := parseGeminiStream(strings.NewReader(stream))
	require.NotNil(t, resp)
	require.Len(t, toolCalls, 1)
	assert.Equal(t, "create_order", toolCalls[0].Name)
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

	// items must be reconstructed as a JSON array of objects, not as
	// bracket-suffixed keys.
	var args struct {
		Items []struct {
			ID   float64 `json:"id"`
			Name string  `json:"name"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(parts[0].FunctionCall.Args, &args))
	require.Len(t, args.Items, 2)
	assert.InEpsilon(t, float64(7), args.Items[0].ID, 0.0001)
	assert.Equal(t, "widget", args.Items[0].Name)
	assert.InEpsilon(t, float64(9), args.Items[1].ID, 0.0001)
}

func TestParseGeminiStream_StreamingFunctionCallStringFragments(t *testing.T) {
	// Vertex AI splits a single string argument across multiple PartialArg
	// elements sharing a jsonPath, each with willContinue=true until the final
	// terminator (willContinue=false). The fragments must be concatenated, and
	// the trailing empty terminator must not clobber the accumulated value.
	chunk1 := `data: {"candidates":[{"content":{"parts":[{"functionCall":{"name":"set_country","partialArgs":[{"jsonPath":"$.country","stringValue":"US","willContinue":true}],"willContinue":true}}],"role":"model"}}],"modelVersion":"gemini-2.0-flash"}` + "\n\n"
	chunk2 := `data: {"candidates":[{"content":{"parts":[{"functionCall":{"partialArgs":[{"jsonPath":"$.country","stringValue":"A","willContinue":true}],"willContinue":true}}],"role":"model"}}],"modelVersion":"gemini-2.0-flash"}` + "\n\n"
	chunk3 := `data: {"candidates":[{"content":{"parts":[{"functionCall":{"partialArgs":[{"jsonPath":"$.country","stringValue":"","willContinue":false}]}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":3,"totalTokenCount":8},"modelVersion":"gemini-2.0-flash"}` + "\n\n"
	stream := chunk1 + chunk2 + chunk3

	resp, toolCalls := parseGeminiStream(strings.NewReader(stream))
	require.NotNil(t, resp)
	require.Len(t, toolCalls, 1)
	assert.Equal(t, "set_country", toolCalls[0].Name)
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

	var args map[string]any
	require.NoError(t, json.Unmarshal(parts[0].FunctionCall.Args, &args))
	assert.Equal(t, "USA", args["country"])
}

func TestParseGeminiStream_OversizedArrayIndex(t *testing.T) {
	// A malformed partialArgs path with an oversized array index must not
	// cause excessive allocation. The path is silently skipped while other
	// valid data in the same stream is still processed correctly.
	chunk1 := `data: {"candidates":[{"content":{"parts":[{"functionCall":{"name":"bad_func","partialArgs":[{"jsonPath":"$.items[1000000000].id","numberValue":1}],"willContinue":true}}],"role":"model"}}],"modelVersion":"gemini-2.0-flash"}` + "\n\n"
	// A valid second argument at a normal path.
	chunk2 := `data: {"candidates":[{"content":{"parts":[{"functionCall":{"partialArgs":[{"jsonPath":"$.name","stringValue":"ok"}]}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":3,"totalTokenCount":8},"modelVersion":"gemini-2.0-flash","responseId":"resp_oai"}` + "\n\n"
	stream := chunk1 + chunk2

	resp, toolCalls := parseGeminiStream(strings.NewReader(stream))

	require.NotNil(t, resp)
	require.Len(t, toolCalls, 1)
	assert.Equal(t, "bad_func", toolCalls[0].Name)
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
	assert.Equal(t, "bad_func", parts[0].FunctionCall.Name)

	// The oversized array index path is skipped, but the valid "name" path
	// should still be present in the reconstructed args.
	var args map[string]any
	require.NoError(t, json.Unmarshal(parts[0].FunctionCall.Args, &args))
	assert.Equal(t, "ok", args["name"])
	// "items" should not be present (oversized index was skipped).
	assert.Nil(t, args["items"])
}
