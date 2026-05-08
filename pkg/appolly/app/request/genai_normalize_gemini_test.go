// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeGeminiInput_TextParts(t *testing.T) {
	input := json.RawMessage(`[{"role":"user","parts":[{"text":"Hello Gemini"}]}]`)
	result := normalizeGeminiInput(input)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	assert.Equal(t, "user", msgs[0].Role)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "text", msgs[0].Parts[0].Type)
	assert.Equal(t, "Hello Gemini", msgs[0].Parts[0].Content)
}

func TestNormalizeGeminiInput_FunctionCall(t *testing.T) {
	input := json.RawMessage(`[{"role":"model","parts":[{"functionCall":{"name":"get_weather","args":{"city":"Paris"}}}]}]`)
	result := normalizeGeminiInput(input)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "tool_call", msgs[0].Parts[0].Type)
	assert.Equal(t, "get_weather", msgs[0].Parts[0].Name)
}

func TestNormalizeGeminiInput_FunctionResponse(t *testing.T) {
	input := json.RawMessage(`[{"role":"function","parts":[{"functionResponse":{"name":"get_weather","response":{"temp":20}}}]}]`)
	result := normalizeGeminiInput(input)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "tool_call_response", msgs[0].Parts[0].Type)
	assert.Equal(t, "get_weather", msgs[0].Parts[0].Name)
}

func TestNormalizeGeminiInput_Empty(t *testing.T) {
	assert.Empty(t, normalizeGeminiInput(nil))
	assert.Empty(t, normalizeGeminiInput(json.RawMessage{}))
}

func TestNormalizeGeminiInput_ParseFailure(t *testing.T) {
	invalid := json.RawMessage(`not json`)
	assert.Equal(t, "not json", normalizeGeminiInput(invalid))
}

func TestNormalizeGeminiInput_MultipleParts(t *testing.T) {
	input := json.RawMessage(`[{"role":"user","parts":[{"text":"First"},{"text":"Second"}]}]`)
	result := normalizeGeminiInput(input)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	require.Len(t, msgs[0].Parts, 2)
	assert.Equal(t, "First", msgs[0].Parts[0].Content)
	assert.Equal(t, "Second", msgs[0].Parts[1].Content)
}

func TestNormalizeGeminiOutput_WithCandidates(t *testing.T) {
	resp := &GeminiResponse{
		Candidates: []GeminiCandidate{
			{
				Content:      &GeminiContent{Role: "model", Parts: json.RawMessage(`[{"text":"Generated text"}]`)},
				FinishReason: "STOP",
			},
		},
	}
	result := normalizeGeminiOutput(resp)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	assert.Equal(t, "model", msgs[0].Role)
	assert.Equal(t, "STOP", msgs[0].FinishReason)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "text", msgs[0].Parts[0].Type)
	assert.Equal(t, "Generated text", msgs[0].Parts[0].Content)
}

func TestNormalizeGeminiOutput_FunctionCallInCandidate(t *testing.T) {
	resp := &GeminiResponse{
		Candidates: []GeminiCandidate{
			{
				Content:      &GeminiContent{Role: "model", Parts: json.RawMessage(`[{"functionCall":{"name":"search","args":{"q":"test"}}}]`)},
				FinishReason: "STOP",
			},
		},
	}
	result := normalizeGeminiOutput(resp)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "tool_call", msgs[0].Parts[0].Type)
	assert.Equal(t, "search", msgs[0].Parts[0].Name)
}

func TestNormalizeGeminiOutput_EmptyCandidates(t *testing.T) {
	resp := &GeminiResponse{}
	assert.Empty(t, normalizeGeminiOutput(resp))
}

func TestNormalizeGeminiOutput_NilContent(t *testing.T) {
	resp := &GeminiResponse{
		Candidates: []GeminiCandidate{{FinishReason: "STOP"}},
	}
	result := normalizeGeminiOutput(resp)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	assert.Equal(t, "STOP", msgs[0].FinishReason)
	assert.Empty(t, msgs[0].Parts)
}

func TestNormalizeGeminiParts_Valid(t *testing.T) {
	raw := json.RawMessage(`[{"text":"hello"},{"functionCall":{"name":"fn","args":{}}}]`)
	result := normalizeGeminiParts(raw)

	var parts []normalizedPart
	require.NoError(t, json.Unmarshal([]byte(result), &parts))
	require.Len(t, parts, 2)
	assert.Equal(t, "text", parts[0].Type)
	assert.Equal(t, "hello", parts[0].Content)
	assert.Equal(t, "tool_call", parts[1].Type)
	assert.Equal(t, "fn", parts[1].Name)
}

func TestNormalizeGeminiParts_Empty(t *testing.T) {
	assert.Empty(t, normalizeGeminiParts(nil))
	assert.Empty(t, normalizeGeminiParts(json.RawMessage{}))
}

func TestNormalizeGeminiParts_ParseFailure(t *testing.T) {
	invalid := json.RawMessage(`invalid`)
	assert.Equal(t, "invalid", normalizeGeminiParts(invalid))
}

func TestGeminiPartToNormalized_TextOnly(t *testing.T) {
	p := geminiPart{Text: "some text"}
	np := geminiPartToNormalized(p)
	assert.Equal(t, "text", np.Type)
	assert.Equal(t, "some text", np.Content)
}

func TestGeminiPartToNormalized_FunctionCallWithEmptyArgs(t *testing.T) {
	p := geminiPart{FunctionCall: &geminiFuncCall{Name: "fn"}}
	np := geminiPartToNormalized(p)
	assert.Equal(t, "tool_call", np.Type)
	assert.Equal(t, "fn", np.Name)
	assert.Nil(t, np.Arguments)
}

func TestGeminiPartToNormalized_FunctionResponseEmptyResponse(t *testing.T) {
	p := geminiPart{FunctionResponse: &geminiFuncResp{Name: "fn"}}
	np := geminiPartToNormalized(p)
	assert.Equal(t, "tool_call_response", np.Type)
	assert.Equal(t, "fn", np.Name)
	assert.Nil(t, np.Response)
}
