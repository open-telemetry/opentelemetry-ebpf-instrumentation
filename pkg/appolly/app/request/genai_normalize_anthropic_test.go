// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeAnthropicInput_TextContent(t *testing.T) {
	input := json.RawMessage(`[{"role":"user","content":"Hello Claude"}]`)
	result := NormalizeAnthropicInput(input)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	assert.Equal(t, "user", msgs[0].Role)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "text", msgs[0].Parts[0].Type)
	assert.Equal(t, "Hello Claude", msgs[0].Parts[0].Content)
}

func TestNormalizeAnthropicInput_ContentBlocks(t *testing.T) {
	input := json.RawMessage(`[{"role":"user","content":[{"type":"text","text":"What is this?"},{"type":"text","text":"Second block"}]}]`)
	result := NormalizeAnthropicInput(input)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	require.Len(t, msgs[0].Parts, 2)
	assert.Equal(t, "What is this?", msgs[0].Parts[0].Content)
	assert.Equal(t, "Second block", msgs[0].Parts[1].Content)
}

func TestNormalizeAnthropicInput_ToolUseBlock(t *testing.T) {
	input := json.RawMessage(`[{"role":"assistant","content":[{"type":"tool_use","id":"tu_1","name":"calculator","input":{"expr":"2+2"}}]}]`)
	result := NormalizeAnthropicInput(input)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "tool_call", msgs[0].Parts[0].Type)
	assert.Equal(t, "tu_1", msgs[0].Parts[0].ID)
	assert.Equal(t, "calculator", msgs[0].Parts[0].Name)
}

func TestNormalizeAnthropicInput_ToolResultBlock(t *testing.T) {
	input := json.RawMessage(`[{"role":"user","content":[{"type":"tool_result","tool_use_id":"tu_1","content":"4"}]}]`)
	result := NormalizeAnthropicInput(input)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "tool_call_response", msgs[0].Parts[0].Type)
	assert.Equal(t, "tu_1", msgs[0].Parts[0].ID)
	assert.Equal(t, "4", msgs[0].Parts[0].Response)
}

func TestNormalizeAnthropicInput_ThinkingBlock(t *testing.T) {
	input := json.RawMessage(`[{"role":"assistant","content":[{"type":"thinking","thinking":"Let me reason about this..."}]}]`)
	result := NormalizeAnthropicInput(input)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "reasoning", msgs[0].Parts[0].Type)
	assert.Equal(t, "Let me reason about this...", msgs[0].Parts[0].Content)
}

func TestNormalizeAnthropicInput_Empty(t *testing.T) {
	assert.Empty(t, NormalizeAnthropicInput(nil))
	assert.Empty(t, NormalizeAnthropicInput(json.RawMessage{}))
}

func TestNormalizeAnthropicInput_ParseFailure(t *testing.T) {
	invalid := json.RawMessage(`not json`)
	assert.Equal(t, "not json", NormalizeAnthropicInput(invalid))
}

func TestNormalizeAnthropicInput_StringContent(t *testing.T) {
	input := json.RawMessage(`[{"role":"user","content":"plain string"}]`)
	result := NormalizeAnthropicInput(input)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "text", msgs[0].Parts[0].Type)
	assert.Equal(t, "plain string", msgs[0].Parts[0].Content)
}

func TestNormalizeAnthropicInput_UnknownBlockType(t *testing.T) {
	input := json.RawMessage(`[{"role":"assistant","content":[{"type":"image","text":""}]}]`)
	result := NormalizeAnthropicInput(input)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "image", msgs[0].Parts[0].Type)
}

func TestNormalizeAnthropicOutput_TextBlocks(t *testing.T) {
	resp := &AnthropicResponse{
		Role:       "assistant",
		Content:    json.RawMessage(`[{"type":"text","text":"Hello!"}]`),
		StopReason: "end_turn",
	}
	result := NormalizeAnthropicOutput(resp)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	assert.Equal(t, "assistant", msgs[0].Role)
	assert.Equal(t, "end_turn", msgs[0].FinishReason)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "text", msgs[0].Parts[0].Type)
	assert.Equal(t, "Hello!", msgs[0].Parts[0].Content)
}

func TestNormalizeAnthropicOutput_ToolUse(t *testing.T) {
	resp := &AnthropicResponse{
		Role:       "assistant",
		Content:    json.RawMessage(`[{"type":"tool_use","id":"tu_2","name":"search","input":{"q":"test"}}]`),
		StopReason: "tool_use",
	}
	result := NormalizeAnthropicOutput(resp)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "tool_call", msgs[0].Parts[0].Type)
	assert.Equal(t, "tu_2", msgs[0].Parts[0].ID)
	assert.Equal(t, "search", msgs[0].Parts[0].Name)
}

func TestNormalizeAnthropicOutput_Thinking(t *testing.T) {
	resp := &AnthropicResponse{
		Role:       "assistant",
		Content:    json.RawMessage(`[{"type":"thinking","thinking":"reasoning here"},{"type":"text","text":"final answer"}]`),
		StopReason: "end_turn",
	}
	result := NormalizeAnthropicOutput(resp)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	require.Len(t, msgs[0].Parts, 2)
	assert.Equal(t, "reasoning", msgs[0].Parts[0].Type)
	assert.Equal(t, "reasoning here", msgs[0].Parts[0].Content)
	assert.Equal(t, "text", msgs[0].Parts[1].Type)
	assert.Equal(t, "final answer", msgs[0].Parts[1].Content)
}

func TestNormalizeAnthropicOutput_Empty(t *testing.T) {
	resp := &AnthropicResponse{Role: "assistant"}
	assert.Empty(t, NormalizeAnthropicOutput(resp))
}

func TestNormalizeAnthropicOutput_UnmarshalFailure(t *testing.T) {
	resp := &AnthropicResponse{
		Role:       "assistant",
		Content:    json.RawMessage(`not valid json`),
		StopReason: "end_turn",
	}
	result := NormalizeAnthropicOutput(resp)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	assert.Equal(t, "assistant", msgs[0].Role)
	assert.Equal(t, "end_turn", msgs[0].FinishReason)
	assert.Equal(t, "not valid json", msgs[0].Parts[0].Content)
}

func TestExtractToolResultContent_String(t *testing.T) {
	result := extractToolResultContent(json.RawMessage(`"hello"`))
	assert.Equal(t, "hello", result)
}

func TestExtractToolResultContent_Object(t *testing.T) {
	result := extractToolResultContent(json.RawMessage(`{"key":"value"}`))
	assert.NotNil(t, result)
}

func TestExtractToolResultContent_Empty(t *testing.T) {
	assert.Nil(t, extractToolResultContent(nil))
	assert.Nil(t, extractToolResultContent(json.RawMessage{}))
}

func TestAnthropicContentToParts_Empty(t *testing.T) {
	assert.Nil(t, anthropicContentToParts(nil))
	assert.Nil(t, anthropicContentToParts(json.RawMessage{}))
}

func TestAnthropicContentToParts_InvalidJSON(t *testing.T) {
	parts := anthropicContentToParts(json.RawMessage(`{not parseable as string or array`))
	require.Len(t, parts, 1)
	assert.Equal(t, "text", parts[0].Type)
	assert.Equal(t, "{not parseable as string or array", parts[0].Content)
}
