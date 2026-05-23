// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeSystemInstructions_NonEmpty(t *testing.T) {
	result := NormalizeSystemInstructions("You are a helpful assistant.")

	var parts []normalizedPart
	require.NoError(t, json.Unmarshal([]byte(result), &parts))
	require.Len(t, parts, 1)
	assert.Equal(t, "text", parts[0].Type)
	assert.Equal(t, "You are a helpful assistant.", parts[0].Content)
}

func TestNormalizeSystemInstructions_Empty(t *testing.T) {
	assert.Empty(t, NormalizeSystemInstructions(""))
}

func TestNormalizeToolDefinitions_OpenAIFormat(t *testing.T) {
	raw := json.RawMessage(`[{"type":"function","function":{"name":"get_weather","description":"Get weather","parameters":{"type":"object"}}}]`)
	result := NormalizeToolDefinitions(raw)

	var tools []normalizedTool
	require.NoError(t, json.Unmarshal([]byte(result), &tools))
	require.Len(t, tools, 1)
	assert.Equal(t, "function", tools[0].Type)
	assert.Equal(t, "get_weather", tools[0].Name)
	assert.Equal(t, "Get weather", tools[0].Description)
}

func TestNormalizeToolDefinitions_AnthropicFormat(t *testing.T) {
	raw := json.RawMessage(`[{"name":"search","description":"Search the web","input_schema":{"type":"object","properties":{"q":{"type":"string"}}}}]`)
	result := NormalizeToolDefinitions(raw)

	var tools []normalizedTool
	require.NoError(t, json.Unmarshal([]byte(result), &tools))
	require.Len(t, tools, 1)
	assert.Equal(t, "function", tools[0].Type)
	assert.Equal(t, "search", tools[0].Name)
	assert.Equal(t, "Search the web", tools[0].Description)
}

func TestNormalizeToolDefinitions_GeminiFormat(t *testing.T) {
	raw := json.RawMessage(`[{"functionDeclarations":[{"name":"fn1","description":"First"},{"name":"fn2","description":"Second"}]}]`)
	result := NormalizeToolDefinitions(raw)

	var tools []normalizedTool
	require.NoError(t, json.Unmarshal([]byte(result), &tools))
	require.Len(t, tools, 2)
	assert.Equal(t, "function", tools[0].Type)
	assert.Equal(t, "fn1", tools[0].Name)
	assert.Equal(t, "First", tools[0].Description)
	assert.Equal(t, "fn2", tools[1].Name)
	assert.Equal(t, "Second", tools[1].Description)
}

func TestNormalizeToolDefinitions_Empty(t *testing.T) {
	assert.Empty(t, NormalizeToolDefinitions(nil))
	assert.Empty(t, NormalizeToolDefinitions(json.RawMessage{}))
}

func TestNormalizeToolDefinitions_ParseFailure(t *testing.T) {
	invalid := json.RawMessage(`not json`)
	assert.Equal(t, "not json", NormalizeToolDefinitions(invalid))
}

func TestNormalizeToolDefinitions_InvalidItem(t *testing.T) {
	raw := json.RawMessage(`[123]`)
	result := NormalizeToolDefinitions(raw)
	assert.Equal(t, "[]", result)
}

func TestNormalizeToolDefinitions_DropsUnsupportedAnthropicType(t *testing.T) {
	raw := json.RawMessage(`[{"type":"computer_20241022","name":"computer","display_width_px":1024}]`)
	result := NormalizeToolDefinitions(raw)
	assert.Equal(t, "[]", result)
}

func TestNormalizeToolDefinitions_MixedValidInvalid(t *testing.T) {
	raw := json.RawMessage(`[{"type":"function","function":{"name":"valid"}},{"type":"computer_20241022","name":"computer"},123]`)
	result := NormalizeToolDefinitions(raw)

	var tools []normalizedTool
	require.NoError(t, json.Unmarshal([]byte(result), &tools))
	require.Len(t, tools, 1)
	assert.Equal(t, "function", tools[0].Type)
	assert.Equal(t, "valid", tools[0].Name)
}

func TestNormalizeToolDefinitions_PreservesFunctionType(t *testing.T) {
	raw := json.RawMessage(`[{"type":"function","function":{"name":"f","description":"d"}}]`)
	result := NormalizeToolDefinitions(raw)

	var tools []normalizedTool
	require.NoError(t, json.Unmarshal([]byte(result), &tools))
	require.Len(t, tools, 1)
	assert.Equal(t, "function", tools[0].Type)
	assert.Equal(t, "f", tools[0].Name)
}

func TestWrapTextAsInputMessage(t *testing.T) {
	result := wrapTextAsInputMessage("test input")

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	assert.Equal(t, "user", msgs[0].Role)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "text", msgs[0].Parts[0].Type)
	assert.Equal(t, "test input", msgs[0].Parts[0].Content)
}

func TestWrapTextAsOutputMessage(t *testing.T) {
	result := wrapTextAsOutputMessage("assistant", "response", "stop")

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	assert.Equal(t, "assistant", msgs[0].Role)
	assert.Equal(t, "stop", msgs[0].FinishReason)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "response", msgs[0].Parts[0].Content)
}
