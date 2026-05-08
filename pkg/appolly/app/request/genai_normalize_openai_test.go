// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeOpenAIMessages_Valid(t *testing.T) {
	input := json.RawMessage(`[{"role":"user","content":"Hello"},{"role":"assistant","content":"Hi there"}]`)
	result := normalizeOpenAIMessages(input)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 2)

	assert.Equal(t, "user", msgs[0].Role)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "text", msgs[0].Parts[0].Type)
	assert.Equal(t, "Hello", msgs[0].Parts[0].Content)

	assert.Equal(t, "assistant", msgs[1].Role)
	require.Len(t, msgs[1].Parts, 1)
	assert.Equal(t, "text", msgs[1].Parts[0].Type)
	assert.Equal(t, "Hi there", msgs[1].Parts[0].Content)
}

func TestNormalizeOpenAIMessages_Empty(t *testing.T) {
	assert.Equal(t, "", normalizeOpenAIMessages(nil))
	assert.Equal(t, "", normalizeOpenAIMessages(json.RawMessage{}))
}

func TestNormalizeOpenAIMessages_ParseFailure(t *testing.T) {
	invalid := json.RawMessage(`not valid json`)
	result := normalizeOpenAIMessages(invalid)
	assert.Equal(t, "not valid json", result)
}

func TestNormalizeOpenAIMessages_WithToolCalls(t *testing.T) {
	input := json.RawMessage(`[{"role":"assistant","content":"","tool_calls":[{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"London\"}"}}]}]`)
	result := normalizeOpenAIMessages(input)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	assert.Equal(t, "assistant", msgs[0].Role)
	require.Len(t, msgs[0].Parts, 2)

	assert.Equal(t, "text", msgs[0].Parts[0].Type)
	assert.Equal(t, "tool_call", msgs[0].Parts[1].Type)
	assert.Equal(t, "call_1", msgs[0].Parts[1].ID)
	assert.Equal(t, "get_weather", msgs[0].Parts[1].Name)
}

func TestNormalizeOpenAIMessages_ToolCallID(t *testing.T) {
	input := json.RawMessage(`[{"role":"tool","content":"sunny","tool_call_id":"call_1"}]`)
	result := normalizeOpenAIMessages(input)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	assert.Equal(t, "tool", msgs[0].Role)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "tool_call_response", msgs[0].Parts[0].Type)
	assert.Equal(t, "call_1", msgs[0].Parts[0].ID)
	assert.Equal(t, "sunny", msgs[0].Parts[0].Response)
}

func TestNormalizeOpenAIMessages_NullContent(t *testing.T) {
	input := json.RawMessage(`[{"role":"assistant","content":null}]`)
	result := normalizeOpenAIMessages(input)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	assert.Equal(t, "assistant", msgs[0].Role)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "text", msgs[0].Parts[0].Type)
	assert.Equal(t, "", msgs[0].Parts[0].Content)
}

func TestNormalizeOpenAIOutput_Choices(t *testing.T) {
	ai := &VendorOpenAI{
		Choices: json.RawMessage(`[{"message":{"role":"assistant","content":"answer"},"finish_reason":"stop"}]`),
	}
	result := normalizeOpenAIOutput(ai)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	assert.Equal(t, "assistant", msgs[0].Role)
	assert.Equal(t, "stop", msgs[0].FinishReason)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "answer", msgs[0].Parts[0].Content)
}

func TestNormalizeOpenAIOutput_ResponsesAPI(t *testing.T) {
	ai := &VendorOpenAI{
		Output: json.RawMessage(`[{"role":"assistant","status":"completed","content":[{"type":"text","text":"response text"}]}]`),
	}
	result := normalizeOpenAIOutput(ai)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	assert.Equal(t, "assistant", msgs[0].Role)
	assert.Equal(t, "completed", msgs[0].FinishReason)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "response text", msgs[0].Parts[0].Content)
}

func TestNormalizeOpenAIOutput_Empty(t *testing.T) {
	ai := &VendorOpenAI{}
	assert.Equal(t, "", normalizeOpenAIOutput(ai))
}

func TestNormalizeOpenAIOutput_Items(t *testing.T) {
	items := json.RawMessage(`[{"id":"item_1"}]`)
	ai := &VendorOpenAI{Items: items}
	assert.Equal(t, string(items), normalizeOpenAIOutput(ai))
}

func TestNormalizeOpenAIOutput_Data(t *testing.T) {
	data := json.RawMessage(`[{"object":"embedding"}]`)
	ai := &VendorOpenAI{Data: data}
	assert.Equal(t, string(data), normalizeOpenAIOutput(ai))
}

func TestNormalizeOpenAIChoices_MultipleChoices(t *testing.T) {
	raw := json.RawMessage(`[{"message":{"role":"assistant","content":"first"},"finish_reason":"stop"},{"message":{"role":"assistant","content":"second"},"finish_reason":"length"}]`)
	result := normalizeOpenAIChoices(raw)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 2)
	assert.Equal(t, "first", msgs[0].Parts[0].Content)
	assert.Equal(t, "stop", msgs[0].FinishReason)
	assert.Equal(t, "second", msgs[1].Parts[0].Content)
	assert.Equal(t, "length", msgs[1].FinishReason)
}

func TestNormalizeOpenAIChoices_WithToolCalls(t *testing.T) {
	raw := json.RawMessage(`[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"tc1","type":"function","function":{"name":"search","arguments":"{}"}}]},"finish_reason":"tool_calls"}]`)
	result := normalizeOpenAIChoices(raw)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	assert.Equal(t, "tool_calls", msgs[0].FinishReason)
	require.Len(t, msgs[0].Parts, 2)
	assert.Equal(t, "text", msgs[0].Parts[0].Type)
	assert.Equal(t, "tool_call", msgs[0].Parts[1].Type)
	assert.Equal(t, "tc1", msgs[0].Parts[1].ID)
	assert.Equal(t, "search", msgs[0].Parts[1].Name)
}

func TestNormalizeOpenAIChoices_ParseFailure(t *testing.T) {
	raw := json.RawMessage(`invalid`)
	assert.Equal(t, "invalid", normalizeOpenAIChoices(raw))
}

func TestOpenAIContentToParts_String(t *testing.T) {
	parts := openAIContentToParts(json.RawMessage(`"hello world"`))
	require.Len(t, parts, 1)
	assert.Equal(t, "text", parts[0].Type)
	assert.Equal(t, "hello world", parts[0].Content)
}

func TestOpenAIContentToParts_NonString(t *testing.T) {
	raw := json.RawMessage(`[{"type":"text","text":"array content"}]`)
	parts := openAIContentToParts(raw)
	require.Len(t, parts, 1)
	assert.Equal(t, "text", parts[0].Type)
	assert.Equal(t, string(raw), parts[0].Content)
}

func TestOpenAIContentToParts_Empty(t *testing.T) {
	assert.Nil(t, openAIContentToParts(nil))
	assert.Nil(t, openAIContentToParts(json.RawMessage{}))
}

func TestOpenAIToolCallsToParts_Valid(t *testing.T) {
	raw := json.RawMessage(`[{"id":"c1","type":"function","function":{"name":"fn1","arguments":"{\"x\":1}"}},{"id":"c2","type":"function","function":{"name":"fn2","arguments":"{}"}}]`)
	parts := openAIToolCallsToParts(raw)
	require.Len(t, parts, 2)
	assert.Equal(t, "tool_call", parts[0].Type)
	assert.Equal(t, "c1", parts[0].ID)
	assert.Equal(t, "fn1", parts[0].Name)
	assert.Equal(t, "tool_call", parts[1].Type)
	assert.Equal(t, "c2", parts[1].ID)
	assert.Equal(t, "fn2", parts[1].Name)
}

func TestOpenAIToolCallsToParts_ParseFailure(t *testing.T) {
	assert.Nil(t, openAIToolCallsToParts(json.RawMessage(`not json`)))
}

func TestNormalizeOpenAIResponsesOutput_ParseFailure(t *testing.T) {
	raw := json.RawMessage(`bad data`)
	assert.Equal(t, "bad data", normalizeOpenAIResponsesOutput(raw))
}
