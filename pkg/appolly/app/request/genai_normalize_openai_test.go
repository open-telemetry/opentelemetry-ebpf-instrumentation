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
	assert.Empty(t, normalizeOpenAIMessages(nil))
	assert.Empty(t, normalizeOpenAIMessages(json.RawMessage{}))
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
	assert.Empty(t, msgs[0].Parts[0].Content)
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
	assert.Empty(t, normalizeOpenAIOutput(ai))
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

func TestOpenAIContentToParts_TextArray(t *testing.T) {
	parts := openAIContentToParts(json.RawMessage(`[{"type":"text","text":"array content"}]`))
	require.Len(t, parts, 1)
	assert.Equal(t, "text", parts[0].Type)
	assert.Equal(t, "array content", parts[0].Content)
}

func TestOpenAIContentToParts_ImageURL(t *testing.T) {
	parts := openAIContentToParts(json.RawMessage(`[{"type":"image_url","image_url":{"url":"https://example.com/img.png","detail":"high"}}]`))
	require.Len(t, parts, 1)
	assert.Equal(t, "uri", parts[0].Type)
	assert.Equal(t, "https://example.com/img.png", parts[0].URI)
	assert.Equal(t, "image", parts[0].Modality)
	assert.Empty(t, parts[0].Content)
}

func TestOpenAIContentToParts_InputAudio(t *testing.T) {
	parts := openAIContentToParts(json.RawMessage(`[{"type":"input_audio","input_audio":{"data":"base64data","format":"wav"}}]`))
	require.Len(t, parts, 1)
	assert.Equal(t, "blob", parts[0].Type)
	assert.Equal(t, "base64data", parts[0].Content)
	assert.Equal(t, "audio", parts[0].Modality)
	assert.Equal(t, "audio/wav", parts[0].MimeType)
}

func TestOpenAIContentToParts_InputAudio_NoFormat(t *testing.T) {
	parts := openAIContentToParts(json.RawMessage(`[{"type":"input_audio","input_audio":{"data":"base64data"}}]`))
	require.Len(t, parts, 1)
	assert.Equal(t, "blob", parts[0].Type)
	assert.Equal(t, "base64data", parts[0].Content)
	assert.Equal(t, "audio", parts[0].Modality)
	assert.Empty(t, parts[0].MimeType)
}

func TestOpenAIContentToParts_FileByID(t *testing.T) {
	parts := openAIContentToParts(json.RawMessage(`[{"type":"file","file":{"file_id":"file_abc123"}}]`))
	require.Len(t, parts, 1)
	assert.Equal(t, "file", parts[0].Type)
	assert.Equal(t, "file_abc123", parts[0].FileID)
	assert.Equal(t, "file", parts[0].Modality)
}

func TestOpenAIContentToParts_FileByID_ImageFilename(t *testing.T) {
	parts := openAIContentToParts(json.RawMessage(`[{"type":"file","file":{"file_id":"file_abc123","filename":"photo.PNG"}}]`))
	require.Len(t, parts, 1)
	assert.Equal(t, "file", parts[0].Type)
	assert.Equal(t, "file_abc123", parts[0].FileID)
	assert.Equal(t, "image", parts[0].Modality)
}

func TestOpenAIContentToParts_FileByData(t *testing.T) {
	parts := openAIContentToParts(json.RawMessage(`[{"type":"file","file":{"file_data":"base64pdf","filename":"doc.pdf"}}]`))
	require.Len(t, parts, 1)
	assert.Equal(t, "blob", parts[0].Type)
	assert.Equal(t, "base64pdf", parts[0].Content)
	assert.Equal(t, "file", parts[0].Modality)
}

func TestOpenAIContentToParts_FileByData_AudioFilename(t *testing.T) {
	parts := openAIContentToParts(json.RawMessage(`[{"type":"file","file":{"file_data":"base64audio","filename":"clip.mp3"}}]`))
	require.Len(t, parts, 1)
	assert.Equal(t, "blob", parts[0].Type)
	assert.Equal(t, "base64audio", parts[0].Content)
	assert.Equal(t, "audio", parts[0].Modality)
}

func TestOpenAIContentToParts_Refusal(t *testing.T) {
	parts := openAIContentToParts(json.RawMessage(`[{"type":"refusal","refusal":"I cannot help with that."}]`))
	require.Len(t, parts, 1)
	assert.Equal(t, "text", parts[0].Type)
	assert.Equal(t, "I cannot help with that.", parts[0].Content)
}

func TestOpenAIContentToParts_Mixed(t *testing.T) {
	parts := openAIContentToParts(json.RawMessage(`[{"type":"text","text":"look at this"},{"type":"image_url","image_url":{"url":"https://x/y.png"}}]`))
	require.Len(t, parts, 2)
	assert.Equal(t, "text", parts[0].Type)
	assert.Equal(t, "look at this", parts[0].Content)
	assert.Equal(t, "uri", parts[1].Type)
	assert.Equal(t, "https://x/y.png", parts[1].URI)
	assert.Equal(t, "image", parts[1].Modality)
}

func TestOpenAIContentToParts_UnknownType(t *testing.T) {
	parts := openAIContentToParts(json.RawMessage(`[{"type":"video_url","text":"fallback"}]`))
	require.Len(t, parts, 1)
	assert.Equal(t, "video_url", parts[0].Type)
	assert.Equal(t, "fallback", parts[0].Content)
}

func TestOpenAIContentToParts_InvalidJSON(t *testing.T) {
	raw := json.RawMessage(`{"not":"an array"}`)
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

func TestNormalizeOpenAIOutput_ResponsesAPI_FunctionCall(t *testing.T) {
	ai := &VendorOpenAI{
		Output: json.RawMessage(`[{"type":"function_call","id":"fc_1","call_id":"call_abc","name":"get_weather","arguments":"{\"city\":\"sf\"}"}]`),
	}
	result := normalizeOpenAIOutput(ai)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	assert.Equal(t, "assistant", msgs[0].Role)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "tool_call", msgs[0].Parts[0].Type)
	assert.Equal(t, "call_abc", msgs[0].Parts[0].ID)
	assert.Equal(t, "get_weather", msgs[0].Parts[0].Name)
	assert.JSONEq(t, `"{\"city\":\"sf\"}"`, string(msgs[0].Parts[0].Arguments))
}

func TestNormalizeOpenAIOutput_ResponsesAPI_MixedItems(t *testing.T) {
	ai := &VendorOpenAI{
		Output: json.RawMessage(`[` +
			`{"type":"message","role":"assistant","status":"completed","content":[{"type":"text","text":"hello"}]},` +
			`{"type":"function_call","call_id":"call_1","name":"do_thing","arguments":"{}"}` +
			`]`),
	}
	result := normalizeOpenAIOutput(ai)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 2)
	// First: text message preserves order
	assert.Equal(t, "assistant", msgs[0].Role)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "text", msgs[0].Parts[0].Type)
	assert.Equal(t, "hello", msgs[0].Parts[0].Content)
	// Second: function_call follows
	assert.Equal(t, "assistant", msgs[1].Role)
	require.Len(t, msgs[1].Parts, 1)
	assert.Equal(t, "tool_call", msgs[1].Parts[0].Type)
	assert.Equal(t, "call_1", msgs[1].Parts[0].ID)
	assert.Equal(t, "do_thing", msgs[1].Parts[0].Name)
}

func TestNormalizeOpenAIOutput_ResponsesAPI_UnknownItemTypeDropped(t *testing.T) {
	ai := &VendorOpenAI{
		Output: json.RawMessage(`[{"type":"reasoning","id":"r1","summary":[]},{"type":"web_search_call","id":"ws1"}]`),
	}
	result := normalizeOpenAIOutput(ai)
	assert.Equal(t, "[]", result)
}

func TestNormalizeOpenAIOutput_ResponsesAPI_FunctionCallFallbackID(t *testing.T) {
	// When call_id is missing, fall back to id.
	ai := &VendorOpenAI{
		Output: json.RawMessage(`[{"type":"function_call","id":"fc_only","name":"do","arguments":"{}"}]`),
	}
	result := normalizeOpenAIOutput(ai)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "fc_only", msgs[0].Parts[0].ID)
}
