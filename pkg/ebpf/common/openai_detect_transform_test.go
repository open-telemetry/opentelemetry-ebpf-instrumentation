// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/json"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
)

func buildOpenAIReqBytes(req GoOpenAIInfo) []byte {
	size := int(unsafe.Sizeof(req))
	b := (*[1 << 20]byte)(unsafe.Pointer(&req))[:size:size]
	out := make([]byte, size)
	copy(out, b)
	return out
}

func copyStringToArray(dst []uint8, src string) {
	copy(dst, []byte(src))
}

func TestReadGoOpenAIRequestIntoSpan_InputOutputMessages(t *testing.T) {
	var req GoOpenAIInfo

	// Set basic fields
	req.Type = 21 // EVENT_GO_OPENAI
	req.StartMonotimeNs = 1000
	req.EndMonotimeNs = 2000
	req.PromptTokens = 100
	req.CompletionTokens = 50

	// Set model fields
	copyStringToArray(req.RequestModel[:], "gpt-4o-mini")
	copyStringToArray(req.ResponseModel[:], "gpt-4o-mini-2024-07-18")
	copyStringToArray(req.ResponseId[:], "chatcmpl-test123")

	// Set input message (user role = 0)
	req.InputMessageRole = 0 // user
	copyStringToArray(req.InputMessageContent[:], "Hello, how are you?")

	// Set output message
	copyStringToArray(req.OutputMessageContent[:], "I am doing well, thank you!")

	record := &ringbuf.Record{RawSample: buildOpenAIReqBytes(req)}
	span, ignore, err := ReadGoOpenAIRequestIntoSpan(record)

	require.NoError(t, err)
	assert.False(t, ignore)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.OpenAI)

	ai := span.GenAI.OpenAI

	// Verify input messages
	assert.NotNil(t, ai.Request.Messages, "input messages should be populated")
	var inputMsgs []genAIMessage
	err = json.Unmarshal(ai.Request.Messages, &inputMsgs)
	require.NoError(t, err, "input messages should be valid JSON")
	require.Len(t, inputMsgs, 1)
	assert.Equal(t, "user", inputMsgs[0].Role)
	assert.Equal(t, "Hello, how are you?", inputMsgs[0].Content)

	// Verify output messages (choices) carry the OpenAI chat-completions
	// wire format expected by normalizeOpenAIChoices: an array of
	// {message: {role, content}, finish_reason} objects.
	assert.NotNil(t, ai.Choices, "output messages (choices) should be populated")
	var outputChoices []genAIChoice
	err = json.Unmarshal(ai.Choices, &outputChoices)
	require.NoError(t, err, "output choices should be valid JSON")
	require.Len(t, outputChoices, 1)
	assert.Equal(t, "assistant", outputChoices[0].Message.Role)
	assert.Equal(t, "I am doing well, thank you!", outputChoices[0].Message.Content)
	assert.Equal(t, "stop", outputChoices[0].FinishReason)

	// And it must be consumable by the canonical output normalizer.
	normalized := ai.GetOutput()
	assert.JSONEq(t,
		`[{"role":"assistant","parts":[{"type":"text","content":"I am doing well, thank you!"}],"finish_reason":"stop"}]`,
		normalized,
	)
}

func TestReadGoOpenAIRequestIntoSpan_SystemRole(t *testing.T) {
	var req GoOpenAIInfo

	req.Type = 21
	req.StartMonotimeNs = 1000
	req.EndMonotimeNs = 2000
	copyStringToArray(req.RequestModel[:], "gpt-4o")
	copyStringToArray(req.ResponseModel[:], "gpt-4o")
	copyStringToArray(req.ResponseId[:], "chatcmpl-sys")

	// Set input message with system role = 1
	req.InputMessageRole = 1 // system
	copyStringToArray(req.InputMessageContent[:], "You are a helpful assistant.")

	record := &ringbuf.Record{RawSample: buildOpenAIReqBytes(req)}
	span, _, err := ReadGoOpenAIRequestIntoSpan(record)

	require.NoError(t, err)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.OpenAI)

	var inputMsgs []genAIMessage
	err = json.Unmarshal(span.GenAI.OpenAI.Request.Messages, &inputMsgs)
	require.NoError(t, err)
	require.Len(t, inputMsgs, 1)
	assert.Equal(t, "system", inputMsgs[0].Role)
	assert.Equal(t, "You are a helpful assistant.", inputMsgs[0].Content)
}

func TestReadGoOpenAIRequestIntoSpan_EmptyMessages(t *testing.T) {
	var req GoOpenAIInfo

	req.Type = 21
	req.StartMonotimeNs = 1000
	req.EndMonotimeNs = 2000
	copyStringToArray(req.RequestModel[:], "gpt-4o-mini")
	copyStringToArray(req.ResponseModel[:], "gpt-4o-mini")
	copyStringToArray(req.ResponseId[:], "chatcmpl-empty")

	// Leave InputMessageContent and OutputMessageContent as zero (empty)
	req.InputMessageRole = 0

	record := &ringbuf.Record{RawSample: buildOpenAIReqBytes(req)}
	span, _, err := ReadGoOpenAIRequestIntoSpan(record)

	require.NoError(t, err)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.OpenAI)

	// When content is empty, messages should be nil
	assert.Nil(t, span.GenAI.OpenAI.Request.Messages, "empty input content should produce nil messages")
	assert.Nil(t, span.GenAI.OpenAI.Choices, "empty output content should produce nil choices")
}

func TestMarshalGenAIMessages(t *testing.T) {
	t.Run("non-empty content produces valid JSON array", func(t *testing.T) {
		result := marshalGenAIMessages("user", "Hello world")
		require.NotNil(t, result)

		var msgs []genAIMessage
		err := json.Unmarshal(result, &msgs)
		require.NoError(t, err)
		require.Len(t, msgs, 1)
		assert.Equal(t, "user", msgs[0].Role)
		assert.Equal(t, "Hello world", msgs[0].Content)
	})

	t.Run("empty content returns nil", func(t *testing.T) {
		result := marshalGenAIMessages("user", "")
		assert.Nil(t, result)
	})

	t.Run("assistant role", func(t *testing.T) {
		result := marshalGenAIMessages("assistant", "I can help with that.")
		require.NotNil(t, result)

		var msgs []genAIMessage
		err := json.Unmarshal(result, &msgs)
		require.NoError(t, err)
		require.Len(t, msgs, 1)
		assert.Equal(t, "assistant", msgs[0].Role)
		assert.Equal(t, "I can help with that.", msgs[0].Content)
	})
}

func TestMarshalGenAIChoices(t *testing.T) {
	t.Run("non-empty content produces openai choices wire format", func(t *testing.T) {
		result := marshalGenAIChoices("assistant", "Hello!", "stop")
		require.NotNil(t, result)

		var choices []genAIChoice
		err := json.Unmarshal(result, &choices)
		require.NoError(t, err)
		require.Len(t, choices, 1)
		assert.Equal(t, "assistant", choices[0].Message.Role)
		assert.Equal(t, "Hello!", choices[0].Message.Content)
		assert.Equal(t, "stop", choices[0].FinishReason)
	})

	t.Run("empty content returns nil", func(t *testing.T) {
		assert.Nil(t, marshalGenAIChoices("assistant", "", "stop"))
	})
}

func TestOpenAIRoleString(t *testing.T) {
	tests := []struct {
		role     uint8
		expected string
	}{
		{0, "user"},
		{1, "system"},
		{2, "assistant"},
		{3, "developer"},
		{4, "tool"},
		{5, "function"},
		{6, "user"},   // unknown defaults to user
		{255, "user"}, // unknown defaults to user
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, openAIRoleString(tt.role),
			"role %d should map to %q", tt.role, tt.expected)
	}
}
