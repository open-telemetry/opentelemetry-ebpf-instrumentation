// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeBedrockOutput_TextBlocks(t *testing.T) {
	resp := &BedrockResponse{
		Content:    json.RawMessage(`[{"type":"text","text":"eBPF is a kernel technology."}]`),
		StopReason: "end_turn",
	}
	result := NormalizeBedrockOutput(resp)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	assert.Equal(t, "assistant", msgs[0].Role)
	assert.Equal(t, "end_turn", msgs[0].FinishReason)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "text", msgs[0].Parts[0].Type)
	assert.Equal(t, "eBPF is a kernel technology.", msgs[0].Parts[0].Content)
}

func TestNormalizeBedrockOutput_ToolUseBlocks(t *testing.T) {
	resp := &BedrockResponse{
		Content:    json.RawMessage(`[{"type":"tool_use","id":"tu_1","name":"lookup","input":{"key":"val"}}]`),
		StopReason: "tool_use",
	}
	result := NormalizeBedrockOutput(resp)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "tool_call", msgs[0].Parts[0].Type)
	assert.Equal(t, "tu_1", msgs[0].Parts[0].ID)
	assert.Equal(t, "lookup", msgs[0].Parts[0].Name)
}

func TestNormalizeBedrockOutput_MixedBlocks(t *testing.T) {
	resp := &BedrockResponse{
		Content:    json.RawMessage(`[{"type":"text","text":"thinking..."},{"type":"tool_use","id":"tu_2","name":"calc","input":{"x":1}}]`),
		StopReason: "tool_use",
	}
	result := NormalizeBedrockOutput(resp)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	require.Len(t, msgs[0].Parts, 2)
	assert.Equal(t, "text", msgs[0].Parts[0].Type)
	assert.Equal(t, "tool_call", msgs[0].Parts[1].Type)
}

func TestNormalizeBedrockOutput_Empty(t *testing.T) {
	resp := &BedrockResponse{}
	assert.Empty(t, NormalizeBedrockOutput(resp))
}

func TestNormalizeBedrockOutput_UnmarshalFailure(t *testing.T) {
	resp := &BedrockResponse{
		Content:    json.RawMessage(`not valid json`),
		StopReason: "end_turn",
	}
	result := NormalizeBedrockOutput(resp)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	assert.Equal(t, "assistant", msgs[0].Role)
	assert.Equal(t, "end_turn", msgs[0].FinishReason)
	assert.Equal(t, "not valid json", msgs[0].Parts[0].Content)
}

func TestNormalizeBedrockOutput_UnknownBlockType(t *testing.T) {
	resp := &BedrockResponse{
		Content:    json.RawMessage(`[{"type":"custom","text":"custom content"}]`),
		StopReason: "end_turn",
	}
	result := NormalizeBedrockOutput(resp)

	var msgs []normalizedMessage
	require.NoError(t, json.Unmarshal([]byte(result), &msgs))
	require.Len(t, msgs, 1)
	require.Len(t, msgs[0].Parts, 1)
	assert.Equal(t, "custom", msgs[0].Parts[0].Type)
	assert.Equal(t, "custom content", msgs[0].Parts[0].Content)
}
