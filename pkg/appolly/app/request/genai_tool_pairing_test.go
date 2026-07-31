// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPairedToolCalls_OpenAI(t *testing.T) {
	messages := json.RawMessage(`[
		{"role":"user","content":"What is the weather in Boston?"},
		{"role":"assistant","content":null,"tool_calls":[
			{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"location\":\"Boston\"}"}}
		]},
		{"role":"tool","tool_call_id":"call_1","content":"Sunny, 72F"}
	]`)
	g := &GenAI{OpenAI: &VendorOpenAI{Request: OpenAIInput{Messages: messages}}}

	got := g.PairedToolCalls()
	require.Len(t, got, 1)
	assert.Equal(t, "call_1", got[0].ID)
	assert.Equal(t, "get_weather", got[0].Name)
	assert.JSONEq(t, `{"location":"Boston"}`, got[0].Arguments)
	assert.Equal(t, "Sunny, 72F", got[0].Result)
}

func TestPairedToolCalls_OpenAI_NoResultNoPair(t *testing.T) {
	// The result has not been sent back yet, so nothing is paired.
	messages := json.RawMessage(`[
		{"role":"user","content":"What is the weather in Boston?"},
		{"role":"assistant","content":null,"tool_calls":[
			{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"location\":\"Boston\"}"}}
		]}
	]`)
	g := &GenAI{OpenAI: &VendorOpenAI{Request: OpenAIInput{Messages: messages}}}
	assert.Empty(t, g.PairedToolCalls())
}

func TestPairedToolCalls_OpenAI_MultipleCalls(t *testing.T) {
	messages := json.RawMessage(`[
		{"role":"assistant","content":null,"tool_calls":[
			{"id":"call_1","function":{"name":"get_weather","arguments":"{\"city\":\"NYC\"}"}},
			{"id":"call_2","function":{"name":"get_time","arguments":"{\"tz\":\"UTC\"}"}}
		]},
		{"role":"tool","tool_call_id":"call_2","content":"12:00"},
		{"role":"tool","tool_call_id":"call_1","content":"Rainy"}
	]`)
	g := &GenAI{OpenAICompatible: &VendorOpenAI{Request: OpenAIInput{Messages: messages}}}

	got := g.PairedToolCalls()
	require.Len(t, got, 2)
	assert.Equal(t, "call_1", got[0].ID)
	assert.Equal(t, "Rainy", got[0].Result)
	assert.Equal(t, "call_2", got[1].ID)
	assert.Equal(t, "12:00", got[1].Result)
}

func TestPairedToolCalls_Ollama_PairByName(t *testing.T) {
	// Ollama omits tool call ids, so pairing falls back to tool_name.
	messages := json.RawMessage(`[
		{"role":"assistant","content":"","tool_calls":[
			{"function":{"name":"get_weather","arguments":{"location":"Berlin"}}}
		]},
		{"role":"tool","tool_name":"get_weather","content":"Cloudy"}
	]`)
	g := &GenAI{Ollama: &VendorOpenAI{Request: OpenAIInput{Messages: messages}}}

	got := g.PairedToolCalls()
	require.Len(t, got, 1)
	assert.Empty(t, got[0].ID)
	assert.Equal(t, "get_weather", got[0].Name)
	assert.JSONEq(t, `{"location":"Berlin"}`, got[0].Arguments)
	assert.Equal(t, "Cloudy", got[0].Result)
}

func TestPairedToolCalls_Anthropic(t *testing.T) {
	messages := json.RawMessage(`[
		{"role":"assistant","content":[
			{"type":"tool_use","id":"toolu_1","name":"get_weather","input":{"location":"Paris"}}
		]},
		{"role":"user","content":[
			{"type":"tool_result","tool_use_id":"toolu_1","content":"Windy"}
		]}
	]`)
	g := &GenAI{Anthropic: &VendorAnthropic{Input: AnthropicRequest{Messages: messages}}}

	got := g.PairedToolCalls()
	require.Len(t, got, 1)
	assert.Equal(t, "toolu_1", got[0].ID)
	assert.Equal(t, "get_weather", got[0].Name)
	assert.JSONEq(t, `{"location":"Paris"}`, got[0].Arguments)
	assert.Equal(t, "Windy", got[0].Result)
}

func TestPairedToolCalls_Gemini(t *testing.T) {
	contents := json.RawMessage(`[
		{"role":"model","parts":[
			{"functionCall":{"name":"get_weather","args":{"location":"Tokyo"}}}
		]},
		{"role":"user","parts":[
			{"functionResponse":{"name":"get_weather","response":{"temp":30}}}
		]}
	]`)
	g := &GenAI{Gemini: &VendorGemini{Input: GeminiRequest{Contents: contents}}}

	got := g.PairedToolCalls()
	require.Len(t, got, 1)
	assert.Empty(t, got[0].ID)
	assert.Equal(t, "get_weather", got[0].Name)
	assert.JSONEq(t, `{"location":"Tokyo"}`, got[0].Arguments)
	assert.JSONEq(t, `{"temp":30}`, got[0].Result)
}

func TestPairedToolCalls_NilAndEmpty(t *testing.T) {
	var g *GenAI
	assert.Nil(t, g.PairedToolCalls())
	assert.Nil(t, (&GenAI{}).PairedToolCalls())
	assert.Nil(t, (&GenAI{OpenAI: &VendorOpenAI{}}).PairedToolCalls())
}

func TestPairedToolCalls_NullArgumentsAndResult(t *testing.T) {
	// JSON null arguments or results are treated as absent.
	nullArgs := json.RawMessage(`[
		{"role":"assistant","content":null,"tool_calls":[
			{"id":"call_1","function":{"name":"get_weather","arguments":null}}
		]},
		{"role":"tool","tool_call_id":"call_1","content":"Sunny"}
	]`)
	g := &GenAI{OpenAI: &VendorOpenAI{Request: OpenAIInput{Messages: nullArgs}}}
	assert.Empty(t, g.PairedToolCalls())

	nullResult := json.RawMessage(`[
		{"role":"assistant","content":null,"tool_calls":[
			{"id":"call_1","function":{"name":"get_weather","arguments":"{\"location\":\"Boston\"}"}}
		]},
		{"role":"tool","tool_call_id":"call_1","content":null}
	]`)
	g = &GenAI{OpenAI: &VendorOpenAI{Request: OpenAIInput{Messages: nullResult}}}
	assert.Empty(t, g.PairedToolCalls())
}

func TestPairedToolCalls_OnlyLatestAssistantTurn(t *testing.T) {
	// A completed tool call from an earlier turn followed by a final
	// assistant answer must not be re-emitted on later requests.
	messages := json.RawMessage(`[
		{"role":"user","content":"What is the weather in Boston?"},
		{"role":"assistant","content":null,"tool_calls":[
			{"id":"call_1","function":{"name":"get_weather","arguments":"{\"location\":\"Boston\"}"}}
		]},
		{"role":"tool","tool_call_id":"call_1","content":"Sunny, 72F"},
		{"role":"assistant","content":"It is sunny and 72F in Boston."},
		{"role":"user","content":"Thanks!"}
	]`)
	g := &GenAI{OpenAI: &VendorOpenAI{Request: OpenAIInput{Messages: messages}}}
	assert.Empty(t, g.PairedToolCalls())
}

func TestPairedToolCalls_LatestTurnOnlyNewCall(t *testing.T) {
	// History retains an earlier completed tool call; only the latest
	// assistant turn's tool call is paired and emitted.
	messages := json.RawMessage(`[
		{"role":"assistant","content":null,"tool_calls":[
			{"id":"call_1","function":{"name":"get_weather","arguments":"{\"city\":\"NYC\"}"}}
		]},
		{"role":"tool","tool_call_id":"call_1","content":"Rainy"},
		{"role":"assistant","content":null,"tool_calls":[
			{"id":"call_2","function":{"name":"get_time","arguments":"{\"tz\":\"UTC\"}"}}
		]},
		{"role":"tool","tool_call_id":"call_2","content":"12:00"}
	]`)
	g := &GenAI{OpenAI: &VendorOpenAI{Request: OpenAIInput{Messages: messages}}}

	got := g.PairedToolCalls()
	require.Len(t, got, 1)
	assert.Equal(t, "call_2", got[0].ID)
	assert.Equal(t, "get_time", got[0].Name)
	assert.Equal(t, "12:00", got[0].Result)
}

func TestPairedToolCalls_Gemini_ParallelCallsByID(t *testing.T) {
	// Gemini 3 parallel calls carry ids; out-of-order responses must be
	// matched by id, not cross-matched by name.
	contents := json.RawMessage(`[
		{"role":"model","parts":[
			{"functionCall":{"id":"fc_1","name":"get_weather","args":{"location":"Tokyo"}}},
			{"functionCall":{"id":"fc_2","name":"get_weather","args":{"location":"Osaka"}}}
		]},
		{"role":"user","parts":[
			{"functionResponse":{"id":"fc_2","name":"get_weather","response":{"temp":25}}},
			{"functionResponse":{"id":"fc_1","name":"get_weather","response":{"temp":30}}}
		]}
	]`)
	g := &GenAI{Gemini: &VendorGemini{Input: GeminiRequest{Contents: contents}}}

	got := g.PairedToolCalls()
	require.Len(t, got, 2)
	assert.Equal(t, "fc_1", got[0].ID)
	assert.JSONEq(t, `{"location":"Tokyo"}`, got[0].Arguments)
	assert.JSONEq(t, `{"temp":30}`, got[0].Result)
	assert.Equal(t, "fc_2", got[1].ID)
	assert.JSONEq(t, `{"location":"Osaka"}`, got[1].Arguments)
	assert.JSONEq(t, `{"temp":25}`, got[1].Result)
}

func TestPairedToolCalls_Anthropic_IsError(t *testing.T) {
	// A tool_result flagged is_error pairs the call as failed and omits
	// the success-only result payload.
	messages := json.RawMessage(`[
		{"role":"assistant","content":[
			{"type":"tool_use","id":"toolu_1","name":"get_weather","input":{"location":"Paris"}}
		]},
		{"role":"user","content":[
			{"type":"tool_result","tool_use_id":"toolu_1","content":"upstream timeout","is_error":true}
		]}
	]`)
	g := &GenAI{Anthropic: &VendorAnthropic{Input: AnthropicRequest{Messages: messages}}}

	got := g.PairedToolCalls()
	require.Len(t, got, 1)
	assert.Equal(t, "toolu_1", got[0].ID)
	assert.True(t, got[0].IsError)
	assert.Empty(t, got[0].Result)
	assert.JSONEq(t, `{"location":"Paris"}`, got[0].Arguments)
}

func TestPairedToolCalls_OpenAIResponses(t *testing.T) {
	// The Responses API keeps calls and results as input items keyed by
	// call_id, not in messages.
	items := json.RawMessage(`[
		{"type":"message","role":"user","content":"What is the weather in Boston?"},
		{"type":"function_call","call_id":"call_1","name":"get_weather","arguments":"{\"location\":\"Boston\"}"},
		{"type":"function_call_output","call_id":"call_1","output":"Sunny, 72F"}
	]`)
	g := &GenAI{OpenAI: &VendorOpenAI{APIType: "responses", Request: OpenAIInput{InputItems: items}}}

	got := g.PairedToolCalls()
	require.Len(t, got, 1)
	assert.Equal(t, "call_1", got[0].ID)
	assert.Equal(t, "get_weather", got[0].Name)
	assert.JSONEq(t, `{"location":"Boston"}`, got[0].Arguments)
	assert.Equal(t, "Sunny, 72F", got[0].Result)
}

func TestPairedToolCalls_OpenAIResponses_CompletedTurnNotReEmitted(t *testing.T) {
	// A final assistant message after the call means the turn concluded, so
	// retained history must not re-emit it.
	items := json.RawMessage(`[
		{"type":"function_call","call_id":"call_1","name":"get_weather","arguments":"{\"location\":\"Boston\"}"},
		{"type":"function_call_output","call_id":"call_1","output":"Sunny, 72F"},
		{"type":"message","role":"assistant","content":"It is sunny in Boston."}
	]`)
	g := &GenAI{OpenAI: &VendorOpenAI{APIType: "responses", Request: OpenAIInput{InputItems: items}}}
	assert.Empty(t, g.PairedToolCalls())
}

func TestPairedToolCalls_OpenAIResponses_SequentialLatestOnly(t *testing.T) {
	// An earlier completed call is retained; only the latest call is emitted.
	items := json.RawMessage(`[
		{"type":"function_call","call_id":"call_1","name":"get_weather","arguments":"{\"city\":\"NYC\"}"},
		{"type":"function_call_output","call_id":"call_1","output":"Rainy"},
		{"type":"function_call","call_id":"call_2","name":"get_time","arguments":"{\"tz\":\"UTC\"}"},
		{"type":"function_call_output","call_id":"call_2","output":"12:00"}
	]`)
	g := &GenAI{OpenAI: &VendorOpenAI{APIType: "responses", Request: OpenAIInput{InputItems: items}}}

	got := g.PairedToolCalls()
	require.Len(t, got, 1)
	assert.Equal(t, "call_2", got[0].ID)
	assert.Equal(t, "get_time", got[0].Name)
	assert.Equal(t, "12:00", got[0].Result)
}
