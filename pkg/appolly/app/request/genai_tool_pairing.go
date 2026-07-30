// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"bytes"
	"encoding/json"
	"slices"
)

// PairedToolCalls extracts tool calls from the request message history. A
// tool call result only appears in a follow-up request as a tool-role
// message, so pairing over the request messages puts arguments and result on
// the same execute_tool span. Pairing is scoped to the most recent
// assistant/model message so that clients retaining the full conversation do
// not re-emit previously completed tool calls on later requests. Only fully
// paired tool calls are returned.
func (g *GenAI) PairedToolCalls() []ToolCall {
	if g == nil {
		return nil
	}
	switch {
	case g.OpenAI != nil:
		return pairOpenAIToolCalls(g.OpenAI.Request.Messages)
	case g.OpenAICompatible != nil:
		return pairOpenAIToolCalls(g.OpenAICompatible.Request.Messages)
	case g.Qwen != nil:
		return pairOpenAIToolCalls(g.Qwen.Request.Messages)
	case g.Ollama != nil:
		return pairOpenAIToolCalls(g.Ollama.Request.Messages)
	case g.Anthropic != nil:
		return pairAnthropicToolCalls(g.Anthropic.Input.Messages)
	case g.Gemini != nil:
		return pairGeminiToolCalls(g.Gemini.Input.Contents)
	default:
		return nil
	}
}

type pendingToolCall struct {
	id   string
	name string
	args json.RawMessage
}

type pendingToolResult struct {
	id      string
	name    string
	result  json.RawMessage
	isError bool
}

// pairToolCalls matches assistant tool calls to tool results by tool call
// id, falling back to the tool name when ids are absent. Absent or JSON null
// arguments and results are treated as missing. Results the provider flagged
// as failed keep the pairing but omit the success-only result payload.
func pairToolCalls(calls []pendingToolCall, results []pendingToolResult) []ToolCall {
	results = slices.DeleteFunc(results, func(r pendingToolResult) bool {
		return emptyJSON(r.result) && !r.isError
	})
	if len(calls) == 0 || len(results) == 0 {
		return nil
	}
	used := make([]bool, len(results))
	var out []ToolCall
	for i := range calls {
		c := &calls[i]
		if emptyJSON(c.args) {
			continue
		}
		idx := matchToolResult(c, results, used)
		if idx < 0 {
			continue
		}
		used[idx] = true

		tc := ToolCall{
			ID:        c.id,
			Name:      c.name,
			Arguments: jsonRawToAttrString(c.args),
			IsError:   results[idx].isError,
		}
		if !tc.IsError {
			tc.Result = jsonRawToAttrString(results[idx].result)
		}
		out = append(out, tc)
	}
	return out
}

func matchToolResult(c *pendingToolCall, results []pendingToolResult, used []bool) int {
	if c.id != "" {
		for i := range results {
			if !used[i] && results[i].id == c.id {
				return i
			}
		}
	}
	if c.name != "" {
		for i := range results {
			// Match by name only when one side lacks an id, to avoid
			// cross-matching calls whose ids simply differ.
			if used[i] || results[i].name != c.name {
				continue
			}
			if c.id == "" || results[i].id == "" {
				return i
			}
		}
	}
	return -1
}

// emptyJSON reports whether raw is absent or a JSON null literal.
func emptyJSON(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

// jsonRawToAttrString renders a raw JSON value as an attribute string: JSON
// string values (e.g. OpenAI's stringified arguments) are unwrapped, other
// values are compacted.
func jsonRawToAttrString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return string(raw)
	}
	return buf.String()
}

// pairOpenAIToolCalls handles the OpenAI chat messages schema shared by
// OpenAI, openai_compatible, Qwen and Ollama. Only the tool calls of the
// latest assistant message are paired, with tool results that follow it.
func pairOpenAIToolCalls(raw json.RawMessage) []ToolCall {
	if len(raw) == 0 {
		return nil
	}
	var msgs []struct {
		Role      string `json:"role"`
		Content   json.RawMessage
		ToolCalls []struct {
			ID       string `json:"id"`
			Function struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			} `json:"function"`
		} `json:"tool_calls"`
		ToolCallID string `json:"tool_call_id"`
		ToolName   string `json:"tool_name"`
		Name       string `json:"name"`
	}
	if err := json.Unmarshal(raw, &msgs); err != nil {
		return nil
	}

	last := -1
	for i := range msgs {
		if msgs[i].Role == "assistant" {
			last = i
		}
	}
	if last < 0 || len(msgs[last].ToolCalls) == 0 {
		return nil
	}

	var calls []pendingToolCall
	for j := range msgs[last].ToolCalls {
		tc := &msgs[last].ToolCalls[j]
		calls = append(calls, pendingToolCall{
			id:   tc.ID,
			name: tc.Function.Name,
			args: tc.Function.Arguments,
		})
	}

	var results []pendingToolResult
	for i := last + 1; i < len(msgs); i++ {
		m := &msgs[i]
		if m.Role != "tool" {
			continue
		}
		name := m.ToolName
		if name == "" {
			name = m.Name
		}
		results = append(results, pendingToolResult{
			id:     m.ToolCallID,
			name:   name,
			result: m.Content,
		})
	}
	return pairToolCalls(calls, results)
}

type anthropicContentBlock struct {
	Type      string          `json:"type"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
	IsError   bool            `json:"is_error"`
}

func anthropicBlocks(raw json.RawMessage) []anthropicContentBlock {
	var blocks []anthropicContentBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return nil
	}
	return blocks
}

// pairAnthropicToolCalls handles the Anthropic messages schema where content
// blocks carry tool_use and tool_result entries linked by tool_use_id. Only
// the tool_use blocks of the latest assistant message are paired, with
// tool_result blocks that follow it. tool_result blocks flagged with
// is_error mark the paired call as failed.
func pairAnthropicToolCalls(raw json.RawMessage) []ToolCall {
	if len(raw) == 0 {
		return nil
	}
	var msgs []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(raw, &msgs); err != nil {
		return nil
	}

	last := -1
	for i := range msgs {
		if msgs[i].Role == "assistant" {
			last = i
		}
	}
	if last < 0 {
		return nil
	}

	var calls []pendingToolCall
	for _, b := range anthropicBlocks(msgs[last].Content) {
		if b.Type == "tool_use" {
			calls = append(calls, pendingToolCall{id: b.ID, name: b.Name, args: b.Input})
		}
	}
	if len(calls) == 0 {
		return nil
	}

	var results []pendingToolResult
	for i := last + 1; i < len(msgs); i++ {
		for _, b := range anthropicBlocks(msgs[i].Content) {
			if b.Type == "tool_result" {
				results = append(results, pendingToolResult{
					id:      b.ToolUseID,
					result:  b.Content,
					isError: b.IsError,
				})
			}
		}
	}
	return pairToolCalls(calls, results)
}

// pairGeminiToolCalls handles the Gemini contents schema. Only the function
// calls of the latest model message are paired, with function responses that
// follow it. Function call/response ids are preserved when present (Gemini 3
// requires them for parallel calls); pairing falls back to the function name
// only when the provider omits ids.
func pairGeminiToolCalls(raw json.RawMessage) []ToolCall {
	if len(raw) == 0 {
		return nil
	}
	var contents []struct {
		Role  string       `json:"role"`
		Parts []geminiPart `json:"parts"`
	}
	if err := json.Unmarshal(raw, &contents); err != nil {
		return nil
	}

	last := -1
	for i := range contents {
		if contents[i].Role == "model" {
			last = i
		}
	}
	if last < 0 {
		return nil
	}

	var calls []pendingToolCall
	for _, p := range contents[last].Parts {
		if p.FunctionCall != nil {
			calls = append(calls, pendingToolCall{
				id:   p.FunctionCall.ID,
				name: p.FunctionCall.Name,
				args: p.FunctionCall.Args,
			})
		}
	}
	if len(calls) == 0 {
		return nil
	}

	var results []pendingToolResult
	for i := last + 1; i < len(contents); i++ {
		for _, p := range contents[i].Parts {
			if p.FunctionResponse != nil {
				results = append(results, pendingToolResult{
					id:     p.FunctionResponse.ID,
					name:   p.FunctionResponse.Name,
					result: p.FunctionResponse.Response,
				})
			}
		}
	}
	return pairToolCalls(calls, results)
}
