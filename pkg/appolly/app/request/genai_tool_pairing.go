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
// the same execute_tool span. Only fully paired tool calls are returned.
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
	id     string
	name   string
	result json.RawMessage
}

// pairToolCalls matches assistant tool calls to tool results by tool call
// id, falling back to the tool name when ids are absent (Gemini, Ollama).
// Absent or JSON null arguments and results are treated as missing.
func pairToolCalls(calls []pendingToolCall, results []pendingToolResult) []ToolCall {
	results = slices.DeleteFunc(results, func(r pendingToolResult) bool {
		return emptyJSON(r.result)
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
		out = append(out, ToolCall{
			ID:        c.id,
			Name:      c.name,
			Arguments: jsonRawToAttrString(c.args),
			Result:    jsonRawToAttrString(results[idx].result),
		})
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
// OpenAI, openai_compatible, Qwen and Ollama.
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

	var calls []pendingToolCall
	var results []pendingToolResult
	for i := range msgs {
		m := &msgs[i]
		for j := range m.ToolCalls {
			tc := &m.ToolCalls[j]
			calls = append(calls, pendingToolCall{
				id:   tc.ID,
				name: tc.Function.Name,
				args: tc.Function.Arguments,
			})
		}
		if m.Role == "tool" {
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
	}
	return pairToolCalls(calls, results)
}

// pairAnthropicToolCalls handles the Anthropic messages schema where content
// blocks carry tool_use and tool_result entries linked by tool_use_id.
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

	var calls []pendingToolCall
	var results []pendingToolResult
	for i := range msgs {
		var blocks []struct {
			Type      string          `json:"type"`
			ID        string          `json:"id"`
			Name      string          `json:"name"`
			Input     json.RawMessage `json:"input"`
			ToolUseID string          `json:"tool_use_id"`
			Content   json.RawMessage `json:"content"`
		}
		if err := json.Unmarshal(msgs[i].Content, &blocks); err != nil {
			continue
		}
		for j := range blocks {
			b := &blocks[j]
			switch b.Type {
			case "tool_use":
				calls = append(calls, pendingToolCall{id: b.ID, name: b.Name, args: b.Input})
			case "tool_result":
				results = append(results, pendingToolResult{id: b.ToolUseID, result: b.Content})
			}
		}
	}
	return pairToolCalls(calls, results)
}

// pairGeminiToolCalls handles the Gemini contents schema. Gemini omits tool
// call ids, so pairing falls back to the function name.
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

	var calls []pendingToolCall
	var results []pendingToolResult
	for i := range contents {
		for j := range contents[i].Parts {
			p := contents[i].Parts[j]
			if p.FunctionCall != nil {
				calls = append(calls, pendingToolCall{name: p.FunctionCall.Name, args: p.FunctionCall.Args})
			}
			if p.FunctionResponse != nil {
				results = append(results, pendingToolResult{name: p.FunctionResponse.Name, result: p.FunctionResponse.Response})
			}
		}
	}
	return pairToolCalls(calls, results)
}
