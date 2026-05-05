// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"encoding/json"
)

// Semconv-compliant message types per:
// https://github.com/open-telemetry/semantic-conventions/blob/main/docs/gen-ai/gen-ai-input-messages.json
// https://github.com/open-telemetry/semantic-conventions/blob/main/docs/gen-ai/gen-ai-output-messages.json

type normalizedPart struct {
	Type      string          `json:"type"`
	Content   string          `json:"content,omitempty"`
	Response  any             `json:"response,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type normalizedMessage struct {
	Role         string           `json:"role"`
	Parts        []normalizedPart `json:"parts"`
	FinishReason string           `json:"finish_reason,omitempty"`
}

// normalizeOpenAIMessages converts OpenAI-style messages (flat "content")
// to the semconv parts schema.
func normalizeOpenAIMessages(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var msgs []struct {
		Role       string          `json:"role"`
		Content    json.RawMessage `json:"content"`
		ToolCalls  json.RawMessage `json:"tool_calls,omitempty"`
		ToolCallID string          `json:"tool_call_id,omitempty"`
	}
	if err := json.Unmarshal(raw, &msgs); err != nil {
		return string(raw)
	}

	out := make([]normalizedMessage, 0, len(msgs))
	for _, m := range msgs {
		nm := normalizedMessage{Role: m.Role}
		nm.Parts = openAIContentToParts(m.Content)

		if len(m.ToolCalls) > 0 {
			nm.Parts = append(nm.Parts, openAIToolCallsToParts(m.ToolCalls)...)
		}
		if m.ToolCallID != "" {
			for i := range nm.Parts {
				nm.Parts[i].ID = m.ToolCallID
				nm.Parts[i].Type = "tool_call_response"
				nm.Parts[i].Response = nm.Parts[i].Content
				nm.Parts[i].Content = ""
			}
		}
		out = append(out, nm)
	}

	b, err := json.Marshal(out)
	if err != nil {
		return string(raw)
	}
	return string(b)
}

func openAIContentToParts(content json.RawMessage) []normalizedPart {
	if len(content) == 0 {
		return nil
	}

	var s string
	if err := json.Unmarshal(content, &s); err == nil {
		return []normalizedPart{{Type: "text", Content: s}}
	}

	return []normalizedPart{{Type: "text", Content: string(content)}}
}

func openAIToolCallsToParts(raw json.RawMessage) []normalizedPart {
	var calls []struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Function struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"function"`
	}
	if err := json.Unmarshal(raw, &calls); err != nil {
		return nil
	}

	parts := make([]normalizedPart, 0, len(calls))
	for _, c := range calls {
		parts = append(parts, normalizedPart{
			Type:      "tool_call",
			ID:        c.ID,
			Name:      c.Function.Name,
			Arguments: c.Function.Arguments,
		})
	}
	return parts
}

// normalizeOpenAIOutput converts OpenAI response choices to semconv output
// messages schema.
func normalizeOpenAIOutput(ai *VendorOpenAI) string {
	if len(ai.Choices) > 0 {
		return normalizeOpenAIChoices(ai.Choices)
	}

	if len(ai.Output) > 0 {
		return normalizeOpenAIResponsesOutput(ai.Output)
	}
	if len(ai.Items) > 0 {
		return string(ai.Items)
	}
	if len(ai.Data) > 0 {
		return string(ai.Data)
	}
	return ""
}

// normalizeOpenAIResponsesOutput converts the OpenAI Responses API output
// array to the semconv output messages schema.
func normalizeOpenAIResponsesOutput(raw json.RawMessage) string {
	var items []struct {
		Role    string `json:"role"`
		Status  string `json:"status"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return string(raw)
	}

	var out []normalizedMessage
	for _, item := range items {
		var parts []normalizedPart
		for _, c := range item.Content {
			parts = append(parts, normalizedPart{Type: "text", Content: c.Text})
		}
		out = append(out, normalizedMessage{
			Role:         item.Role,
			Parts:        parts,
			FinishReason: item.Status,
		})
	}

	b, err := json.Marshal(out)
	if err != nil {
		return string(raw)
	}
	return string(b)
}

func normalizeOpenAIChoices(raw json.RawMessage) string {
	var choices []struct {
		Message struct {
			Role      string          `json:"role"`
			Content   json.RawMessage `json:"content"`
			ToolCalls json.RawMessage `json:"tool_calls,omitempty"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	}
	if err := json.Unmarshal(raw, &choices); err != nil {
		return string(raw)
	}

	out := make([]normalizedMessage, 0, len(choices))
	for _, c := range choices {
		nm := normalizedMessage{
			Role:         c.Message.Role,
			FinishReason: c.FinishReason,
		}
		nm.Parts = openAIContentToParts(c.Message.Content)
		if len(c.Message.ToolCalls) > 0 {
			nm.Parts = append(nm.Parts, openAIToolCallsToParts(c.Message.ToolCalls)...)
		}
		out = append(out, nm)
	}

	b, err := json.Marshal(out)
	if err != nil {
		return string(raw)
	}
	return string(b)
}

// NormalizeAnthropicInput converts Anthropic request messages to semconv
// schema. Anthropic content blocks can contain tool_use and tool_result
// entries that require separate handling from OpenAI format.
func NormalizeAnthropicInput(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var msgs []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(raw, &msgs); err != nil {
		return string(raw)
	}

	out := make([]normalizedMessage, 0, len(msgs))
	for _, m := range msgs {
		nm := normalizedMessage{Role: m.Role}
		nm.Parts = anthropicContentToParts(m.Content)
		out = append(out, nm)
	}

	b, err := json.Marshal(out)
	if err != nil {
		return string(raw)
	}
	return string(b)
}

func anthropicContentToParts(content json.RawMessage) []normalizedPart {
	if len(content) == 0 {
		return nil
	}

	var s string
	if err := json.Unmarshal(content, &s); err == nil {
		return []normalizedPart{{Type: "text", Content: s}}
	}

	var blocks []struct {
		Type      string          `json:"type"`
		Text      string          `json:"text,omitempty"`
		ID        string          `json:"id,omitempty"`
		Name      string          `json:"name,omitempty"`
		Input     json.RawMessage `json:"input,omitempty"`
		ToolUseID string          `json:"tool_use_id,omitempty"`
		Content   json.RawMessage `json:"content,omitempty"`
		Thinking  string          `json:"thinking,omitempty"`
	}
	if err := json.Unmarshal(content, &blocks); err != nil {
		return []normalizedPart{{Type: "text", Content: string(content)}}
	}

	parts := make([]normalizedPart, 0, len(blocks))
	for _, b := range blocks {
		switch b.Type {
		case "text":
			parts = append(parts, normalizedPart{Type: "text", Content: b.Text})
		case "tool_use":
			parts = append(parts, normalizedPart{
				Type:      "tool_call",
				ID:        b.ID,
				Name:      b.Name,
				Arguments: b.Input,
			})
		case "tool_result":
			parts = append(parts, normalizedPart{
				Type:     "tool_call_response",
				ID:       b.ToolUseID,
				Response: extractToolResultContent(b.Content),
			})
		case "thinking":
			parts = append(parts, normalizedPart{Type: "reasoning", Content: b.Thinking})
		default:
			parts = append(parts, normalizedPart{Type: b.Type, Content: b.Text})
		}
	}
	return parts
}

// extractToolResultContent returns the tool result content as a string.
// Anthropic tool_result content can be a string or an array of content blocks.
func extractToolResultContent(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}

	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}

	var obj any
	if err := json.Unmarshal(raw, &obj); err == nil {
		return obj
	}

	return string(raw)
}

// NormalizeAnthropicOutput converts Anthropic response content blocks
// to semconv output messages schema.
func NormalizeAnthropicOutput(resp *AnthropicResponse) string {
	if len(resp.Content) == 0 {
		return ""
	}

	var blocks []struct {
		Type     string          `json:"type"`
		Text     string          `json:"text,omitempty"`
		ID       string          `json:"id,omitempty"`
		Name     string          `json:"name,omitempty"`
		Input    json.RawMessage `json:"input,omitempty"`
		Thinking string          `json:"thinking,omitempty"`
	}
	if err := json.Unmarshal(resp.Content, &blocks); err != nil {
		return wrapTextAsOutputMessage(resp.Role, string(resp.Content), resp.StopReason)
	}

	var parts []normalizedPart
	for _, b := range blocks {
		switch b.Type {
		case "text":
			parts = append(parts, normalizedPart{Type: "text", Content: b.Text})
		case "tool_use":
			parts = append(parts, normalizedPart{
				Type:      "tool_call",
				ID:        b.ID,
				Name:      b.Name,
				Arguments: b.Input,
			})
		case "thinking":
			parts = append(parts, normalizedPart{Type: "reasoning", Content: b.Thinking})
		default:
			parts = append(parts, normalizedPart{Type: b.Type, Content: b.Text})
		}
	}

	msg := normalizedMessage{
		Role:         resp.Role,
		Parts:        parts,
		FinishReason: resp.StopReason,
	}

	out, err := json.Marshal([]normalizedMessage{msg})
	if err != nil {
		return string(resp.Content)
	}
	return string(out)
}

// geminiPart captures all Gemini part types including function calls/responses.
type geminiPart struct {
	Text             string          `json:"text,omitempty"`
	FunctionCall     *geminiFuncCall `json:"functionCall,omitempty"`
	FunctionResponse *geminiFuncResp `json:"functionResponse,omitempty"`
}

type geminiFuncCall struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args,omitempty"`
}

type geminiFuncResp struct {
	Name     string          `json:"name"`
	Response json.RawMessage `json:"response,omitempty"`
}

func geminiPartToNormalized(p geminiPart) normalizedPart {
	if p.FunctionCall != nil {
		return normalizedPart{
			Type:      "tool_call",
			Name:      p.FunctionCall.Name,
			Arguments: p.FunctionCall.Args,
		}
	}
	if p.FunctionResponse != nil {
		var resp any
		if len(p.FunctionResponse.Response) > 0 {
			_ = json.Unmarshal(p.FunctionResponse.Response, &resp)
		}
		return normalizedPart{
			Type:     "tool_call_response",
			Name:     p.FunctionResponse.Name,
			Response: resp,
		}
	}
	return normalizedPart{Type: "text", Content: p.Text}
}

// normalizeGeminiInput converts Gemini contents to the semconv schema.
func normalizeGeminiInput(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var contents []struct {
		Role  string       `json:"role"`
		Parts []geminiPart `json:"parts"`
	}
	if err := json.Unmarshal(raw, &contents); err != nil {
		return string(raw)
	}

	out := make([]normalizedMessage, 0, len(contents))
	for _, c := range contents {
		nm := normalizedMessage{Role: c.Role}
		for _, p := range c.Parts {
			nm.Parts = append(nm.Parts, geminiPartToNormalized(p))
		}
		out = append(out, nm)
	}

	b, err := json.Marshal(out)
	if err != nil {
		return string(raw)
	}
	return string(b)
}

// normalizeGeminiOutput converts Gemini candidates to semconv output messages.
func normalizeGeminiOutput(resp *GeminiResponse) string {
	if len(resp.Candidates) == 0 {
		return ""
	}

	out := make([]normalizedMessage, 0, len(resp.Candidates))
	for _, c := range resp.Candidates {
		nm := normalizedMessage{FinishReason: c.FinishReason}
		if c.Content != nil {
			nm.Role = c.Content.Role

			var parts []geminiPart
			if err := json.Unmarshal(c.Content.Parts, &parts); err == nil {
				for _, p := range parts {
					nm.Parts = append(nm.Parts, geminiPartToNormalized(p))
				}
			}
		}
		out = append(out, nm)
	}

	b, err := json.Marshal(out)
	if err != nil {
		return ""
	}
	return string(b)
}

// normalizeGeminiParts converts Gemini-style parts from a single
// content block to semconv parts.
func normalizeGeminiParts(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var parts []geminiPart
	if err := json.Unmarshal(raw, &parts); err != nil {
		return string(raw)
	}

	out := make([]normalizedPart, 0, len(parts))
	for _, p := range parts {
		out = append(out, geminiPartToNormalized(p))
	}

	b, err := json.Marshal(out)
	if err != nil {
		return string(raw)
	}
	return string(b)
}

// NormalizeBedrockOutput converts Bedrock Claude-style content blocks
// to the semconv output messages schema. For Bedrock responses that use
// Anthropic Claude format, the content blocks are identical to Anthropic.
func NormalizeBedrockOutput(resp *BedrockResponse) string {
	if len(resp.Content) == 0 {
		return ""
	}

	var blocks []struct {
		Type  string          `json:"type"`
		Text  string          `json:"text,omitempty"`
		ID    string          `json:"id,omitempty"`
		Name  string          `json:"name,omitempty"`
		Input json.RawMessage `json:"input,omitempty"`
	}
	if err := json.Unmarshal(resp.Content, &blocks); err != nil {
		return wrapTextAsOutputMessage("assistant", string(resp.Content), resp.StopReason)
	}

	var parts []normalizedPart
	for _, b := range blocks {
		switch b.Type {
		case "text":
			parts = append(parts, normalizedPart{Type: "text", Content: b.Text})
		case "tool_use":
			parts = append(parts, normalizedPart{
				Type:      "tool_call",
				ID:        b.ID,
				Name:      b.Name,
				Arguments: b.Input,
			})
		default:
			parts = append(parts, normalizedPart{Type: b.Type, Content: b.Text})
		}
	}

	msg := normalizedMessage{
		Role:         "assistant",
		Parts:        parts,
		FinishReason: resp.StopReason,
	}

	out, err := json.Marshal([]normalizedMessage{msg})
	if err != nil {
		return string(resp.Content)
	}
	return string(out)
}

func wrapTextAsInputMessage(text string) string {
	msg := normalizedMessage{
		Role:  "user",
		Parts: []normalizedPart{{Type: "text", Content: text}},
	}
	b, err := json.Marshal([]normalizedMessage{msg})
	if err != nil {
		return text
	}
	return string(b)
}

func wrapTextAsOutputMessage(role, text, finishReason string) string {
	msg := normalizedMessage{
		Role:         role,
		Parts:        []normalizedPart{{Type: "text", Content: text}},
		FinishReason: finishReason,
	}
	b, err := json.Marshal([]normalizedMessage{msg})
	if err != nil {
		return text
	}
	return string(b)
}

// NormalizeSystemInstructions converts a plain text system instruction
// to the semconv JSON schema: [{"type":"text","content":"..."}]
func NormalizeSystemInstructions(text string) string {
	if text == "" {
		return ""
	}
	parts := []normalizedPart{{Type: "text", Content: text}}
	b, err := json.Marshal(parts)
	if err != nil {
		return text
	}
	return string(b)
}

type normalizedTool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// NormalizeToolDefinitions converts provider-native tool definitions to the
// semconv schema: [{"type":"function","name":"...","description":"...","parameters":{}}]
func NormalizeToolDefinitions(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return string(raw)
	}

	var out []normalizedTool
	for _, item := range items {
		out = append(out, normalizeToolItem(item)...)
	}

	b, err := json.Marshal(out)
	if err != nil {
		return string(raw)
	}
	return string(b)
}

func normalizeToolItem(raw json.RawMessage) []normalizedTool {
	var probe struct {
		// OpenAI wrapper: {"type":"function","function":{...}}
		Type     string `json:"type"`
		Function *struct {
			Name        string          `json:"name"`
			Description string          `json:"description,omitempty"`
			Parameters  json.RawMessage `json:"parameters,omitempty"`
		} `json:"function,omitempty"`
		// Anthropic direct: {"name":"...","description":"...","input_schema":{}}
		Name        string          `json:"name,omitempty"`
		Description string          `json:"description,omitempty"`
		InputSchema json.RawMessage `json:"input_schema,omitempty"`
		// Gemini: {"functionDeclarations":[{"name":"..."}]}
		FunctionDeclarations []struct {
			Name        string          `json:"name"`
			Description string          `json:"description,omitempty"`
			Parameters  json.RawMessage `json:"parameters,omitempty"`
		} `json:"functionDeclarations,omitempty"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil
	}

	if len(probe.FunctionDeclarations) > 0 {
		out := make([]normalizedTool, 0, len(probe.FunctionDeclarations))
		for _, fd := range probe.FunctionDeclarations {
			out = append(out, normalizedTool{
				Type:        "function",
				Name:        fd.Name,
				Description: fd.Description,
				Parameters:  fd.Parameters,
			})
		}
		return out
	}

	nt := normalizedTool{Type: "function"}
	if probe.Function != nil {
		nt.Name = probe.Function.Name
		nt.Description = probe.Function.Description
		nt.Parameters = probe.Function.Parameters
	} else {
		nt.Name = probe.Name
		nt.Description = probe.Description
		nt.Parameters = probe.InputSchema
	}
	return []normalizedTool{nt}
}
