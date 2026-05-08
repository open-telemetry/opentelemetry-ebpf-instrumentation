// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"encoding/json"
)

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
