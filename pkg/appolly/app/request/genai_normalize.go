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
	URI       string          `json:"uri,omitempty"`
	FileID    string          `json:"file_id,omitempty"`
	Modality  string          `json:"modality,omitempty"`
	MimeType  string          `json:"mime_type,omitempty"`
}

type normalizedMessage struct {
	Role         string           `json:"role"`
	Parts        []normalizedPart `json:"parts"`
	FinishReason string           `json:"finish_reason,omitempty"`
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
