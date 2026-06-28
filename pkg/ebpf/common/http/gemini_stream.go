// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

type geminiStreamChunk struct {
	Candidates    []geminiStreamCandidate `json:"candidates"`
	UsageMetadata *request.GeminiUsage    `json:"usageMetadata"`
	ModelVersion  string                  `json:"modelVersion"`
	ResponseID    string                  `json:"responseId"`
}

type geminiStreamCandidate struct {
	Content      *geminiStreamContent `json:"content"`
	FinishReason string               `json:"finishReason"`
}

type geminiStreamContent struct {
	Parts []json.RawMessage `json:"parts"`
	Role  string            `json:"role"`
}

type geminiTextPart struct {
	Text string `json:"text"`
}

type geminiFunctionCallPart struct {
	FunctionCall *struct {
		Name string `json:"name"`
	} `json:"functionCall"`
}

// parseGeminiStream parses the SSE stream from Gemini APIs and returns
// the aggregated response with usage statistics and tool calls.
func parseGeminiStream(reader io.Reader) (*request.GeminiResponse, []request.ToolCall) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)

	var contentBuilder strings.Builder
	var toolCalls []request.ToolCall
	var finishReason string
	var modelVersion string
	var responseID string
	var usage *request.GeminiUsage

	for scanner.Scan() {
		line := scanner.Text()

		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")

		var chunk geminiStreamChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			slog.Debug("parseGeminiStream: failed to parse chunk", "error", err)
			continue
		}

		if chunk.ModelVersion != "" {
			modelVersion = chunk.ModelVersion
		}
		if chunk.ResponseID != "" {
			responseID = chunk.ResponseID
		}
		if chunk.UsageMetadata != nil && chunk.UsageMetadata.TotalTokenCount > 0 {
			usage = chunk.UsageMetadata
		}

		if len(chunk.Candidates) == 0 {
			continue
		}

		candidate := &chunk.Candidates[0]
		if candidate.FinishReason != "" {
			finishReason = candidate.FinishReason
		}
		if candidate.Content == nil {
			continue
		}

		for _, rawPart := range candidate.Content.Parts {
			var textPart geminiTextPart
			if err := json.Unmarshal(rawPart, &textPart); err == nil && textPart.Text != "" {
				contentBuilder.WriteString(textPart.Text)
				continue
			}

			var fcPart geminiFunctionCallPart
			if err := json.Unmarshal(rawPart, &fcPart); err == nil && fcPart.FunctionCall != nil && fcPart.FunctionCall.Name != "" {
				toolCalls = append(toolCalls, request.ToolCall{
					Name: fcPart.FunctionCall.Name,
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		slog.Debug("parseGeminiStream: scanner error", "error", err)
	}

	resp := &request.GeminiResponse{
		ModelVersion: modelVersion,
		ResponseID:   responseID,
	}

	if usage != nil {
		resp.UsageMetadata = *usage
	}

	// Build the aggregated candidate with parts.
	parts := buildGeminiStreamParts(contentBuilder.String(), toolCalls)
	if parts != nil || finishReason != "" {
		resp.Candidates = []request.GeminiCandidate{
			{
				Content: &request.GeminiContent{
					Parts: parts,
					Role:  "model",
				},
				FinishReason: finishReason,
			},
		}
	}

	return resp, toolCalls
}

// buildGeminiStreamParts constructs the parts JSON from aggregated text and tool calls.
func buildGeminiStreamParts(text string, toolCalls []request.ToolCall) json.RawMessage {
	if text == "" && len(toolCalls) == 0 {
		return nil
	}

	type textPartJSON struct {
		Text string `json:"text"`
	}
	type fcNameJSON struct {
		Name string `json:"name"`
	}
	type fcPartJSON struct {
		FunctionCall fcNameJSON `json:"functionCall"`
	}

	var parts []any
	if text != "" {
		parts = append(parts, textPartJSON{Text: text})
	}
	for i := range toolCalls {
		parts = append(parts, fcPartJSON{FunctionCall: fcNameJSON{Name: toolCalls[i].Name}})
	}

	raw, err := json.Marshal(parts)
	if err != nil {
		return nil
	}
	return raw
}
