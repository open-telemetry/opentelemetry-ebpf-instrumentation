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
	Index        int                  `json:"index"`
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
	FunctionCall *geminiFunctionCallData `json:"functionCall"`
}

type geminiFunctionCallData struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args,omitempty"`
}

// candidateAggregator accumulates streamed text and function-call parts
// for a single candidate index.
type candidateAggregator struct {
	content      strings.Builder
	fcParts      []json.RawMessage
	finishReason string
}

// parseGeminiStream parses the SSE stream from Gemini APIs and returns
// the aggregated response with usage statistics and tool calls.
//
// SSE framing: Gemini emits one JSON object per "data:" line. We
// intentionally only support this observed single-line framing
// (consistent with the OpenAI SSE parser) rather than the full
// multi-line SSE spec.
func parseGeminiStream(reader io.Reader) (*request.GeminiResponse, []request.ToolCall) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)

	candidates := make(map[int]*candidateAggregator)
	var toolCalls []request.ToolCall
	var modelVersion string
	var responseID string
	var usage *request.GeminiUsage

	for scanner.Scan() {
		line := scanner.Text()

		data, ok := extractSSEData(line)
		if !ok {
			continue
		}

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
		if chunk.UsageMetadata != nil && geminiUsageHasTokens(chunk.UsageMetadata) {
			usage = chunk.UsageMetadata
		}

		for i := range chunk.Candidates {
			c := &chunk.Candidates[i]
			agg := candidates[c.Index]
			if agg == nil {
				agg = &candidateAggregator{}
				candidates[c.Index] = agg
			}

			if c.FinishReason != "" {
				agg.finishReason = c.FinishReason
			}
			if c.Content == nil {
				continue
			}

			for _, rawPart := range c.Content.Parts {
				var textPart geminiTextPart
				if err := json.Unmarshal(rawPart, &textPart); err == nil && textPart.Text != "" {
					agg.content.WriteString(textPart.Text)
					continue
				}

				var fcPart geminiFunctionCallPart
				if err := json.Unmarshal(rawPart, &fcPart); err == nil && fcPart.FunctionCall != nil && fcPart.FunctionCall.Name != "" {
					toolCalls = append(toolCalls, request.ToolCall{
						Name: fcPart.FunctionCall.Name,
					})
					agg.fcParts = append(agg.fcParts, rawPart)
				}
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

	resp.Candidates = buildGeminiCandidates(candidates)

	return resp, toolCalls
}

// extractSSEData extracts the JSON payload from an SSE data line.
// It handles both "data: " (with space) and "data:" (without space) prefixes.
func extractSSEData(line string) (string, bool) {
	if strings.HasPrefix(line, "data: ") {
		return line[6:], true
	}
	if strings.HasPrefix(line, "data:") {
		return line[5:], true
	}
	return "", false
}

// geminiUsageHasTokens returns true when any of the exported token
// fields are populated, not just totalTokenCount.
func geminiUsageHasTokens(u *request.GeminiUsage) bool {
	return u.PromptTokenCount > 0 || u.CandidatesTokenCount > 0 || u.TotalTokenCount > 0
}

// buildGeminiCandidates constructs the final candidate list from the
// per-index aggregators, ordered by candidate index.
func buildGeminiCandidates(aggs map[int]*candidateAggregator) []request.GeminiCandidate {
	if len(aggs) == 0 {
		return nil
	}

	maxIdx := 0
	for idx := range aggs {
		if idx > maxIdx {
			maxIdx = idx
		}
	}

	result := make([]request.GeminiCandidate, maxIdx+1)
	for idx, agg := range aggs {
		parts := buildGeminiStreamParts(agg.content.String(), agg.fcParts)
		result[idx] = request.GeminiCandidate{
			Content: &request.GeminiContent{
				Parts: parts,
				Role:  "model",
			},
			FinishReason: agg.finishReason,
		}
	}
	return result
}

// buildGeminiStreamParts constructs the parts JSON from aggregated text
// and raw function-call parts (preserving arguments).
func buildGeminiStreamParts(text string, fcParts []json.RawMessage) json.RawMessage {
	if text == "" && len(fcParts) == 0 {
		return nil
	}

	type textPartJSON struct {
		Text string `json:"text"`
	}

	var parts []json.RawMessage
	if text != "" {
		raw, err := json.Marshal(textPartJSON{Text: text})
		if err == nil {
			parts = append(parts, raw)
		}
	}
	parts = append(parts, fcParts...)

	raw, err := json.Marshal(parts)
	if err != nil {
		return nil
	}
	return raw
}
