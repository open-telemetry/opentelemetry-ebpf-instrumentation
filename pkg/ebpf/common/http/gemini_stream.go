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

// maxGeminiStreamCandidates bounds allocations derived from response-provided
// candidate indices, consistent with the openai_stream.go guard.
const maxGeminiStreamCandidates = 256

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

// candidatePart is a single ordered part in a candidate's content.
// Either text is non-empty (text part) or fcRaw is non-nil (function-call part).
type candidatePart struct {
	text  string
	fcRaw json.RawMessage
}

// candidateAggregator accumulates streamed parts for a single candidate
// index, preserving the original part ordering.
type candidateAggregator struct {
	parts        []candidatePart
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
			if c.Index < 0 || c.Index >= maxGeminiStreamCandidates {
				continue
			}
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
					if n := len(agg.parts); n > 0 && agg.parts[n-1].fcRaw == nil {
						agg.parts[n-1].text += textPart.Text
					} else {
						agg.parts = append(agg.parts, candidatePart{text: textPart.Text})
					}
					continue
				}

				var fcPart geminiFunctionCallPart
				if err := json.Unmarshal(rawPart, &fcPart); err == nil && fcPart.FunctionCall != nil && fcPart.FunctionCall.Name != "" {
					toolCalls = append(toolCalls, request.ToolCall{
						Name: fcPart.FunctionCall.Name,
					})
					agg.parts = append(agg.parts, candidatePart{fcRaw: rawPart})
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
		parts := buildGeminiStreamParts(agg.parts)
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

// buildGeminiStreamParts constructs the parts JSON from ordered candidate
// parts, preserving the original text/function-call ordering and coalescing
// only adjacent text fragments.
func buildGeminiStreamParts(parts []candidatePart) json.RawMessage {
	if len(parts) == 0 {
		return nil
	}

	type textPartJSON struct {
		Text string `json:"text"`
	}

	var rawParts []json.RawMessage
	for _, p := range parts {
		if p.fcRaw != nil {
			rawParts = append(rawParts, p.fcRaw)
			continue
		}
		if p.text != "" {
			raw, err := json.Marshal(textPartJSON{Text: p.text})
			if err == nil {
				rawParts = append(rawParts, raw)
			}
		}
	}

	if len(rawParts) == 0 {
		return nil
	}

	raw, err := json.Marshal(rawParts)
	if err != nil {
		return nil
	}
	return raw
}
