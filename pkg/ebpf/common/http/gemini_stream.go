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
	Text             string `json:"text"`
	Thought          bool   `json:"thought,omitempty"`
	ThoughtSignature string `json:"thoughtSignature,omitempty"`
}

type geminiFunctionCallPart struct {
	FunctionCall *geminiFunctionCallData `json:"functionCall"`
}

type geminiFunctionCallData struct {
	Name         string          `json:"name"`
	Args         json.RawMessage `json:"args,omitempty"`
	PartialArgs  string          `json:"partialArgs,omitempty"`
	WillContinue *bool           `json:"willContinue,omitempty"`
}

// geminiStreamError represents a bare error envelope that Gemini may send on
// an HTTP 200 stream (as observed by the official Go client).
type geminiStreamError struct {
	Error *request.GeminiError `json:"error"`
}

// candidatePart is a single ordered part in a candidate's content.
// Either textBuilder is non-nil (text part) or fcRaw is non-nil (function-call part).
type candidatePart struct {
	textBuilder *strings.Builder
	thought     bool
	fcRaw       json.RawMessage
}

// fcAggregator accumulates streaming function call arguments for Vertex AI's
// streamFunctionCallArguments feature where args arrive across multiple chunks.
type fcAggregator struct {
	name       string
	argsAccum  strings.Builder
	hasFullArg bool            // true if args came as a complete JSON object
	fullArg    json.RawMessage // stored when args is a complete JSON object
}

// candidateAggregator accumulates streamed parts for a single candidate
// index, preserving the original part ordering.
type candidateAggregator struct {
	parts        []candidatePart
	finishReason string
	// activeFC tracks a function call being built across multiple stream chunks
	// (Vertex AI streamFunctionCallArguments).
	activeFC *fcAggregator
}

// flushActiveFC finalizes any in-progress function call aggregation and
// appends the result to the candidate's parts list. Returns the function
// call name for toolCalls tracking (empty if nothing was flushed).
func (ca *candidateAggregator) flushActiveFC() string {
	if ca.activeFC == nil {
		return ""
	}
	fc := ca.activeFC
	ca.activeFC = nil

	if fc.name == "" {
		return ""
	}

	var raw json.RawMessage
	if fc.hasFullArg {
		// Complete args arrived as a JSON object.
		raw = buildFunctionCallRaw(fc.name, fc.fullArg)
	} else if fc.argsAccum.Len() > 0 {
		// Partial args were accumulated as string fragments.
		raw = buildFunctionCallRaw(fc.name, json.RawMessage(fc.argsAccum.String()))
	} else {
		// Name-only function call with no args.
		raw = buildFunctionCallRaw(fc.name, nil)
	}

	ca.parts = append(ca.parts, candidatePart{fcRaw: raw})
	return fc.name
}

// buildFunctionCallRaw constructs the raw JSON for a function call part.
func buildFunctionCallRaw(name string, args json.RawMessage) json.RawMessage {
	type fcData struct {
		Name string          `json:"name"`
		Args json.RawMessage `json:"args,omitempty"`
	}
	type fcWrapper struct {
		FunctionCall fcData `json:"functionCall"`
	}
	w := fcWrapper{FunctionCall: fcData{Name: name, Args: args}}
	raw, err := json.Marshal(w)
	if err != nil {
		return nil
	}
	return raw
}

// parseGeminiStream parses the SSE stream from Gemini APIs and returns
// the aggregated response with usage statistics and tool calls.
//
// SSE framing: Gemini emits one JSON object per "data:" line. We
// intentionally only support this observed single-line framing
// (consistent with the OpenAI SSE parser) rather than the full
// multi-line SSE spec.
//
// Error handling: bare {"error": ...} records on an HTTP 200 stream
// are treated as API errors (consistent with the official Google Gen AI
// Go client behavior).
func parseGeminiStream(reader io.Reader) (*request.GeminiResponse, []request.ToolCall) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)

	candidates := make(map[int]*candidateAggregator)
	var toolCalls []request.ToolCall
	var modelVersion string
	var responseID string
	var usage *request.GeminiUsage
	var streamError *request.GeminiError

	for scanner.Scan() {
		line := scanner.Text()

		data, ok := extractSSEData(line)
		if !ok {
			// Check for bare error envelope (not wrapped in "data:" prefix).
			if err := tryParseErrorLine(line); err != nil {
				streamError = err
			}
			continue
		}

		var chunk geminiStreamChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			slog.Debug("parseGeminiStream: failed to parse chunk", "error", err)
			continue
		}

		// Check if this data line is itself an error envelope.
		if chunk.Candidates == nil && chunk.UsageMetadata == nil {
			if err := tryParseErrorLine(data); err != nil {
				streamError = err
				continue
			}
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
					// Flush any active function call before appending text.
					if name := agg.flushActiveFC(); name != "" {
						toolCalls = append(toolCalls, request.ToolCall{Name: name})
					}
					appendTextPart(agg, textPart)
					continue
				}

				var fcPart geminiFunctionCallPart
				if err := json.Unmarshal(rawPart, &fcPart); err == nil && fcPart.FunctionCall != nil {
					processFunctionCallPart(agg, fcPart.FunctionCall, &toolCalls)
				}
			}
		}
	}

	// Flush any remaining active function calls.
	for _, agg := range candidates {
		if name := agg.flushActiveFC(); name != "" {
			toolCalls = append(toolCalls, request.ToolCall{Name: name})
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
	if streamError != nil {
		resp.Error = streamError
	}

	resp.Candidates = buildGeminiCandidates(candidates)

	return resp, toolCalls
}

// appendTextPart adds a text fragment to the candidate aggregator, coalescing
// only with the previous part when both are text parts with equivalent metadata
// (thought flag). Uses strings.Builder for efficient concatenation.
func appendTextPart(agg *candidateAggregator, tp geminiTextPart) {
	n := len(agg.parts)
	// Coalesce with previous text part only if metadata (thought) matches.
	if n > 0 && agg.parts[n-1].textBuilder != nil && agg.parts[n-1].thought == tp.Thought {
		agg.parts[n-1].textBuilder.WriteString(tp.Text)
		return
	}
	b := &strings.Builder{}
	b.WriteString(tp.Text)
	agg.parts = append(agg.parts, candidatePart{
		textBuilder: b,
		thought:     tp.Thought,
	})
}

// processFunctionCallPart handles a function call part, supporting both
// complete single-chunk calls and Vertex AI's streaming function call
// arguments where the name arrives first and args follow in subsequent chunks.
func processFunctionCallPart(agg *candidateAggregator, fc *geminiFunctionCallData, toolCalls *[]request.ToolCall) {
	if fc.Name != "" {
		// New named function call: flush any previous active FC.
		if name := agg.flushActiveFC(); name != "" {
			*toolCalls = append(*toolCalls, request.ToolCall{Name: name})
		}

		// If the call has complete args and no continuation, store directly.
		if len(fc.Args) > 0 && fc.PartialArgs == "" {
			agg.activeFC = &fcAggregator{
				name:       fc.Name,
				hasFullArg: true,
				fullArg:    fc.Args,
			}
			// If willContinue is nil or false, this is a complete call.
			if fc.WillContinue == nil || !*fc.WillContinue {
				if name := agg.flushActiveFC(); name != "" {
					*toolCalls = append(*toolCalls, request.ToolCall{Name: name})
				}
			}
			return
		}

		// Start aggregation (name only, or name with partial args).
		agg.activeFC = &fcAggregator{name: fc.Name}
		if fc.PartialArgs != "" {
			agg.activeFC.argsAccum.WriteString(fc.PartialArgs)
		}

		// If no continuation expected and no partial args, flush immediately.
		if fc.WillContinue == nil && fc.PartialArgs == "" && len(fc.Args) == 0 {
			if name := agg.flushActiveFC(); name != "" {
				*toolCalls = append(*toolCalls, request.ToolCall{Name: name})
			}
		}
		return
	}

	// Continuation fragment (no name): append to active function call.
	if agg.activeFC == nil {
		return
	}
	if fc.PartialArgs != "" {
		agg.activeFC.argsAccum.WriteString(fc.PartialArgs)
	} else if len(fc.Args) > 0 {
		// Args as JSON in continuation.
		agg.activeFC.argsAccum.Write(fc.Args)
	}

	// If willContinue is explicitly false or absent, the call is complete.
	if fc.WillContinue == nil || !*fc.WillContinue {
		if name := agg.flushActiveFC(); name != "" {
			*toolCalls = append(*toolCalls, request.ToolCall{Name: name})
		}
	}
}

// tryParseErrorLine attempts to parse a line as a bare Gemini error envelope.
// Returns the error if found, nil otherwise.
func tryParseErrorLine(line string) *request.GeminiError {
	line = strings.TrimSpace(line)
	if line == "" || line[0] != '{' {
		return nil
	}
	var envelope geminiStreamError
	if err := json.Unmarshal([]byte(line), &envelope); err != nil {
		return nil
	}
	if envelope.Error != nil && (envelope.Error.Code != 0 || envelope.Error.Status != "" || envelope.Error.Message != "") {
		return envelope.Error
	}
	return nil
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
// only adjacent text fragments with equivalent metadata (thought flag).
func buildGeminiStreamParts(parts []candidatePart) json.RawMessage {
	if len(parts) == 0 {
		return nil
	}

	var rawParts []json.RawMessage
	for _, p := range parts {
		if p.fcRaw != nil {
			rawParts = append(rawParts, p.fcRaw)
			continue
		}
		if p.textBuilder != nil && p.textBuilder.Len() > 0 {
			raw := marshalTextPart(p.textBuilder.String(), p.thought)
			if raw != nil {
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

// marshalTextPart marshals a text part, including thought metadata if present.
func marshalTextPart(text string, thought bool) json.RawMessage {
	if thought {
		type thoughtPartJSON struct {
			Text    string `json:"text"`
			Thought bool   `json:"thought"`
		}
		raw, err := json.Marshal(thoughtPartJSON{Text: text, Thought: true})
		if err != nil {
			return nil
		}
		return raw
	}
	type textPartJSON struct {
		Text string `json:"text"`
	}
	raw, err := json.Marshal(textPartJSON{Text: text})
	if err != nil {
		return nil
	}
	return raw
}
