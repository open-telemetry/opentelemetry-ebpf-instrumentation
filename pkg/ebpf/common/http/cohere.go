// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const (
	cohereHost     = "api.cohere.com"
	cohereChatPath = "/v2/chat"
)

// cohereChatRequest represents the Cohere v2 chat request body.
type cohereChatRequest struct {
	Model            string          `json:"model"`
	Messages         json.RawMessage `json:"messages"`
	MaxTokens        int             `json:"max_tokens"`
	Temperature      float64         `json:"temperature"`
	P                float64         `json:"p"`
	StopSequences    json.RawMessage `json:"stop_sequences"`
	Seed             *int            `json:"seed"`
	FrequencyPenalty float64         `json:"frequency_penalty"`
	PresencePenalty  float64         `json:"presence_penalty"`
	Stream           bool            `json:"stream"`
	Tools            json.RawMessage `json:"tools"`
}

// cohereChatResponse represents the Cohere v2 non-streaming chat response
// body. The message object (role, content blocks, tool_calls) has the same
// shape as an OpenAI chat completion message, so it is kept raw and handed to
// the OpenAI choice normalization.
type cohereChatResponse struct {
	ID           string          `json:"id"`
	FinishReason string          `json:"finish_reason"`
	Message      json.RawMessage `json:"message"`
}

// cohereToolCall represents a Cohere v2 tool call, which has the same shape as
// an OpenAI chat completion tool call. Arguments is a JSON-encoded string.
type cohereToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// cohereStreamEvent holds the fields OBI reads from a Cohere v2 chat stream
// event. Each event type populates a different subset of them.
type cohereStreamEvent struct {
	Type  string `json:"type"`
	ID    string `json:"id"`
	Delta struct {
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Content struct {
				Text string `json:"text"`
			} `json:"content"`
			ToolCalls cohereToolCall `json:"tool_calls"`
		} `json:"message"`
	} `json:"delta"`
}

// isCohereChatRequest returns true if the request targets the Cohere v2 chat
// endpoint on the Cohere API host.
func isCohereChatRequest(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}

	host := extractHostname(req)
	if host != cohereHost && !strings.HasSuffix(host, "."+cohereHost) {
		return false
	}

	return strings.HasSuffix(strings.TrimSuffix(requestPath(req), "/"), cohereChatPath)
}

// CohereSpan detects Cohere v2 chat requests and converts them into a GenAI
// span.
func CohereSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if !isCohereChatRequest(req) {
		return *baseSpan, false
	}

	reqB, ok := readHTTPRequestBody("CohereSpan", req, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	respB, ok := readHTTPResponseBody("CohereSpan", resp, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	slog.Debug("Cohere", "request", string(reqB), "response", string(respB))

	var cohereReq cohereChatRequest
	unmarshalJSONBestEffort(reqB, &cohereReq)

	parsed := &request.VendorOpenAI{
		OperationName: request.ChatOperationName,
		ProviderName:  "cohere",
		TopP:          cohereReq.P,
		Request: request.OpenAIInput{
			Model:            cohereReq.Model,
			Messages:         cohereReq.Messages,
			MaxTokens:        cohereReq.MaxTokens,
			Temperature:      cohereReq.Temperature,
			Stop:             cohereReq.StopSequences,
			Seed:             cohereReq.Seed,
			FrequencyPenalty: cohereReq.FrequencyPenalty,
			PresencePenalty:  cohereReq.PresencePenalty,
			Stream:           cohereReq.Stream,
			Tools:            cohereReq.Tools,
		},
	}

	if looksLikeJSON(respB) {
		parseCohereChatResponse(respB, parsed)
	} else {
		parseCohereChatStream(respB, parsed)
	}

	parsed.ToolCalls = extractToolCalls(parsed.Choices)

	baseSpan.SubType = request.HTTPSubtypeCohere
	baseSpan.GenAI = &request.GenAI{
		Cohere: parsed,
	}

	return *baseSpan, true
}

// parseCohereChatResponse fills the response fields of parsed from a
// non-streaming Cohere v2 chat response.
func parseCohereChatResponse(respB []byte, parsed *request.VendorOpenAI) {
	var cohereResp cohereChatResponse
	unmarshalJSONBestEffort(respB, &cohereResp)

	parsed.ID = cohereResp.ID
	parsed.Usage.InputTokens = tokenCountJSONField(respB, "usage", "tokens", "input_tokens")
	parsed.Usage.OutputTokens = tokenCountJSONField(respB, "usage", "tokens", "output_tokens")

	// Cohere error responses reuse the `message` field for the error text,
	// so only an object is a model message.
	var errorMessage string
	if json.Unmarshal(cohereResp.Message, &errorMessage) == nil {
		parsed.Error.Message = errorMessage
		return
	}

	if len(cohereResp.Message) > 0 || cohereResp.FinishReason != "" {
		buildCohereChoices(parsed, cohereResp.Message, cohereResp.FinishReason)
	}
}

// parseCohereChatStream fills the response fields of parsed from a Cohere v2
// chat SSE stream. Every event carries its type in the JSON payload, so the
// SSE `event:` lines are not needed.
func parseCohereChatStream(respB []byte, parsed *request.VendorOpenAI) {
	scanner := bufio.NewScanner(bytes.NewReader(respB))
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)

	var content strings.Builder
	var toolCalls []cohereToolCall
	var finishReason string

	for scanner.Scan() {
		data, ok := extractSSEData(scanner.Text())
		if !ok {
			continue
		}
		dataB := []byte(strings.TrimSpace(data))

		var event cohereStreamEvent
		unmarshalJSONBestEffort(dataB, &event)

		switch event.Type {
		case "message-start":
			parsed.ID = event.ID
		case "content-delta":
			content.WriteString(event.Delta.Message.Content.Text)
		case "tool-call-start":
			toolCalls = append(toolCalls, event.Delta.Message.ToolCalls)
		case "tool-call-delta":
			if len(toolCalls) > 0 {
				toolCalls[len(toolCalls)-1].Function.Arguments += event.Delta.Message.ToolCalls.Function.Arguments
			}
		case "message-end":
			finishReason = event.Delta.FinishReason
			parsed.Usage.InputTokens.Merge(tokenCountJSONField(dataB, "delta", "usage", "tokens", "input_tokens"))
			parsed.Usage.OutputTokens.Merge(tokenCountJSONField(dataB, "delta", "usage", "tokens", "output_tokens"))
		}
	}
	if err := scanner.Err(); err != nil {
		slog.Debug("failed to parse complete Cohere stream, continuing with partial fields", "error", err)
	}

	if content.Len() == 0 && len(toolCalls) == 0 && finishReason == "" {
		return
	}

	type contentBlock struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	message := struct {
		Role      string           `json:"role"`
		Content   []contentBlock   `json:"content,omitempty"`
		ToolCalls []cohereToolCall `json:"tool_calls,omitempty"`
	}{
		Role:      "assistant",
		ToolCalls: toolCalls,
	}
	if content.Len() > 0 {
		message.Content = []contentBlock{{Type: "text", Text: content.String()}}
	}

	messageB, err := json.Marshal(message)
	if err != nil {
		return
	}
	buildCohereChoices(parsed, messageB, finishReason)
}

// buildCohereChoices wraps a Cohere message into the OpenAI choices layout
// used by GetFinishReasons(), GetOutput() and extractToolCalls().
func buildCohereChoices(parsed *request.VendorOpenAI, message json.RawMessage, finishReason string) {
	choices := []struct {
		Message      json.RawMessage `json:"message,omitempty"`
		FinishReason string          `json:"finish_reason"`
	}{{
		Message:      message,
		FinishReason: finishReason,
	}}
	if b, err := json.Marshal(choices); err == nil {
		parsed.Choices = b
	}
}
