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

// ollamaRequest represents the Ollama native request body for both
// /api/chat and /api/generate endpoints.
type ollamaRequest struct {
	Model    string          `json:"model"`
	Messages json.RawMessage `json:"messages"`
	Prompt   string          `json:"prompt"`
	System   string          `json:"system"`
	Stream   *bool           `json:"stream"`
	Tools    json.RawMessage `json:"tools"`
	Input    json.RawMessage `json:"input"`
}

// ollamaResponse represents the Ollama native response body shared
// between /api/chat and /api/generate endpoints.
type ollamaResponse struct {
	Model           string             `json:"model"`
	Message         json.RawMessage    `json:"message"`
	Response        string             `json:"response"`
	Done            bool               `json:"done"`
	DoneReason      string             `json:"done_reason"`
	PromptEvalCount request.TokenCount `json:"prompt_eval_count"`
	EvalCount       request.TokenCount `json:"eval_count"`
	// Embeddings holds the response of /api/embed:
	// {"embeddings":[[...],[...]]}. Embedding holds the single vector
	// returned by the legacy /api/embeddings endpoint.
	Embeddings json.RawMessage `json:"embeddings"`
	Embedding  json.RawMessage `json:"embedding"`
}

// ollamaChatMessage represents a single message in an Ollama chat response.
type ollamaChatMessage struct {
	Role      string          `json:"role"`
	Content   string          `json:"content"`
	ToolCalls json.RawMessage `json:"tool_calls"`
}

// isOllamaPath returns true if the URL path ends with /api/chat, /api/generate,
// /api/embed or the legacy /api/embeddings.
func isOllamaPath(req *http.Request) bool {
	path := requestPath(req)
	return strings.HasSuffix(path, "/api/chat") ||
		strings.HasSuffix(path, "/api/generate") ||
		strings.HasSuffix(path, "/api/embed") ||
		strings.HasSuffix(path, "/api/embeddings")
}

// ollamaOperation returns the gen_ai.operation.name for the request path.
func ollamaOperation(req *http.Request) string {
	path := requestPath(req)
	switch {
	case strings.HasSuffix(path, "/api/chat"):
		return request.ChatOperationName
	case strings.HasSuffix(path, "/api/embed"), strings.HasSuffix(path, "/api/embeddings"):
		return request.EmbeddingOperationName
	default:
		return request.CompletionOperationName
	}
}

// OllamaSpan detects Ollama native /api/chat and /api/generate requests
// and converts them into a GenAI span.
func OllamaSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if !isOllamaPath(req) {
		return *baseSpan, false
	}

	reqB, ok := readHTTPRequestBody("OllamaSpan", req, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	respB, ok := readHTTPResponseBody("OllamaSpan", resp, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	slog.Debug("Ollama", "request", string(reqB), "response", string(respB))

	var ollamaReq ollamaRequest
	unmarshalJSONBestEffort(reqB, &ollamaReq)

	operation := ollamaOperation(req)
	isChat := operation == request.ChatOperationName

	var ollamaResp ollamaResponse
	var toolCalls []request.ToolCall
	// Ollama streaming uses newline-delimited JSON (NDJSON), not SSE.
	// A single non-streaming response is valid JSON; multiple NDJSON lines are not.
	switch {
	case json.Valid(respB):
		unmarshalJSONBestEffort(respB, &ollamaResp)
		ollamaResp.PromptEvalCount.Merge(tokenCountJSONField(respB, "prompt_eval_count"))
		ollamaResp.EvalCount.Merge(tokenCountJSONField(respB, "eval_count"))
		if isChat {
			toolCalls = extractOllamaToolCalls(ollamaResp.Message)
		}
	case looksLikeJSON(respB):
		ollamaResp, toolCalls = parseOllamaStream(bytes.NewReader(respB), isChat)
	default:
		return *baseSpan, false
	}

	// Reject if no model could be extracted from either request or response.
	if ollamaReq.Model == "" && ollamaResp.Model == "" {
		return *baseSpan, false
	}

	// Build the VendorOpenAI-compatible response.
	parsed := &request.VendorOpenAI{
		OperationName: operation,
		ResponseModel: ollamaResp.Model,
		ProviderName:  "ollama",
	}

	// Map token counts: Ollama uses prompt_eval_count / eval_count.
	parsed.Usage.InputTokens = ollamaResp.PromptEvalCount
	parsed.Usage.OutputTokens = ollamaResp.EvalCount

	// Build request info.
	parsed.Request = request.OpenAIInput{
		Model:    ollamaReq.Model,
		Messages: ollamaReq.Messages,
		Prompt:   ollamaReq.Prompt,
		Stream:   ollamaReq.Stream == nil || *ollamaReq.Stream,
		Tools:    ollamaReq.Tools,
	}
	// /api/embed sends the text to embed in the `input` field (a string
	// or an array of strings) rather than `prompt` or `messages`.
	if operation == request.EmbeddingOperationName {
		parsed.Request.Stream = false
		var input string
		if err := json.Unmarshal(ollamaReq.Input, &input); err == nil {
			parsed.Request.Input = input
		}
		parsed.Data = ollamaEmbeddingData(&ollamaResp)
	}

	// For /api/generate, keep system instructions separate.
	if !isChat && ollamaReq.System != "" {
		parsed.Request.Instructions = ollamaReq.System
	}

	// Fallback model resolution.
	if parsed.ResponseModel == "" {
		parsed.ResponseModel = ollamaReq.Model
	}
	if parsed.Request.Model == "" {
		parsed.Request.Model = parsed.ResponseModel
	}

	// Build output as normalized choices for GetOutput()/GetFinishReasons().
	if isChat {
		var msg ollamaChatMessage
		if len(ollamaResp.Message) > 0 {
			_ = json.Unmarshal(ollamaResp.Message, &msg)
		}
		if msg.Content != "" || ollamaResp.DoneReason != "" {
			buildOllamaChoices(parsed, msg.Role, msg.Content, ollamaResp.DoneReason)
		}
	} else if ollamaResp.Response != "" || ollamaResp.DoneReason != "" {
		buildOllamaChoices(parsed, "assistant", ollamaResp.Response, ollamaResp.DoneReason)
	}

	parsed.ToolCalls = toolCalls

	baseSpan.SubType = request.HTTPSubtypeOllama
	baseSpan.GenAI = &request.GenAI{
		Ollama: parsed,
	}

	return *baseSpan, true
}

// ollamaEmbeddingData converts the Ollama embedding response into the
// OpenAI-style `data` layout understood by GetEmbeddingDimensions:
// /api/embed returns {"embeddings":[[...]]} (one vector per input), while the
// legacy /api/embeddings returns a single {"embedding":[...]} vector. Only the
// first vector is kept, matching the dimension attribute semantics.
func ollamaEmbeddingData(resp *ollamaResponse) json.RawMessage {
	var vector json.RawMessage
	if len(resp.Embeddings) > 0 {
		var vectors []json.RawMessage
		if err := json.Unmarshal(resp.Embeddings, &vectors); err != nil || len(vectors) == 0 {
			return nil
		}
		vector = vectors[0]
	} else if len(resp.Embedding) > 0 {
		vector = resp.Embedding
	}
	if len(vector) == 0 {
		return nil
	}
	type dataEntry struct {
		Embedding json.RawMessage `json:"embedding"`
	}
	b, err := json.Marshal([]dataEntry{{Embedding: vector}})
	if err != nil {
		return nil
	}
	return b
}

// buildOllamaChoices constructs the Choices JSON used by GetFinishReasons()
// and normalizeOpenAIChoices for output rendering.
func buildOllamaChoices(parsed *request.VendorOpenAI, role, content, finishReason string) {
	type choiceMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type choice struct {
		Message      choiceMsg `json:"message"`
		FinishReason string    `json:"finish_reason"`
	}
	if role == "" {
		role = "assistant"
	}
	choices := []choice{{
		Message:      choiceMsg{Role: role, Content: content},
		FinishReason: finishReason,
	}}
	if b, err := json.Marshal(choices); err == nil {
		parsed.Choices = b
	}
}

// extractOllamaToolCalls extracts tool calls from an Ollama chat message.
func extractOllamaToolCalls(messageRaw json.RawMessage) []request.ToolCall {
	if len(messageRaw) == 0 {
		return nil
	}
	var msg struct {
		ToolCalls []struct {
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		} `json:"tool_calls"`
	}
	if err := json.Unmarshal(messageRaw, &msg); err != nil {
		return nil
	}
	var result []request.ToolCall
	for i := range msg.ToolCalls {
		if msg.ToolCalls[i].Function.Name != "" {
			result = append(result, request.ToolCall{
				Name: msg.ToolCalls[i].Function.Name,
			})
		}
	}
	return result
}

// parseOllamaStream parses Ollama's newline-delimited JSON streaming
// response. Each line is a complete JSON object; the final object has
// done=true and carries token counts and done_reason.
func parseOllamaStream(reader *bytes.Reader, isChat bool) (ollamaResponse, []request.ToolCall) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)

	var final ollamaResponse
	var contentBuilder strings.Builder
	var toolCalls []request.ToolCall
	var role string

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var chunk ollamaResponse
		unmarshalJSONBestEffort(line, &chunk)
		chunk.PromptEvalCount.Merge(tokenCountJSONField(line, "prompt_eval_count"))
		chunk.EvalCount.Merge(tokenCountJSONField(line, "eval_count"))

		if chunk.Model != "" && final.Model == "" {
			final.Model = chunk.Model
		}

		switch {
		case isChat && len(chunk.Message) > 0:
			var msg ollamaChatMessage
			if err := json.Unmarshal(chunk.Message, &msg); err == nil {
				if msg.Role != "" {
					role = msg.Role
				}
				contentBuilder.WriteString(msg.Content)
				if len(msg.ToolCalls) > 0 {
					tc := extractOllamaToolCalls(chunk.Message)
					toolCalls = append(toolCalls, tc...)
				}
			}
		case !isChat:
			contentBuilder.WriteString(chunk.Response)
		}

		final.PromptEvalCount.Merge(chunk.PromptEvalCount)
		final.EvalCount.Merge(chunk.EvalCount)

		if chunk.Done {
			final.Done = true
			final.DoneReason = chunk.DoneReason
			if chunk.Model != "" {
				final.Model = chunk.Model
			}
		}
	}

	if isChat {
		if role == "" {
			role = "assistant"
		}
		msg := ollamaChatMessage{Role: role, Content: contentBuilder.String()}
		if b, err := json.Marshal(msg); err == nil {
			final.Message = b
		}
	} else {
		final.Response = contentBuilder.String()
	}

	return final, toolCalls
}
