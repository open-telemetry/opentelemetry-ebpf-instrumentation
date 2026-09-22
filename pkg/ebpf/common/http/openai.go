// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

type openAIToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name string `json:"name"`
	} `json:"function"`
}

func extractToolCalls(choices json.RawMessage) []request.ToolCall {
	if len(choices) == 0 {
		return nil
	}

	var parsed []struct {
		Message struct {
			ToolCalls []openAIToolCall `json:"tool_calls"`
		} `json:"message"`
	}
	if err := json.Unmarshal(choices, &parsed); err != nil {
		return nil
	}

	var result []request.ToolCall
	for i := range parsed {
		for j := range parsed[i].Message.ToolCalls {
			tc := &parsed[i].Message.ToolCalls[j]
			if tc.Function.Name == "" {
				continue
			}
			result = append(result, request.ToolCall{
				ID:   tc.ID,
				Name: tc.Function.Name,
			})
		}
	}
	return result
}

// parseOpenAICompatibleResponse parses an OpenAI-compatible response body,
// handling both JSON and SSE streaming formats. It returns the parsed response
// and any tool calls extracted from the response.
func parseOpenAICompatibleResponse(respB []byte) (*request.VendorOpenAI, []request.ToolCall) {
	if looksLikeJSON(respB) {
		resp := parseVendorOpenAI(respB)
		return &resp, extractToolCalls(resp.Choices)
	}
	reader := bytes.NewReader(respB)
	return parseOpenAIStream(reader)
}

func looksLikeOpenAIBody(reqB, respB []byte, path string) bool {
	model := strings.ToLower(genaiModel(reqB, respB))

	// DashScope embedding models are named "text-embedding-v<N>": leave them
	// for the Qwen detector.
	if isDashScopeEmbeddingModel(model) {
		return false
	}

	// "gpt" covers chat/completions and responses; "text-embedding" covers the
	// embeddings.
	return strings.HasPrefix(model, "gpt") || (strings.HasPrefix(model, "text-embedding") && strings.Contains(path, "/v1/embeddings"))
}

func OpenAISpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	// Check any of the well known response headers that OpenAI would use
	isOpenAI := false
	for _, header := range []string{"Openai-Version", "Openai-Organization", "Openai-Project", "Openai-Processing-Ms"} {
		if val := resp.Header.Get(header); val != "" {
			isOpenAI = true
			break
		}
	}

	maybeOpenAI := false

	if !isOpenAI {
		// HTTP/2 requests carry no usable headers, so fall back to a body-shape
		// heuristic. OpenAI is the catch-all for OpenAI-compatible payloads that
		// no sibling provider (Qwen, Anthropic) claims.
		if !isHTTP2Request(req) || !strings.Contains(baseSpan.Path, "/v1/") {
			return *baseSpan, false
		}
		maybeOpenAI = true
	}

	reqB, ok := readHTTPRequestBody("OpenAISpan", req, baseSpan, "headers", resp.Header)
	if !ok {
		return *baseSpan, false
	}

	respB, ok := readHTTPResponseBody("OpenAISpan", resp, baseSpan, "headers", resp.Header)
	if !ok {
		return *baseSpan, false
	}

	if maybeOpenAI {
		if !looksLikeOpenAIBody(reqB, respB, baseSpan.Path) {
			return *baseSpan, false
		}
	}

	slog.Debug("OpenAI", "request", string(reqB), "response", string(respB))

	parsedRequest := parseOpenAIInput(reqB, isOpenAIResponsesRequest(req))
	parsedResponse, toolCalls := parseOpenAICompatibleResponse(respB)

	if parsedResponse.ResponseModel == "" {
		parsedResponse.ResponseModel = parsedRequest.Model
	}
	if parsedRequest.Model == "" {
		parsedRequest.Model = parsedResponse.ResponseModel
	}

	parsedResponse.Request = parsedRequest
	parsedResponse.ToolCalls = toolCalls

	// Override operation name and derive API type from URL path. The path is
	// authoritative even when the response carries no `object` field (error
	// responses don't): the operation name feeds required metric attributes
	// (gen_ai.client.operation.duration / token.usage), so failed calls must
	// carry it too.
	parsedResponse.OperationName, parsedResponse.APIType = openAIOperation(requestPath(req))

	baseSpan.SubType = request.HTTPSubtypeOpenAI
	baseSpan.GenAI = &request.GenAI{
		OpenAI: parsedResponse,
	}

	return *baseSpan, true
}

// API types OBI derives from an OpenAI request path, mirroring the
// `openai.api.type` enum declared in schemas/obi/groups/openai/registry.yaml.
// Adding one here requires a member there too; a test asserts the two agree.
const (
	openAIAPITypeChatCompletions = "chat_completions"
	openAIAPITypeTextCompletions = "text_completions"
	openAIAPITypeEmbeddings      = "embeddings"
	openAIAPITypeResponses       = "responses"
)

var openAIAPITypes = map[string]struct{}{
	openAIAPITypeChatCompletions: {},
	openAIAPITypeTextCompletions: {},
	openAIAPITypeEmbeddings:      {},
	openAIAPITypeResponses:       {},
}

// openAIOperation names the operation and the API type an OpenAI request path
// addresses. The path is read instead of the response body because it names the
// endpoint on an error and on a truncated capture too.
//
// An endpoint is recognized by the API collection its path walks through rather
// than by the whole path, so a deployment mounted under a prefix
// (/openai/deployments/{id}/chat/completions on Azure, a gateway) and a call on
// a single resource (/v1/responses/{id}, /v1/chatkit/threads/{id}/items) both
// resolve to the endpoint that owns them. Segments are walked from the end so
// the deepest collection wins. Detection is header- or host-driven, so an
// endpoint OBI has no operation for reports `_OTHER` rather than nothing.
func openAIOperation(path string) (string, string) {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	for i, segment := range slices.Backward(segments) {
		parent := ""
		if i > 0 {
			parent = segments[i-1]
		}

		switch segment {
		case "completions":
			if parent == "chat" {
				return request.ChatOperationName, openAIAPITypeChatCompletions
			}
			return request.CompletionOperationName, openAIAPITypeTextCompletions
		case "embeddings":
			return request.EmbeddingOperationName, openAIAPITypeEmbeddings
		case "responses":
			return request.ResponseOperationName, openAIAPITypeResponses
		case "conversations":
			return request.ConversationOperationName, ""
		case "sessions":
			if parent == "chatkit" {
				return request.ChatKitSessionOperationName, ""
			}
		case "threads":
			if parent == "chatkit" {
				return request.ChatKitThreadOperationName, ""
			}
		}
	}

	return request.OtherOperationName, ""
}
