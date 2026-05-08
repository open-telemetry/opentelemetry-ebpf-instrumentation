// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func OpenAISpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	// Check any of the well known response headers that OpenAI would use
	isOpenAI := false
	for _, header := range []string{"Openai-Version", "Openai-Organization", "Openai-Project", "Openai-Processing-Ms"} {
		if val := resp.Header.Get(header); val != "" {
			isOpenAI = true
			break
		}
	}

	if !isOpenAI {
		return *baseSpan, false
	}

	reqB, err := io.ReadAll(req.Body)
	if err != nil {
		return *baseSpan, false
	}
	req.Body = io.NopCloser(bytes.NewBuffer(reqB))

	respB, err := getResponseBody(resp)
	if err != nil && len(respB) == 0 {
		return *baseSpan, false
	}

	slog.Debug("OpenAI", "request", string(reqB), "response", string(respB))

	var parsedRequest request.OpenAIInput
	if err := json.Unmarshal(reqB, &parsedRequest); err != nil {
		slog.Debug("failed to parse OpenAI request", "error", err)
	}

	var parsedResponse request.VendorOpenAI
	if err := json.Unmarshal(respB, &parsedResponse); err != nil {
		slog.Debug("failed to parse OpenAI response", "error", err)
	}

	parsedResponse.Request = parsedRequest

	// Override operation name and derive API type from URL path.
	if req.URL != nil {
		path := strings.TrimSuffix(req.URL.Path, "/")
		switch path {
		case "/v1/chat/completions":
			parsedResponse.OperationName = request.ChatOperationName
			parsedResponse.APIType = "chat_completions"
		case "/v1/embeddings":
			parsedResponse.OperationName = request.EmbeddingOperationName
			parsedResponse.APIType = "embeddings"
		case "/v1/responses":
			parsedResponse.APIType = "responses"
		}
	}

	baseSpan.SubType = request.HTTPSubtypeOpenAI
	baseSpan.GenAI = &request.GenAI{
		OpenAI: &parsedResponse,
	}

	return *baseSpan, true
}
