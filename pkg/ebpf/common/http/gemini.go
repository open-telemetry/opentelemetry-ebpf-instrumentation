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

func isGemini(respHeader http.Header) bool {
	return respHeader.Get("X-Gemini-Service-Tier") != ""
}

func GeminiSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if !isGemini(resp.Header) {
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

	slog.Debug("Gemini", "request", string(reqB), "response", string(respB))

	var parsedRequest request.GeminiRequest
	if err := json.Unmarshal(reqB, &parsedRequest); err != nil {
		slog.Debug("failed to parse Gemini request", "error", err)
	}

	var parsedResponse request.GeminiResponse
	if err := json.Unmarshal(respB, &parsedResponse); err != nil {
		slog.Debug("failed to parse Gemini response", "error", err)
	}

	model := extractGeminiModel(req)

	baseSpan.SubType = request.HTTPSubtypeGemini
	baseSpan.GenAI = &request.GenAI{
		Gemini: &request.VendorGemini{
			Input:  parsedRequest,
			Output: parsedResponse,
			Model:  model,
		},
	}

	return *baseSpan, true
}

// extractGeminiModel extracts the model name from the URL path.
// Gemini URLs follow the pattern: /v1beta/models/{model}:generateContent
func extractGeminiModel(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	path := req.URL.Path
	const prefix = "/models/"
	idx := strings.Index(path, prefix)
	if idx < 0 {
		return ""
	}
	model := path[idx+len(prefix):]
	if colonIdx := strings.Index(model, ":"); colonIdx >= 0 {
		model = model[:colonIdx]
	}
	return model
}
