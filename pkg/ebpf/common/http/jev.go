// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"log/slog"
	"net/http"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const (
	jevSystemOnePath   = "/api/v1/systemone"
	jevSystemOnePathV1 = "/v1/systemone"
)

func isJevPath(path string) bool {
	path = strings.TrimSuffix(path, "/")
	return strings.HasSuffix(path, jevSystemOnePath) ||
		strings.HasSuffix(path, jevSystemOnePathV1)
}

func looksLikeJevBody(reqB, respB []byte) bool {
	// Check for Jev-specific response fields
	// Search the complete response for model (not just header window)
	model := extractJSONStringField(respB, "model", 0)
	if model == "" {
		return false
	}

	// Jev models start with "jev-" or are "jev-latest"
	lowerModel := strings.ToLower(model)
	if !strings.HasPrefix(lowerModel, "jev-") && lowerModel != "jev-latest" {
		return false
	}

	// Check for answers field (required in Jev responses)
	if extractJSONRawField(respB, "answers") == nil {
		return false
	}

	// Check for Jev-specific request fields (state and questions)
	if extractJSONRawField(reqB, "state") == nil {
		return false
	}
	if extractJSONRawField(reqB, "questions") == nil {
		return false
	}

	return true
}

func JevSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	// Jev can be identified by path or by response headers/body
	if !isJevPath(baseSpan.Path) {
		// If not a known Jev path, check for Jev-like response body
		// First validate request shape to avoid unnecessary response processing
		reqB, ok := readHTTPRequestBody("JevSpan", req, baseSpan)
		if !ok {
			return *baseSpan, false
		}

		// Check request has Jev-specific fields before reading response
		if extractJSONRawField(reqB, "state") == nil {
			return *baseSpan, false
		}
		if extractJSONRawField(reqB, "questions") == nil {
			return *baseSpan, false
		}

		respB, ok := readHTTPResponseBody("JevSpan", resp, baseSpan)
		if !ok {
			return *baseSpan, false
		}

		if !looksLikeJevBody(reqB, respB) {
			return *baseSpan, false
		}
	}

	reqB, ok := readHTTPRequestBody("JevSpan", req, baseSpan)
	reqOK := ok
	if !reqOK && !isJevPath(baseSpan.Path) {
		return *baseSpan, false
	}

	respB, ok := readHTTPResponseBody("JevSpan", resp, baseSpan)
	respOK := ok
	if !respOK && !isJevPath(baseSpan.Path) {
		return *baseSpan, false
	}

	// Deliberately avoid logging full request/response bodies: they may
	// contain sensitive user content (state, questions, answers).
	slog.Debug("Jev", "requestBytes", len(reqB), "responseBytes", len(respB))

	var parsedRequest request.JevRequest
	if reqOK && len(reqB) > 0 {
		unmarshalJSONBestEffort(reqB, &parsedRequest)
		// Fallback: extract model from potentially truncated JSON
		if parsedRequest.Model == "" {
			parsedRequest.Model = extractModelField(reqB)
		}
	}

	var parsedResponse request.VendorJev
	if respOK && len(respB) > 0 {
		unmarshalJSONBestEffort(respB, &parsedResponse)
		// Extract fields that may appear before truncation
		if parsedResponse.ID == "" {
			parsedResponse.ID = extractJSONStringField(respB, "id", 0)
		}
		if parsedResponse.Model == "" {
			parsedResponse.Model = extractJSONStringField(respB, "model", 0)
		}
		if parsedResponse.Provider == "" {
			parsedResponse.Provider = extractJSONStringField(respB, "provider", 0)
		}
		// Extract usage container if present
		var usage request.JevUsage
		if unmarshalJSONContainerBestEffort(respB, &usage, "usage") {
			parsedResponse.Usage = usage
		}

		parsedResponse.Request = parsedRequest
		// Set operation name for Jev
		parsedResponse.OperationName = "decision"

		// Normalize provider name to match semconv enum
		if parsedResponse.Provider == "" {
			parsedResponse.Provider = "typesafe"
		}
		if parsedResponse.Provider == "jev-ai.org" {
			parsedResponse.Provider = "typesafe"
		}
	} else {
		// Body read failed or empty, create minimal span
		parsedResponse = request.VendorJev{
			Request:        parsedRequest,
			Provider:       "typesafe",
			Model:          parsedRequest.Model,
			OperationName:  "decision",
			Usage:          request.JevUsage{},
		}
	}

	baseSpan.SubType = request.HTTPSubtypeJev
	baseSpan.GenAI = &request.GenAI{
		Jev: &parsedResponse,
	}

	return *baseSpan, true
}
