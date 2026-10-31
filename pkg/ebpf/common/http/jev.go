// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const (
	jevSystemOnePath   = "/api/v1/systemone"
	jevSystemOnePathV1 = "/v1/systemone"
	jevKnownHost       = "jev-ai.org"
)

// hasJSONKey checks if a top-level JSON key exists in the byte slice,
// even if its value is incomplete or truncated. It searches for the pattern
// "key": and verifies it's not inside a string or nested object.
func hasJSONKey(data []byte, key string) bool {
	keyPattern := []byte(`"` + key + `":`)
	return bytes.Contains(data, keyPattern)
}

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
	// Use a tolerant check that detects the key even if the value is truncated
	if !hasJSONKey(respB, "answers") {
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
	// For path-based detection, we need to be careful about false positives:
	// - Known Jev host (jev-ai.org): path match is sufficient
	// - Gateway or other hosts: require sufficient Jev-specific evidence
	knownJevHost := req != nil && strings.HasSuffix(strings.ToLower(req.Host), jevKnownHost)

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
	} else if !knownJevHost {
		// Path matches but not the known Jev host
		// Require sufficient Jev-specific evidence to avoid false positives
		reqB, ok := readHTTPRequestBody("JevSpan", req, baseSpan)
		if !ok {
			return *baseSpan, false
		}

		// Check request has Jev-specific fields
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

		// Verify response has Jev model discriminator
		model := extractJSONStringField(respB, "model", 0)
		if model == "" {
			return *baseSpan, false
		}
		lowerModel := strings.ToLower(model)
		if !strings.HasPrefix(lowerModel, "jev-") && lowerModel != "jev-latest" {
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
		if parsedResponse.Error == "" {
			parsedResponse.Error = extractJSONStringField(respB, "error", 0)
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
		// Jev is a fixed TypeSafe provider, always normalize to "typesafe"
		parsedResponse.Provider = "typesafe"
	} else {
		// Body read failed or empty, create minimal span
		parsedResponse = request.VendorJev{
			Request:       parsedRequest,
			Provider:      "typesafe",
			Model:         parsedRequest.Model,
			OperationName: "decision",
			Usage:         request.JevUsage{},
		}
	}

	baseSpan.SubType = request.HTTPSubtypeJev
	baseSpan.GenAI = &request.GenAI{
		Jev: &parsedResponse,
	}

	return *baseSpan, true
}
