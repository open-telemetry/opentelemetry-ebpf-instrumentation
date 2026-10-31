// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const (
	jevSystemOnePath   = "/api/v1/systemone"
	jevSystemOnePathV1 = "/v1/systemone"
	jevKnownHost       = "jev-ai.org"
)

// extractHostname returns the hostname from the request, stripping any
// port number that may be present in req.URL.Host or req.Host.
func extractHostname(req *http.Request) string {
	if h := req.URL.Hostname(); h != "" {
		return h
	}
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// isJevHost reports whether the request targets a known Jev host or subdomain.
// Recognizes exact jev-ai.org and dot-delimited subdomains (e.g., api.jev-ai.org).
// Rejects notjev-ai.org and jev-ai.org.example.com.
func isJevHost(req *http.Request) bool {
	if req == nil {
		return false
	}
	host := extractHostname(req)
	host = strings.ToLower(host)

	// Check for exact match
	if host == jevKnownHost {
		return true
	}

	// Check for subdomain: *.jev-ai.org
	if strings.HasSuffix(host, "."+jevKnownHost) {
		// Ensure the part before the dot is not empty
		prefix := strings.TrimSuffix(host, "."+jevKnownHost)
		if prefix != "" {
			return true
		}
	}

	return false
}

// hasJSONKey checks if a top-level JSON key exists in the byte slice,
// even if its value is incomplete or truncated. It scans the JSON properly
// to avoid false matches inside strings or nested objects.
func hasJSONKey(data []byte, key string) bool {
	keyPattern := `"` + key + `"`
	keyLen := len(keyPattern)
	if len(data) == 0 {
		return false
	}

	// Simple state machine for JSON parsing
	// States: 0=outside, 1=in_string, 2=in_escape, 3=in_object, 4=in_array
	state := 0
	depth := 0 // nesting depth for objects/arrays
	i := 0

	for i < len(data) {
		c := data[i]

		switch state {
		case 0: // outside string
			if c == '"' {
				state = 1
			} else if c == '{' {
				depth++
			} else if c == '}' {
				depth--
			} else if c == '[' {
				depth++
			} else if c == ']' {
				depth--
			}
		case 1: // in string
			if c == '\\' {
				state = 2
			} else if c == '"' {
				state = 0
			}
		case 2: // in escape sequence
			state = 1
		}

		// Check for potential key match at top level (depth 1, outside string)
		if state == 0 && depth == 1 && c == '"' && i+keyLen < len(data) {
			// Check if this could be our key
			if string(data[i:i+keyLen]) == keyPattern {
				// Verify it's followed by whitespace and a colon
				j := i + keyLen
				// Skip whitespace
				for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r') {
					j++
				}
				// Check for colon
				if j < len(data) && data[j] == ':' {
					return true
				}
			}
		}

		i++
	}

	return false
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
		// If no model, check for error field - gateway may return error without model
		if hasJSONKey(respB, "error") {
			// Check if request has Jev-specific fields
			if hasJSONKey(reqB, "state") && hasJSONKey(reqB, "questions") {
				return true
			}
		}
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
	// Use tolerant key detection for partial bodies
	if !hasJSONKey(reqB, "state") {
		return false
	}
	if !hasJSONKey(reqB, "questions") {
		return false
	}

	return true
}

func JevSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	// Jev can be identified by path or by response headers/body
	// For path-based detection, we need to be careful about false positives:
	// - Known Jev host (jev-ai.org or subdomains): path match is sufficient
	// - Gateway or other hosts: require sufficient Jev-specific evidence
	knownJevHost := isJevHost(req)

	if !isJevPath(baseSpan.Path) {
		// If not a known Jev path, check for Jev-like response body
		// Use tolerant key detection for partial bodies
		reqB, ok := readHTTPRequestBody("JevSpan", req, baseSpan)
		if !ok {
			return *baseSpan, false
		}

		// Check request has Jev-specific fields using tolerant detection
		if !hasJSONKey(reqB, "state") {
			return *baseSpan, false
		}
		if !hasJSONKey(reqB, "questions") {
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

		// Check request has Jev-specific fields using tolerant detection
		if !hasJSONKey(reqB, "state") {
			return *baseSpan, false
		}
		if !hasJSONKey(reqB, "questions") {
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
		// Even if unmarshal fails, try to extract fields individually
		if len(parsedRequest.State) == 0 && hasJSONKey(reqB, "state") {
			parsedRequest.State = extractJSONRawField(reqB, "state")
		}
		if len(parsedRequest.Questions) == 0 && hasJSONKey(reqB, "questions") {
			parsedRequest.Questions = extractJSONRawField(reqB, "questions")
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
		// Extract answers if present (may be truncated)
		if len(parsedResponse.Answers) == 0 && hasJSONKey(respB, "answers") {
			parsedResponse.Answers = extractJSONRawField(respB, "answers")
		}

		parsedResponse.Request = parsedRequest
		// Set operation name for Jev
		parsedResponse.OperationName = "decision"

		// Normalize provider name to match semconv enum
		// Jev is a fixed TypeSafe provider, always normalize to "typesafe"
		parsedResponse.Provider = "typesafe"
	} else {
		// Body read failed or empty, create minimal span
		// Preserve request model even when response cannot be read
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
