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
	jevKnownHost       = "typesafe.ai"
	// typesafeAgentPrefix is the product token official TypeSafe SDKs send in
	// the User-Agent and X-TypeSafe-SDK request headers ("typesafe-sdk/<version>").
	typesafeAgentPrefix = "typesafe-sdk"
)

// isJevHost reports whether the request targets the official TypeSafe API
// host or a subdomain (e.g., api.typesafe.ai). It rejects lookalikes such as
// nottypesafe.ai and typesafe.ai.example.com.
func isJevHost(req *http.Request) bool {
	if req == nil {
		return false
	}
	host := strings.ToLower(extractHostname(req))

	if host == jevKnownHost {
		return true
	}

	if strings.HasSuffix(host, "."+jevKnownHost) {
		return strings.TrimSuffix(host, "."+jevKnownHost) != ""
	}

	return false
}

// hasTypeSafeAgent reports whether the request carries the product token that
// official TypeSafe SDKs send in the User-Agent and X-TypeSafe-SDK headers.
func hasTypeSafeAgent(req *http.Request) bool {
	if req == nil {
		return false
	}
	return hasTypeSafeAgentValue(req.Header.Get("X-TypeSafe-SDK")) ||
		hasTypeSafeAgentValue(req.Header.Get("User-Agent"))
}

func hasTypeSafeAgentValue(value string) bool {
	return len(value) >= len(typesafeAgentPrefix) &&
		strings.EqualFold(value[:len(typesafeAgentPrefix)], typesafeAgentPrefix)
}

func isJevPath(path string) bool {
	path = strings.TrimSuffix(path, "/")
	return strings.HasSuffix(path, jevSystemOnePath) ||
		strings.HasSuffix(path, jevSystemOnePathV1)
}

func JevSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	// Cheap metadata gate evaluated before any body is read: the System One
	// path plus either the official TypeSafe SDK headers or the TypeSafe host.
	// Detection runs on the ring-buffer path, so unrelated exchanges must not
	// pay for body reads or JSON scanning.
	if !isJevPath(baseSpan.Path) || (!hasTypeSafeAgent(req) && !isJevHost(req)) {
		return *baseSpan, false
	}

	reqB, reqOK := readHTTPRequestBody("JevSpan", req, baseSpan)
	respB, respOK := readHTTPResponseBody("JevSpan", resp, baseSpan)

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
		if len(parsedRequest.State) == 0 {
			parsedRequest.State = extractJSONRawField(reqB, "state")
		}
		if len(parsedRequest.Questions) == 0 {
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
			// Fall back to request model if response model is missing (e.g., error responses)
			if parsedResponse.Model == "" {
				parsedResponse.Model = parsedRequest.Model
			}
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
		if len(parsedResponse.Answers) == 0 {
			parsedResponse.Answers = extractJSONRawField(respB, "answers")
		}

		parsedResponse.Request = parsedRequest
		// Set operation name for Jev
		parsedResponse.OperationName = "decision"
	} else {
		// Body read failed or empty, create minimal span
		// Preserve request model even when response cannot be read
		parsedResponse = request.VendorJev{
			Request:       parsedRequest,
			Model:         parsedRequest.Model,
			OperationName: "decision",
			Usage:         request.JevUsage{},
		}
	}

	// Jev is a fixed TypeSafe provider, always normalize to "typesafe"
	parsedResponse.Provider = "typesafe"

	baseSpan.SubType = request.HTTPSubtypeJev
	baseSpan.GenAI = &request.GenAI{
		Jev: &parsedResponse,
	}

	return *baseSpan, true
}
