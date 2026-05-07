// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// rerankProviders maps hostname suffixes to GenAI provider names.
// Provider names are aligned with existing canonical names used elsewhere
// in the codebase (e.g. embedding uses "voyage" for Voyage AI).
var rerankProviders = []struct {
	hostSuffix string
	provider   string
}{
	{"cohere.com", "cohere"},
	{"cohere.ai", "cohere"},
	{"jina.ai", "jina"},
	{"voyageai.com", "voyage"},
	{"dashscope.aliyuncs.com", "qwen"},
	{"dashscope.aliyun.com", "qwen"},
}

// isRerankPath returns true when the request URL path contains a rerank
// endpoint segment (e.g. /v1/rerank, /v2/rerank).
func isRerankPath(req *http.Request) bool {
	path := rerankRequestPath(req)
	return strings.Contains(path, "/rerank")
}

// rerankRequestPath extracts the request path from multiple URL representations,
// handling opaque URLs and fallback to RequestURI.
func rerankRequestPath(req *http.Request) string {
	if req == nil {
		return ""
	}
	if req.URL != nil {
		if req.URL.Path != "" {
			return req.URL.Path
		}
		if req.URL.Opaque != "" {
			if parsed, err := url.Parse(req.URL.Opaque); err == nil && parsed.Path != "" {
				return parsed.Path
			}
			if strings.HasPrefix(req.URL.Opaque, "/") {
				return req.URL.Opaque
			}
		}
	}
	if req.RequestURI == "" {
		return ""
	}
	if parsed, err := url.ParseRequestURI(req.RequestURI); err == nil && parsed.Path != "" {
		return parsed.Path
	}
	return req.RequestURI
}

// rerankProviderFromHost returns the provider name based on the request
// hostname.  It falls back to "unknown" when no known provider matches.
// Uses suffix matching (like EmbeddingSpan) to avoid false positives.
func rerankProviderFromHost(req *http.Request) string {
	host := extractHostname(req)
	for _, p := range rerankProviders {
		if host == p.hostSuffix || strings.HasSuffix(host, "."+p.hostSuffix) {
			return p.provider
		}
	}
	return "unknown"
}

// modelPattern extracts the "model" value from potentially truncated JSON.
var modelPattern = regexp.MustCompile(`"model"\s*:\s*"([^"]+)"`)

// extractModelFromPartialJSON attempts to extract the model field from
// potentially truncated JSON using a simple regex.  This is a fallback
// when standard json.Unmarshal fails due to eBPF buffer truncation.
func extractModelFromPartialJSON(data []byte) string {
	m := modelPattern.FindSubmatch(data)
	if m != nil {
		return string(m[1])
	}
	return ""
}

// RerankSpan detects rerank API calls by URL path matching and parses
// the request/response bodies into GenAI rerank attributes.
// Body parsing is best-effort: once the rerank path is detected, the span
// is always classified as rerank regardless of body read/parse failures.
func RerankSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if !isRerankPath(req) {
		return *baseSpan, false
	}

	provider := rerankProviderFromHost(req)

	// Request body parsing is best-effort: since the provider is already
	// confirmed by URL path, a body read failure should not prevent
	// classification.
	var reqB []byte
	if req.Body != nil {
		var err error
		reqB, err = io.ReadAll(req.Body)
		if err != nil {
			slog.Debug("RerankSpan: failed to read request body, continuing without it", "provider", provider, "error", err)
		}
		req.Body = io.NopCloser(bytes.NewBuffer(reqB))
	}

	// Response body parsing is best-effort: truncated responses may fail
	// to parse but should not prevent provider detection.
	respB, err := getResponseBody(resp)
	if err != nil {
		slog.Debug("RerankSpan: failed to read response body, continuing without it", "provider", provider, "error", err)
	}

	slog.Debug("Rerank", "provider", provider, "request", string(reqB), "response", string(respB))

	var parsedRequest request.RerankRequest
	if len(reqB) > 0 {
		if err := json.Unmarshal(reqB, &parsedRequest); err != nil {
			slog.Debug("failed to parse rerank request", "provider", provider, "error", err)
			// Fallback: extract model from potentially truncated JSON.
			if parsedRequest.Model == "" {
				parsedRequest.Model = extractModelFromPartialJSON(reqB)
			}
		}
	}

	var parsedResponse request.RerankResponse
	if len(respB) > 0 {
		if err := json.Unmarshal(respB, &parsedResponse); err != nil {
			slog.Debug("failed to parse rerank response", "provider", provider, "error", err)
		}
	}

	baseSpan.SubType = request.HTTPSubtypeRerank
	baseSpan.GenAI = &request.GenAI{
		Rerank: &request.VendorRerank{
			Input:    parsedRequest,
			Output:   parsedResponse,
			Provider: provider,
		},
	}

	return *baseSpan, true
}
