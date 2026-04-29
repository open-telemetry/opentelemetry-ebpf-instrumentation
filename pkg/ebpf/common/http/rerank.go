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

// rerankProviders maps hostname substrings to GenAI provider names.
var rerankProviders = []struct {
	host     string
	provider string
}{
	{"cohere.com", "cohere"},
	{"cohere.ai", "cohere"},
	{"jina.ai", "jina"},
	{"voyageai.com", "voyageai"},
	{"dashscope.aliyuncs.com", "dashscope"},
	{"dashscope.aliyun.com", "dashscope"},
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
func rerankProviderFromHost(req *http.Request) string {
	host := rerankHostname(req)
	for _, p := range rerankProviders {
		if strings.Contains(host, p.host) {
			return p.provider
		}
	}
	return "unknown"
}

// rerankHostname returns the hostname from the request URL or Host header.
func rerankHostname(req *http.Request) string {
	if req.URL != nil && req.URL.Host != "" {
		return strings.ToLower(req.URL.Host)
	}
	if req.Host != "" {
		return strings.ToLower(req.Host)
	}
	return ""
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
func RerankSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if !isRerankPath(req) {
		return *baseSpan, false
	}

	reqB, err := io.ReadAll(req.Body)
	if err != nil && len(reqB) == 0 {
		return *baseSpan, false
	}
	req.Body = io.NopCloser(bytes.NewBuffer(reqB))

	respB, err := getResponseBody(resp)
	if err != nil && len(respB) == 0 {
		return *baseSpan, false
	}

	slog.Debug("Rerank", "request", string(reqB), "response", string(respB))

	var parsedRequest request.RerankRequest
	if err := json.Unmarshal(reqB, &parsedRequest); err != nil {
		slog.Debug("failed to parse rerank request", "error", err)
		// Fallback: extract model from potentially truncated JSON.
		if parsedRequest.Model == "" {
			parsedRequest.Model = extractModelFromPartialJSON(reqB)
		}
	}

	var parsedResponse request.RerankResponse
	if err := json.Unmarshal(respB, &parsedResponse); err != nil {
		slog.Debug("failed to parse rerank response", "error", err)
	}

	provider := rerankProviderFromHost(req)

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
