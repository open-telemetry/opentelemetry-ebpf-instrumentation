// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// embeddingHostPattern pairs a known hostname suffix with a required URL path
// suffix and the provider name to assign when matched.
type embeddingHostPattern struct {
	hostSuffix string
	pathSuffix string
	provider   string
}

// embeddingHostPatterns lists known embedding API hosts and their required
// URL path suffixes. Matching is performed by hostname suffix and path suffix,
// which naturally handles arbitrary path prefixes before the API suffix.
var embeddingHostPatterns = []embeddingHostPattern{
	{"api.voyageai.com", "/v1/embeddings", "voyage"},
	{"api.cohere.com", "/v2/embed", "cohere"},
	{"api.jina.ai", "/v1/embeddings", "jina"},
}

// parseEmbeddingProvider checks whether the request targets a known embedding-only
// provider by matching the hostname and URL path against embeddingHostPatterns.
// Returns the provider name if matched, or empty string otherwise.
func parseEmbeddingProvider(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}

	host := extractHostname(req)
	path := strings.TrimSuffix(req.URL.Path, "/")

	for _, hp := range embeddingHostPatterns {
		if (host == hp.hostSuffix || strings.HasSuffix(host, "."+hp.hostSuffix)) &&
			strings.HasSuffix(path, hp.pathSuffix) {
			return hp.provider
		}
	}

	return ""
}

// EmbeddingSpan detects embedding API calls to Voyage AI, Cohere, and Jina AI
// based on hostname and URL path matching, and extracts embedding-specific
// fields into the span.
func EmbeddingSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	provider := parseEmbeddingProvider(req)
	if provider == "" {
		return *baseSpan, false
	}

	reqB := readHTTPRequestBodyLenient("EmbeddingSpan", req, baseSpan, "provider", provider)
	respB := readHTTPResponseBodyLenient("EmbeddingSpan", resp, baseSpan, "provider", provider)

	slog.Debug("Embedding", "provider", provider, "request", string(reqB), "response", string(respB))

	parsedRequest := parseEmbeddingRequest(reqB)

	var parsedResponse request.EmbeddingResponse
	if len(respB) > 0 && !unmarshalJSON(respB, &parsedResponse) {
		slog.Debug("failed to parse embedding response", "provider", provider)
	}
	var usage request.EmbeddingUsage
	if unmarshalJSONContainerBestEffort(respB, &usage, "usage") {
		parsedResponse.Usage.PromptTokens.Merge(usage.PromptTokens)
		parsedResponse.Usage.TotalTokens.Merge(usage.TotalTokens)
	}
	var billedUnits request.CohereBilledUnits
	if unmarshalJSONContainerBestEffort(respB, &billedUnits, "meta", "billed_units") {
		if parsedResponse.Meta == nil {
			parsedResponse.Meta = &request.CohereResponseMeta{}
		}
		if parsedResponse.Meta.BilledUnits == nil {
			parsedResponse.Meta.BilledUnits = &request.CohereBilledUnits{}
		}
		parsedResponse.Meta.BilledUnits.InputTokens.Merge(billedUnits.InputTokens)
	}
	if parsedResponse.Dimensions == 0 {
		parsedResponse.Dimensions = parseEmbeddingDimensions(respB)
	}

	baseSpan.SubType = request.HTTPSubtypeEmbedding
	baseSpan.GenAI = &request.GenAI{
		Embedding: &request.VendorEmbedding{
			Provider: provider,
			Model:    parsedRequest.Model,
			Input:    parsedRequest,
			Output:   parsedResponse,
		},
	}

	return *baseSpan, true
}

// parseEmbeddingDimensions inspects a raw embedding response body and returns
// the length of a single output vector. It supports the OpenAI-style
// data[].embedding layout (Voyage, Jina) and the Cohere v2
// embeddings.{float,int8,...}[][] layout. Returns 0 when not determinable.
func parseEmbeddingDimensions(body []byte) int {
	if len(body) == 0 {
		return 0
	}

	// OpenAI-style layout: {"data":[{"embedding":[...]}]}
	var openAIStyle struct {
		Data []struct {
			Embedding []json.Number `json:"embedding"`
		} `json:"data"`
	}
	if unmarshalJSON(body, &openAIStyle) && len(openAIStyle.Data) > 0 {
		if n := len(openAIStyle.Data[0].Embedding); n > 0 {
			return n
		}
	}

	// Cohere v2 layout: {"embeddings":{"float":[[...]]}}
	var cohereStyle struct {
		Embeddings map[string][][]json.Number `json:"embeddings"`
	}
	if unmarshalJSON(body, &cohereStyle) {
		for _, vectors := range cohereStyle.Embeddings {
			if len(vectors) > 0 {
				if n := len(vectors[0]); n > 0 {
					return n
				}
			}
		}
	}

	return 0
}
