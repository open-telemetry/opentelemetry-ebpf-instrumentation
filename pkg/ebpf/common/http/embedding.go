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
// the model dimension count of a single output vector. It supports the OpenAI-style
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

	// Cohere v2 layout: {"embeddings":{"float":[[...]],"binary":[[...]]}}
	var cohereStyle struct {
		Embeddings map[string]json.RawMessage `json:"embeddings"`
	}
	if unmarshalJSON(body, &cohereStyle) {
		if n := cohereEmbeddingDimensions(cohereStyle.Embeddings); n > 0 {
			return n
		}
	}

	return 0
}

// cohereBinaryPackedDims is the number of model dimensions packed into each
// byte entry of a Cohere v2 binary/ubinary embedding vector.
const cohereBinaryPackedDims = 8

// cohereEmbeddingDimensions derives the model dimension count from Cohere v2
// embeddings, keyed by embedding type. Non-packed types are preferred because
// their entry count equals the dimension count; binary/ubinary vectors pack
// eight dimensions into each byte entry, so their length is expanded.
func cohereEmbeddingDimensions(embeddings map[string]json.RawMessage) int {
	for _, key := range []string{"float", "int8", "uint8"} {
		if n := cohereVectorLength(embeddings, key); n > 0 {
			return n
		}
	}

	for _, key := range []string{"binary", "ubinary"} {
		if n := cohereVectorLength(embeddings, key); n > 0 {
			return n * cohereBinaryPackedDims
		}
	}

	return 0
}

// cohereVectorLength returns the entry count of the first vector under the
// given embedding type key, or 0 when the key is absent or its value is not
// a numeric matrix.
func cohereVectorLength(embeddings map[string]json.RawMessage, key string) int {
	raw, ok := embeddings[key]
	if !ok {
		return 0
	}

	var vectors [][]json.Number
	if !unmarshalJSON(raw, &vectors) || len(vectors) == 0 {
		return 0
	}

	return len(vectors[0])
}
