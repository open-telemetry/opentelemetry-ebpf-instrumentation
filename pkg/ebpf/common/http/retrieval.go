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

// retrievalHostPattern pairs a known vector database hostname suffix with a
// URL path suffix and the provider name to assign when both match.
// Detection is host-anchored (like EmbeddingSpan) to keep false positives
// close to zero: a request is only classified as retrieval when it targets
// a known vector store endpoint.
type retrievalHostPattern struct {
	hostSuffix string
	pathSuffix string
	provider   string
}

// retrievalHostPatterns enumerates known vector retrieval (similarity
// search) endpoints. Paths use suffix matching so that collection / index
// IDs embedded in the path (Qdrant, Milvus, Chroma) are handled naturally.
//
// References (public docs):
//   - Pinecone:  POST /query, POST /vectors/query on *.pinecone.io
//   - Qdrant:    POST /collections/{name}/points/search|query on *.qdrant.tech / *.qdrant.io
//   - Milvus:    POST /v1/vector/search, /v2/vectordb/entities/search on *.milvus.io
//   - Zilliz:    same Milvus paths on *.zillizcloud.com
//   - Chroma:    POST /api/v1/collections/{id}/query on *.trychroma.com
//   - Weaviate:  POST /v1/graphql on *.weaviate.io / *.weaviate.cloud / *.weaviate.network
var retrievalHostPatterns = []retrievalHostPattern{
	// Pinecone
	{"pinecone.io", "/query", "pinecone"},
	{"pinecone.io", "/vectors/query", "pinecone"},
	// Qdrant
	{"qdrant.tech", "/points/search", "qdrant"},
	{"qdrant.tech", "/points/query", "qdrant"},
	{"qdrant.io", "/points/search", "qdrant"},
	{"qdrant.io", "/points/query", "qdrant"},
	// Milvus / Zilliz
	{"milvus.io", "/vector/search", "milvus"},
	{"milvus.io", "/entities/search", "milvus"},
	{"zillizcloud.com", "/vector/search", "zilliz"},
	{"zillizcloud.com", "/entities/search", "zilliz"},
	// Chroma
	{"trychroma.com", "/query", "chroma"},
	// Weaviate (GraphQL-based similarity search)
	{"weaviate.io", "/v1/graphql", "weaviate"},
	{"weaviate.cloud", "/v1/graphql", "weaviate"},
	{"weaviate.network", "/v1/graphql", "weaviate"},
}

// parseRetrievalProvider returns the provider name when the request targets
// a known vector retrieval endpoint (host suffix + path suffix match), and
// an empty string otherwise.
func parseRetrievalProvider(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}

	host := extractHostname(req)
	path := strings.TrimSuffix(req.URL.Path, "/")

	for _, hp := range retrievalHostPatterns {
		if (host == hp.hostSuffix || strings.HasSuffix(host, "."+hp.hostSuffix)) &&
			strings.HasSuffix(path, hp.pathSuffix) {
			return hp.provider
		}
	}

	return ""
}

// RetrievalSpan detects vector retrieval (similarity search) API calls to
// known vector databases based on hostname and URL path matching, and
// extracts retrieval-specific fields into the span.
//
// Body parsing is best-effort: once the provider is confirmed by the URL,
// the span is always classified as retrieval even if the body cannot be
// read or parsed (e.g. due to eBPF payload truncation).
func RetrievalSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	provider := parseRetrievalProvider(req)
	if provider == "" {
		return *baseSpan, false
	}

	var reqB []byte
	if req.Body != nil {
		var err error
		reqB, err = io.ReadAll(req.Body)
		if err != nil {
			slog.Debug("RetrievalSpan: failed to read request body, continuing without it", "provider", provider, "error", err)
		}
		req.Body = io.NopCloser(bytes.NewBuffer(reqB))
	}

	respB, err := getResponseBody(resp)
	if err != nil {
		slog.Debug("RetrievalSpan: failed to read response body, continuing without it", "provider", provider, "error", err)
	}

	slog.Debug("Retrieval", "provider", provider, "request", string(reqB), "response", string(respB))

	var parsedRequest request.RetrievalRequest
	if len(reqB) > 0 {
		if err := json.Unmarshal(reqB, &parsedRequest); err != nil {
			slog.Debug("failed to parse retrieval request", "provider", provider, "error", err)
		}
	}

	var parsedResponse request.RetrievalResponse
	if len(respB) > 0 {
		if err := json.Unmarshal(respB, &parsedResponse); err != nil {
			slog.Debug("failed to parse retrieval response", "provider", provider, "error", err)
		}
	}

	baseSpan.SubType = request.HTTPSubtypeRetrieval
	baseSpan.GenAI = &request.GenAI{
		Retrieval: &request.VendorRetrieval{
			Provider: provider,
			Input:    parsedRequest,
			Output:   parsedResponse,
		},
	}

	return *baseSpan, true
}
