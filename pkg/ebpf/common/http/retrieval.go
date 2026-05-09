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
//
// Known hosts are treated as a strong provider-identification signal, but not
// as a hard requirement for classifying a request as retrieval. This keeps the
// detector extensible for self-hosted deployments, custom domains and cloud
// vendor-managed endpoints while still preserving precise provider names when
// they can be inferred from the hostname.
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

var retrievalPathSignals = []string{
	"/query",
	"/search",
	"/points/search",
	"/points/query",
	"/vector/search",
	"/entities/search",
}

var retrievalBodySignals = []string{
	`"vector"`,
	`"top_k"`,
	`"topK"`,
	`"limit"`,
	`"namespace"`,
	`"collection"`,
	`"collectionName"`,
	`"collection_name"`,
	`"query_embeddings"`,
}

const genericRetrievalProvider = "generic"

var weaviateGraphQLRetrievalSignals = []string{
	"nearvector",
	"neartext",
	"nearobject",
	"hybrid",
	"bm25",
}

func parseRetrievalProvider(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}

	host := extractHostname(req)
	path := normalizedRetrievalPath(req)

	for _, hp := range retrievalHostPatterns {
		if (host == hp.hostSuffix || strings.HasSuffix(host, "."+hp.hostSuffix)) &&
			strings.HasSuffix(path, hp.pathSuffix) {
			return hp.provider
		}
	}

	return ""
}

func normalizedRetrievalPath(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}

	path := strings.TrimSpace(req.URL.Path)
	if path == "" {
		return ""
	}
	if path == "/" {
		return "/"
	}
	return strings.TrimSuffix(path, "/")
}

func hasRetrievalPathSignal(path string) bool {
	for _, signal := range retrievalPathSignals {
		if strings.HasSuffix(path, signal) {
			return true
		}
	}
	return false
}

func retrievalBodySignalCount(body []byte) int {
	if len(body) == 0 {
		return 0
	}

	count := 0
	for _, signal := range retrievalBodySignals {
		if bytes.Contains(body, []byte(signal)) {
			count++
		}
	}
	return count
}

func detectRetrievalProvider(req *http.Request, body []byte) string {
	if req == nil || req.URL == nil {
		return ""
	}
	if req.Method != http.MethodPost {
		return ""
	}

	provider := parseRetrievalProvider(req)
	path := normalizedRetrievalPath(req)

	if provider == "weaviate" {
		if hasWeaviateRetrievalSignals(body) {
			return provider
		}
		return ""
	}

	if provider != "" {
		return provider
	}

	if path == "/v1/graphql" {
		if hasWeaviateRetrievalSignals(body) {
			return genericRetrievalProvider
		}
		return ""
	}

	if !hasRetrievalPathSignal(path) {
		return ""
	}

	if retrievalBodySignalCount(body) < 2 {
		return ""
	}

	return genericRetrievalProvider
}

func isWeaviateRetrievalGraphQLQuery(query string) bool {
	normalized := strings.Join(strings.Fields(strings.ToLower(query)), " ")
	// GraphQL allows `Get {` and `Get{` interchangeably; accept both to avoid
	// false negatives when clients omit the space before the selection set.
	if !strings.Contains(normalized, "get {") && !strings.Contains(normalized, "get{") {
		return false
	}

	for _, signal := range weaviateGraphQLRetrievalSignals {
		if strings.Contains(normalized, signal) {
			return true
		}
	}

	return false
}

func weaviateTopLevelQuery(body []byte) string {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return ""
	}

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			break
		}

		key, ok := keyTok.(string)
		if !ok {
			break
		}

		if key == "query" {
			var query string
			if err := dec.Decode(&query); err == nil {
				return query
			}
			return ""
		}

		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			break
		}
	}

	return ""
}

func hasWeaviateRetrievalSignals(body []byte) bool {
	if len(body) == 0 {
		return false
	}

	if query := weaviateTopLevelQuery(body); query != "" {
		return isWeaviateRetrievalGraphQLQuery(query)
	}

	if !bytes.Contains(body, []byte(`"query"`)) {
		return false
	}

	return isWeaviateRetrievalGraphQLQuery(string(body))
}

// retrievalNeedsBodyProbe returns true when the request's method / host / path
// could plausibly correspond to a vector retrieval call. It is intentionally a
// cheap pre-check so non-retrieval traffic bypasses the request-body read in
// [RetrievalSpan] entirely.
func retrievalNeedsBodyProbe(req *http.Request) bool {
	if req == nil || req.URL == nil || req.Method != http.MethodPost {
		return false
	}
	if parseRetrievalProvider(req) != "" {
		return true
	}
	path := normalizedRetrievalPath(req)
	return path == "/v1/graphql" || hasRetrievalPathSignal(path)
}

// RetrievalSpan detects vector retrieval (similarity search) API calls based
// on a combination of provider-specific host matches and generic path/body
// heuristics, then extracts retrieval-specific fields into the span.
//
// Body parsing is best-effort: once retrieval is detected, spans are
// classified even if request/response parsing fails. For GraphQL requests at
// /v1/graphql, body-level retrieval signals are required to reduce false
// positives on non-retrieval operations.
func RetrievalSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if !retrievalNeedsBodyProbe(req) {
		return *baseSpan, false
	}

	var reqB []byte
	if req.Body != nil {
		var err error
		reqB, err = io.ReadAll(req.Body)
		if err != nil {
			slog.Debug("RetrievalSpan: failed to read request body, continuing without it", "error", err)
		}
		req.Body = io.NopCloser(bytes.NewBuffer(reqB))
	}

	provider := detectRetrievalProvider(req, reqB)
	if provider == "" {
		return *baseSpan, false
	}

	respB, err := getResponseBody(resp)
	if err != nil {
		slog.Debug("RetrievalSpan: failed to read response body, continuing without it", "provider", provider, "error", err)
	}

	// Deliberately avoid logging full request/response bodies: they may
	// contain sensitive user content and can be large. Log only minimal
	// metadata sufficient for troubleshooting.
	slog.Debug("Retrieval", "provider", provider, "path", requestPath(req),
		"requestBytes", len(reqB), "responseBytes", len(respB))

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
