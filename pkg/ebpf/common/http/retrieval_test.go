// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const pineconeQueryRequest = `{
  "namespace": "ns1",
  "topK": 3,
  "vector": [0.1, 0.2, 0.3, 0.4]
}`

const pineconeQueryResponse = `{
  "matches": [
    {"id": "doc-1", "score": 0.91},
    {"id": "doc-2", "score": 0.82},
    {"id": "doc-3", "score": 0.75}
  ],
  "namespace": "ns1",
  "usage": {"readUnits": 5}
}`

const qdrantSearchRequest = `{
  "vector": [0.1, 0.2, 0.3],
  "limit": 5
}`

const qdrantSearchResponse = `{
  "result": [
    {"id": 1, "score": 0.95},
    {"id": 2, "score": 0.88}
  ],
  "status": "ok"
}`

const milvusSearchRequest = `{
  "collectionName": "documents",
  "vector": [0.1, 0.2, 0.3],
  "limit": 10
}`

const milvusSearchResponse = `{
  "code": 0,
  "data": [
    {"id": "1", "distance": 0.1},
    {"id": "2", "distance": 0.2}
  ]
}`

func TestRetrievalSpan_Pinecone(t *testing.T) {
	req := makeRequest(t, http.MethodPost,
		"https://example-abc.svc.us-east1-aws.pinecone.io/query", pineconeQueryRequest)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, pineconeQueryResponse)

	base := &request.Span{}
	span, ok := RetrievalSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Retrieval)
	assert.Equal(t, request.HTTPSubtypeRetrieval, span.SubType)

	ai := span.GenAI.Retrieval
	assert.Equal(t, "pinecone", ai.Provider)
	assert.Equal(t, "retrieval", ai.OperationName())
	assert.Equal(t, "ns1", ai.GetCollection())
}

func TestRetrievalSpan_Qdrant(t *testing.T) {
	req := makeRequest(t, http.MethodPost,
		"https://my-cluster.aws.qdrant.io/collections/my_coll/points/search",
		qdrantSearchRequest)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, qdrantSearchResponse)

	base := &request.Span{}
	span, ok := RetrievalSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.Retrieval)
	assert.Equal(t, "qdrant", span.GenAI.Retrieval.Provider)
}

func TestRetrievalSpan_Milvus(t *testing.T) {
	req := makeRequest(t, http.MethodPost,
		"https://in01-xxxx.aws-us-west-2.vectordb.zillizcloud.com/v2/vectordb/entities/search",
		milvusSearchRequest)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, milvusSearchResponse)

	base := &request.Span{}
	span, ok := RetrievalSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.Retrieval)
	assert.Equal(t, "zilliz", span.GenAI.Retrieval.Provider)
	assert.Equal(t, "documents", span.GenAI.Retrieval.GetCollection())
}

func TestRetrievalSpan_UnknownHost_GenericDetection(t *testing.T) {
	req := makeRequest(t, http.MethodPost,
		"https://api.example.com/v1/search", `{"vector":[0.1],"top_k":3,"collection":"docs"}`)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, `{"matches":[]}`)

	base := &request.Span{}
	span, ok := RetrievalSpan(base, req, resp)
	require.True(t, ok)
	require.NotNil(t, span.GenAI.Retrieval)
	assert.Equal(t, genericRetrievalProvider, span.GenAI.Retrieval.Provider)
}

func TestRetrievalSpan_UnknownHost_InsufficientSignals(t *testing.T) {
	req := makeRequest(t, http.MethodPost,
		"https://api.example.com/v1/search", `{"query":"hello"}`)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, `{"matches":[]}`)

	base := &request.Span{}
	_, ok := RetrievalSpan(base, req, resp)
	assert.False(t, ok)
}

func TestParseRetrievalProvider(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{"pinecone /query", "https://idx.pinecone.io/query", "pinecone"},
		{"pinecone /vectors/query", "https://idx.svc.us.pinecone.io/vectors/query", "pinecone"},
		{"qdrant points/search", "https://c.aws.qdrant.io/collections/n/points/search", "qdrant"},
		{"qdrant points/query", "https://c.aws.qdrant.tech/collections/n/points/query", "qdrant"},
		{"milvus v1 vector/search", "https://x.milvus.io/v1/vector/search", "milvus"},
		{"zilliz entities/search", "https://x.zillizcloud.com/v2/vectordb/entities/search", "zilliz"},
		{"chroma /query", "https://x.trychroma.com/api/v1/collections/id/query", "chroma"},
		{"weaviate /v1/graphql", "https://x.weaviate.cloud/v1/graphql", "weaviate"},
		{"unknown host", "https://api.example.com/v1/query", ""},
		{"wrong path for pinecone", "https://idx.pinecone.io/describe_index_stats", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := makeRequest(t, http.MethodPost, tt.url, "{}")
			assert.Equal(t, tt.expected, parseRetrievalProvider(req))
		})
	}
}

func TestDetectRetrievalProvider(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		url      string
		body     string
		expected string
	}{
		{
			name:     "known provider still wins",
			method:   http.MethodPost,
			url:      "https://idx.pinecone.io/query",
			body:     pineconeQueryRequest,
			expected: "pinecone",
		},
		{
			name:     "unknown host generic retrieval",
			method:   http.MethodPost,
			url:      "https://vector.company.internal/v1/search",
			body:     `{"vector":[0.1],"limit":5,"collection":"docs"}`,
			expected: genericRetrievalProvider,
		},
		{
			name:     "unknown host query path",
			method:   http.MethodPost,
			url:      "https://gateway.example.com/api/query",
			body:     `{"namespace":"ns1","topK":3,"vector":[0.1]}`,
			expected: genericRetrievalProvider,
		},
		{
			name:     "get method is ignored",
			method:   http.MethodGet,
			url:      "https://vector.company.internal/v1/search",
			body:     `{"vector":[0.1],"limit":5}`,
			expected: "",
		},
		{
			name:     "insufficient body signals",
			method:   http.MethodPost,
			url:      "https://vector.company.internal/v1/search",
			body:     `{"query":"hello"}`,
			expected: "",
		},
		{
			name:     "graphql retrieval on unknown host",
			method:   http.MethodPost,
			url:      "https://gateway.example.com/v1/graphql",
			body:     `{"query":"{ Get { Article(nearText: { concepts: [\"biology\"] }, limit: 3) { title } } }"}`,
			expected: genericRetrievalProvider,
		},
		{
			name:     "graphql non retrieval on unknown host",
			method:   http.MethodPost,
			url:      "https://gateway.example.com/v1/graphql",
			body:     `{"query":"{ Aggregate { Article { meta { count } } } }"}`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.method == http.MethodPost {
				req = makeRequest(t, http.MethodPost, tt.url, tt.body)
			} else {
				var err error
				req, err = http.NewRequest(tt.method, tt.url, strings.NewReader(tt.body))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")
			}
			assert.Equal(t, tt.expected, detectRetrievalProvider(req, []byte(tt.body)))
		})
	}
}

func TestRetrievalSpan_WeaviateGraphQL(t *testing.T) {
	t.Run("retrieval query", func(t *testing.T) {
		req := makeRequest(t, http.MethodPost,
			"https://x.weaviate.cloud/v1/graphql",
			`{"query":"{ Get { Article(nearText: { concepts: [\"biology\"] }, limit: 3) { title } } }"}`,
		)
		resp := makePlainResponse(http.StatusOK, http.Header{
			"Content-Type": []string{"application/json"},
		}, `{"data":{"Get":{"Article":[]}}}`)

		base := &request.Span{}
		span, ok := RetrievalSpan(base, req, resp)
		require.True(t, ok)
		require.NotNil(t, span.GenAI.Retrieval)
		assert.Equal(t, "weaviate", span.GenAI.Retrieval.Provider)
	})

	t.Run("retrieval query with newlines and whitespace", func(t *testing.T) {
		req := makeRequest(t, http.MethodPost,
			"https://x.weaviate.cloud/v1/graphql",
			`{"query":"{\n  Get\t{\n    Article(\n      nearText: { concepts: [\"biology\"] }\n      limit: 3\n    ) {\n      title\n    }\n  }\n}"}`,
		)
		resp := makePlainResponse(http.StatusOK, http.Header{
			"Content-Type": []string{"application/json"},
		}, `{"data":{"Get":{"Article":[]}}}`)

		base := &request.Span{}
		span, ok := RetrievalSpan(base, req, resp)
		require.True(t, ok)
		require.NotNil(t, span.GenAI.Retrieval)
		assert.Equal(t, "weaviate", span.GenAI.Retrieval.Provider)
	})

	t.Run("retrieval query without space before brace", func(t *testing.T) {
		req := makeRequest(t, http.MethodPost,
			"https://x.weaviate.cloud/v1/graphql",
			`{"query":"{Get{Article(nearVector:{vector:[0.1,0.2]},limit:3){title}}}"}`,
		)
		resp := makePlainResponse(http.StatusOK, http.Header{
			"Content-Type": []string{"application/json"},
		}, `{"data":{"Get":{"Article":[]}}}`)

		base := &request.Span{}
		span, ok := RetrievalSpan(base, req, resp)
		require.True(t, ok)
		require.NotNil(t, span.GenAI.Retrieval)
		assert.Equal(t, "weaviate", span.GenAI.Retrieval.Provider)
	})

	t.Run("non retrieval query", func(t *testing.T) {
		req := makeRequest(t, http.MethodPost,
			"https://x.weaviate.cloud/v1/graphql",
			`{"query":"{ Aggregate { Article { meta { count } } } }"}`,
		)
		resp := makePlainResponse(http.StatusOK, http.Header{
			"Content-Type": []string{"application/json"},
		}, `{"data":{"Aggregate":{"Article":[{"meta":{"count":10}}]}}}`)

		base := &request.Span{}
		_, ok := RetrievalSpan(base, req, resp)
		assert.False(t, ok)
	})
}

func TestRetrievalSpan_CollectionVariants(t *testing.T) {
	tests := []struct {
		name        string
		requestBody string
		expected    string
	}{
		{
			name:        "collection",
			requestBody: `{"collection":"docs","limit":1}`,
			expected:    "docs",
		},
		{
			name:        "collectionName",
			requestBody: `{"collectionName":"docs-camel","limit":1}`,
			expected:    "docs-camel",
		},
		{
			name:        "collection_name",
			requestBody: `{"collection_name":"docs-snake","limit":1}`,
			expected:    "docs-snake",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := makeRequest(t, http.MethodPost,
				"https://x.trychroma.com/api/v1/collections/id/query", tt.requestBody)
			resp := makePlainResponse(http.StatusOK, http.Header{
				"Content-Type": []string{"application/json"},
			}, `{"results":[]}`)

			base := &request.Span{}
			span, ok := RetrievalSpan(base, req, resp)
			require.True(t, ok)
			require.NotNil(t, span.GenAI.Retrieval)
			assert.Equal(t, tt.expected, span.GenAI.Retrieval.GetCollection())
		})
	}
}

func TestRetrievalSpan_TraceName(t *testing.T) {
	span := &request.Span{
		Type:    request.EventTypeHTTPClient,
		SubType: request.HTTPSubtypeRetrieval,
		GenAI: &request.GenAI{
			Retrieval: &request.VendorRetrieval{
				Provider: "pinecone",
				Input:    request.RetrievalRequest{Namespace: "docs"},
			},
		},
	}
	assert.Equal(t, "retrieval docs", span.TraceName())

	spanNoCollection := &request.Span{
		Type:    request.EventTypeHTTPClient,
		SubType: request.HTTPSubtypeRetrieval,
		GenAI: &request.GenAI{
			Retrieval: &request.VendorRetrieval{Provider: "qdrant"},
		},
	}
	assert.Equal(t, "retrieval qdrant", spanNoCollection.TraceName())
}

func TestIsGenAISubtype_Retrieval(t *testing.T) {
	assert.True(t, request.IsGenAISubtype(request.HTTPSubtypeRetrieval))
}
