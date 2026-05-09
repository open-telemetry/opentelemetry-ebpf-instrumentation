// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"net/http"
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
	assert.Equal(t, 3, ai.GetTopK())
	assert.Equal(t, 3, ai.ResultCount())
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
	assert.Equal(t, 5, span.GenAI.Retrieval.GetTopK())
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
	assert.Equal(t, 10, span.GenAI.Retrieval.GetTopK())
	assert.Equal(t, 2, span.GenAI.Retrieval.ResultCount())
}

func TestRetrievalSpan_UnknownHost(t *testing.T) {
	req := makeRequest(t, http.MethodPost,
		"https://api.example.com/v1/search", `{"vector":[0.1],"top_k":3}`)
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
