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

const voyageRequestBody = `{"model":"voyage-3","input":["Hello world","Goodbye world"]}`

const voyageResponseBody = `{
  "object": "list",
  "data": [
    {"object": "embedding", "embedding": [0.1, 0.2], "index": 0},
    {"object": "embedding", "embedding": [0.3, 0.4], "index": 1}
  ],
  "model": "voyage-3",
  "usage": {"total_tokens": 8}
}`

const cohereRequestBody = `{"model":"embed-english-v3.0","texts":["Hello world"],"input_type":"search_document"}`

const cohereResponseBody = `{
  "id": "emb-123",
  "embeddings": {"float": [[0.1, 0.2]]},
  "meta": {"api_version": {"version": "2"}, "billed_units": {"input_tokens": 4}}
}`

const jinaRequestBody = `{"model":"jina-embeddings-v3","input":["Hello world"],"dimensions":512}`

const jinaResponseBody = `{
  "model": "jina-embeddings-v3",
  "object": "list",
  "data": [
    {"object": "embedding", "embedding": [0.1, 0.2], "index": 0}
  ],
  "usage": {"prompt_tokens": 6, "total_tokens": 6}
}`

func TestEmbeddingSpan_VoyageAI(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "https://api.voyageai.com/v1/embeddings", voyageRequestBody)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, voyageResponseBody)

	base := &request.Span{}
	span, ok := EmbeddingSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Embedding)
	assert.Equal(t, request.HTTPSubtypeEmbedding, span.SubType)

	ai := span.GenAI.Embedding
	assert.Equal(t, "voyage", ai.Provider)
	assert.Equal(t, "voyage-3", ai.Model)
	assert.Equal(t, "embeddings", ai.OperationName())
	assert.Equal(t, 8, ai.GetInputTokens())
	assert.Equal(t, 2, ai.Input.InputCount())
}

func TestEmbeddingSpan_Cohere(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "https://api.cohere.com/v2/embed", cohereRequestBody)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, cohereResponseBody)

	base := &request.Span{}
	span, ok := EmbeddingSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Embedding)
	assert.Equal(t, request.HTTPSubtypeEmbedding, span.SubType)

	ai := span.GenAI.Embedding
	assert.Equal(t, "cohere", ai.Provider)
	assert.Equal(t, "embed-english-v3.0", ai.Model)
	assert.Equal(t, "embeddings", ai.OperationName())
	assert.Equal(t, 4, ai.GetInputTokens())
	assert.Equal(t, 1, ai.Input.InputCount())
}

func TestEmbeddingSpan_JinaAI(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "https://api.jina.ai/v1/embeddings", jinaRequestBody)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, jinaResponseBody)

	base := &request.Span{}
	span, ok := EmbeddingSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Embedding)
	assert.Equal(t, request.HTTPSubtypeEmbedding, span.SubType)

	ai := span.GenAI.Embedding
	assert.Equal(t, "jina", ai.Provider)
	assert.Equal(t, "jina-embeddings-v3", ai.Model)
	assert.Equal(t, "embeddings", ai.OperationName())
	assert.Equal(t, 6, ai.GetInputTokens())
	assert.Equal(t, 512, ai.Input.Dimensions)
	assert.Equal(t, 1, ai.Input.InputCount())
}

func TestEmbeddingSpan_NotEmbeddingProvider(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://example.com/api", `{"query":"hello"}`)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, `{"result":"ok"}`)

	base := &request.Span{}
	_, ok := EmbeddingSpan(base, req, resp)

	assert.False(t, ok, "should not be detected as embedding provider for unknown host")
}

func TestIsEmbeddingProvider(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "Voyage AI",
			url:      "https://api.voyageai.com/v1/embeddings",
			expected: "voyage",
		},
		{
			name:     "Cohere",
			url:      "https://api.cohere.com/v2/embed",
			expected: "cohere",
		},
		{
			name:     "Jina AI",
			url:      "https://api.jina.ai/v1/embeddings",
			expected: "jina",
		},
		{
			name:     "unknown host",
			url:      "https://api.example.com/v1/embeddings",
			expected: "",
		},
		{
			name:     "wrong path for cohere",
			url:      "https://api.cohere.com/v1/embeddings",
			expected: "",
		},
		{
			name:     "Voyage AI trailing slash",
			url:      "https://api.voyageai.com/v1/embeddings/",
			expected: "voyage",
		},
		{
			name:     "Cohere trailing slash",
			url:      "https://api.cohere.com/v2/embed/",
			expected: "cohere",
		},
		{
			name:     "Jina AI trailing slash",
			url:      "https://api.jina.ai/v1/embeddings/",
			expected: "jina",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := makeRequest(t, http.MethodPost, tt.url, "{}")
			assert.Equal(t, tt.expected, parseEmbeddingProvider(req))
		})
	}
}

func TestEmbeddingSpan_TraceName(t *testing.T) {
	span := &request.Span{
		Type:    request.EventTypeHTTPClient,
		SubType: request.HTTPSubtypeEmbedding,
		GenAI: &request.GenAI{
			Embedding: &request.VendorEmbedding{
				Provider: "voyage",
				Model:    "voyage-3",
			},
		},
	}
	assert.Equal(t, "embeddings voyage-3", span.TraceName())

	spanNoModel := &request.Span{
		Type:    request.EventTypeHTTPClient,
		SubType: request.HTTPSubtypeEmbedding,
		GenAI: &request.GenAI{
			Embedding: &request.VendorEmbedding{
				Provider: "cohere",
			},
		},
	}
	assert.Equal(t, "embeddings", spanNoModel.TraceName())
}

func TestEmbeddingInputCount(t *testing.T) {
	// array of strings
	r := &request.EmbeddingRequest{Input: []byte(`["hello", "world"]`)}
	assert.Equal(t, 2, r.InputCount())

	// single string
	r2 := &request.EmbeddingRequest{Input: []byte(`"hello"`)}
	assert.Equal(t, 1, r2.InputCount())

	// empty
	r3 := &request.EmbeddingRequest{}
	assert.Equal(t, 0, r3.InputCount())

	// Cohere texts field
	r4 := &request.EmbeddingRequest{Texts: []byte(`["hello"]`)}
	assert.Equal(t, 1, r4.InputCount())
}
