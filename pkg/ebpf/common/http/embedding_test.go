// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/base64"
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
	assert.Equal(t, 8, reportedValue(ai.InputTokenCount()))
	assert.Equal(t, 2, ai.Input.InputCount())
	// No request dimension: derived from the response vector length.
	assert.Equal(t, 2, ai.Dimensions())
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
	assert.Equal(t, 4, reportedValue(ai.InputTokenCount()))
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
	assert.Equal(t, 6, reportedValue(ai.InputTokenCount()))
	assert.Equal(t, 512, ai.Input.Dimensions)
	// Explicit request dimension takes precedence over the response vector length.
	assert.Equal(t, 512, ai.Dimensions())
	assert.Equal(t, 1, ai.Input.InputCount())
}

func TestEmbeddingSpan_EncodingFormats(t *testing.T) {
	t.Run("openai_style_single", func(t *testing.T) {
		req := makeRequest(t, http.MethodPost, "https://api.voyageai.com/v1/embeddings",
			`{"model":"voyage-3","input":["hi"],"encoding_format":"base64"}`)
		resp := makePlainResponse(http.StatusOK, http.Header{"Content-Type": []string{"application/json"}},
			voyageResponseBody)

		span, ok := EmbeddingSpan(&request.Span{}, req, resp)
		require.True(t, ok)
		assert.Equal(t, []string{"base64"}, span.GenAI.Embedding.Input.EncodingFormats())
	})

	t.Run("cohere_style_list", func(t *testing.T) {
		req := makeRequest(t, http.MethodPost, "https://api.cohere.com/v2/embed",
			`{"model":"embed-english-v3.0","texts":["hi"],"embedding_types":["float","int8"]}`)
		resp := makePlainResponse(http.StatusOK, http.Header{"Content-Type": []string{"application/json"}},
			cohereResponseBody)

		span, ok := EmbeddingSpan(&request.Span{}, req, resp)
		require.True(t, ok)
		ai := span.GenAI.Embedding
		assert.Equal(t, []string{"float", "int8"}, ai.Input.EncodingFormats())
		// Cohere embeddings.float[][] vectors yield the dimension count.
		assert.Equal(t, 2, ai.Dimensions())
	})

	t.Run("output_dimension_request", func(t *testing.T) {
		req := makeRequest(t, http.MethodPost, "https://api.voyageai.com/v1/embeddings",
			`{"model":"voyage-3","input":["hi"],"output_dimension":1024}`)
		resp := makePlainResponse(http.StatusOK, http.Header{"Content-Type": []string{"application/json"}},
			voyageResponseBody)

		span, ok := EmbeddingSpan(&request.Span{}, req, resp)
		require.True(t, ok)
		assert.Equal(t, 1024, span.GenAI.Embedding.Dimensions())
		assert.Nil(t, span.GenAI.Embedding.Input.EncodingFormats())
	})
}

func TestEmbeddingSpan_CohereBinaryDimensions(t *testing.T) {
	post := func(t *testing.T, respBody string) request.Span {
		t.Helper()
		req := makeRequest(t, http.MethodPost, "https://api.cohere.com/v2/embed",
			`{"model":"embed-english-v3.0","texts":["hi"],"embedding_types":["binary"]}`)
		resp := makePlainResponse(http.StatusOK, http.Header{"Content-Type": []string{"application/json"}},
			respBody)

		span, ok := EmbeddingSpan(&request.Span{}, req, resp)
		require.True(t, ok)
		return span
	}

	t.Run("binary_expands_packed_entries", func(t *testing.T) {
		span := post(t, `{"embeddings":{"binary":[[1,2,3,4]]}}`)
		// Each binary entry packs eight model dimensions: 4 entries -> 32 dims.
		assert.Equal(t, 32, span.GenAI.Embedding.Dimensions())
	})

	t.Run("ubinary_expands_packed_entries", func(t *testing.T) {
		span := post(t, `{"embeddings":{"ubinary":[[255,0]]}}`)
		assert.Equal(t, 16, span.GenAI.Embedding.Dimensions())
	})

	t.Run("float_preferred_over_binary", func(t *testing.T) {
		span := post(t, `{"embeddings":{"binary":[[1,2]],"float":[[0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9,1.0,1.1,1.2,1.3,1.4,1.5,1.6]]}}`)
		// Non-packed vectors are preferred regardless of map iteration order.
		assert.Equal(t, 16, span.GenAI.Embedding.Dimensions())
	})
}

func TestEmbeddingSpan_RepresentationAwareDimensions(t *testing.T) {
	embed := func(t *testing.T, url, reqBody, respBody string) request.Span {
		t.Helper()
		req := makeRequest(t, http.MethodPost, url, reqBody)
		resp := makePlainResponse(http.StatusOK, http.Header{"Content-Type": []string{"application/json"}},
			respBody)

		span, ok := EmbeddingSpan(&request.Span{}, req, resp)
		require.True(t, ok)
		return span
	}

	b64Floats := func(dims int) string {
		return base64.StdEncoding.EncodeToString(make([]byte, dims*4))
	}

	t.Run("voyage_binary_dtype_expands_packed_vector", func(t *testing.T) {
		span := embed(t, "https://api.voyageai.com/v1/embeddings",
			`{"model":"voyage-3","input":["hi"],"output_dtype":"binary"}`,
			`{"data":[{"embedding":[1,2,3,4]}],"model":"voyage-3"}`)
		// 4 bit-packed byte entries carry 32 model dimensions.
		assert.Equal(t, 32, span.GenAI.Embedding.Dimensions())
	})

	t.Run("voyage_base64_float_vector", func(t *testing.T) {
		span := embed(t, "https://api.voyageai.com/v1/embeddings",
			`{"model":"voyage-3","input":["hi"],"encoding_format":"base64"}`,
			`{"data":[{"embedding":"`+b64Floats(1024)+`"}],"model":"voyage-3"}`)
		assert.Equal(t, 1024, span.GenAI.Embedding.Dimensions())
	})

	t.Run("voyage_base64_int8_vector", func(t *testing.T) {
		vec := base64.StdEncoding.EncodeToString(make([]byte, 256))
		span := embed(t, "https://api.voyageai.com/v1/embeddings",
			`{"model":"voyage-3","input":["hi"],"output_dtype":"int8","encoding_format":"base64"}`,
			`{"data":[{"embedding":"`+vec+`"}],"model":"voyage-3"}`)
		// int8 elements are one byte per dimension.
		assert.Equal(t, 256, span.GenAI.Embedding.Dimensions())
	})

	t.Run("jina_base64_embedding_type", func(t *testing.T) {
		span := embed(t, "https://api.jina.ai/v1/embeddings",
			`{"model":"jina-embeddings-v3","input":["hi"],"embedding_type":"base64"}`,
			`{"data":[{"embedding":"`+b64Floats(512)+`"}],"model":"jina-embeddings-v3"}`)
		assert.Equal(t, 512, span.GenAI.Embedding.Dimensions())
	})

	t.Run("jina_binary_embedding_type", func(t *testing.T) {
		span := embed(t, "https://api.jina.ai/v1/embeddings",
			`{"model":"jina-embeddings-v3","input":["hi"],"embedding_type":"binary"}`,
			`{"data":[{"embedding":[7,7]}],"model":"jina-embeddings-v3"}`)
		assert.Equal(t, 16, span.GenAI.Embedding.Dimensions())
	})

	t.Run("cohere_base64_vectors", func(t *testing.T) {
		span := embed(t, "https://api.cohere.com/v2/embed",
			`{"model":"embed-english-v3.0","texts":["hi"],"embedding_types":["base64"]}`,
			`{"embeddings":{"base64":["`+b64Floats(1024)+`"]}}`)
		assert.Equal(t, 1024, span.GenAI.Embedding.Dimensions())
	})
}

func TestParseEmbeddingDimensions_TruncatedBatch(t *testing.T) {
	noFormat := &request.EmbeddingRequest{}

	t.Run("first_vector_complete_later_vector_truncated", func(t *testing.T) {
		body := []byte(`{"data":[{"embedding":[0.1,0.2,0.3]},{"embedding":[0.4,0.`)
		assert.Equal(t, 3, parseEmbeddingDimensions(noFormat, body))
	})

	t.Run("first_vector_truncated_returns_zero", func(t *testing.T) {
		body := []byte(`{"data":[{"embedding":[0.1,0.2`)
		assert.Equal(t, 0, parseEmbeddingDimensions(noFormat, body))
	})

	t.Run("truncated_after_complete_envelope_field", func(t *testing.T) {
		body := []byte(`{"model":"voyage-3","data":[{"embedding":[0.1,0.2]}],"usage":{"total_to`)
		assert.Equal(t, 2, parseEmbeddingDimensions(noFormat, body))
	})
}

func TestEmbeddingRequest_NativeFormatFields(t *testing.T) {
	t.Run("jina_embedding_type_string", func(t *testing.T) {
		r := &request.EmbeddingRequest{EmbeddingType: []byte(`"binary"`)}
		assert.Equal(t, []string{"binary"}, r.EncodingFormats())
		assert.Equal(t, "binary", r.RequestedDtype())
	})

	t.Run("jina_embedding_type_array", func(t *testing.T) {
		r := &request.EmbeddingRequest{EmbeddingType: []byte(`["float","base64"]`)}
		assert.Equal(t, []string{"float", "base64"}, r.EncodingFormats())
		assert.Equal(t, "float", r.RequestedDtype())
	})

	t.Run("voyage_output_dtype", func(t *testing.T) {
		r := &request.EmbeddingRequest{OutputDtype: "ubinary"}
		assert.Equal(t, []string{"ubinary"}, r.EncodingFormats())
		assert.Equal(t, "ubinary", r.RequestedDtype())
	})

	t.Run("voyage_output_dtype_with_base64_encoding", func(t *testing.T) {
		r := &request.EmbeddingRequest{OutputDtype: "int8", EncodingFormat: "base64"}
		assert.Equal(t, []string{"int8", "base64"}, r.EncodingFormats())
		assert.Equal(t, "int8", r.RequestedDtype())
	})

	t.Run("cohere_embedding_types_take_precedence", func(t *testing.T) {
		r := &request.EmbeddingRequest{EmbeddingTypes: []string{"float", "binary"}}
		assert.Equal(t, []string{"float", "binary"}, r.EncodingFormats())
		assert.Empty(t, r.RequestedDtype())
	})
}

func TestEmbeddingSpan_ExplicitZeroUsage(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "https://api.voyageai.com/v1/embeddings", voyageRequestBody)
	resp := makePlainResponse(http.StatusOK, http.Header{"Content-Type": []string{"application/json"}},
		`{"model":"voyage-3","usage":{"total_tokens":0}}`)

	span, ok := EmbeddingSpan(&request.Span{}, req, resp)
	require.True(t, ok)
	assert.True(t, isReported(span.GenAIInputTokenCount()))
	assert.Zero(t, reportedValue(span.GenAIInputTokenCount()))
	assert.False(t, isReported(span.GenAIOutputTokenCount()))
}

func TestEmbeddingSpan_UsageAfterMalformedEnvelopeField(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "https://api.voyageai.com/v1/embeddings", voyageRequestBody)
	resp := makePlainResponse(http.StatusOK, http.Header{"Content-Type": []string{"application/json"}},
		`{"model":{},"usage":{"total_tokens":0}}`)

	span, ok := EmbeddingSpan(&request.Span{}, req, resp)
	require.True(t, ok)
	assert.True(t, isReported(span.GenAIInputTokenCount()))
	assert.Zero(t, reportedValue(span.GenAIInputTokenCount()))
}

func TestEmbeddingSpan_BilledUnitsAfterMalformedEnvelopeField(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "https://api.cohere.com/v2/embed", cohereRequestBody)
	resp := makePlainResponse(http.StatusOK, http.Header{"Content-Type": []string{"application/json"}},
		`{"model":{},"meta":{"billed_units":{"input_tokens":0}}}`)

	span, ok := EmbeddingSpan(&request.Span{}, req, resp)
	require.True(t, ok)
	assert.True(t, isReported(span.GenAIInputTokenCount()))
	assert.Zero(t, reportedValue(span.GenAIInputTokenCount()))
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
