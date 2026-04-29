// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const cohereRerankRequestBody = `{
  "model": "rerank-v3.5",
  "query": "What is the capital of the United States?",
  "top_n": 3,
  "documents": [
    "Carson City is the capital city of the American state of Nevada.",
    "Washington, D.C. is the capital of the United States.",
    "Capital punishment has existed in the United States since before it was a country."
  ]
}`

const cohereRerankResponseBody = `{
  "id": "abc-123-rerank",
  "results": [
    {"index": 1, "relevance_score": 0.999071},
    {"index": 0, "relevance_score": 0.7867867},
    {"index": 2, "relevance_score": 0.32713068}
  ],
  "meta": {
    "billed_units": {"search_units": 1},
    "tokens": {"input_tokens": 411}
  }
}`

const jinaRerankRequestBody = `{
  "model": "jina-reranker-v2-base-multilingual",
  "query": "Organic skincare products for sensitive skin",
  "top_n": 3,
  "documents": [
    "Organic cotton baby clothes are a popular choice.",
    "New makeup launches high-coverage foundation.",
    "Bio-Facial Serum is designed for sensitive skin."
  ]
}`

const jinaRerankResponseBody = `{
  "model": "jina-reranker-v2-base-multilingual",
  "results": [
    {"index": 2, "relevance_score": 0.95},
    {"index": 0, "relevance_score": 0.45},
    {"index": 1, "relevance_score": 0.12}
  ],
  "usage": {
    "total_tokens": 128,
    "prompt_tokens": 42
  }
}`

const rerankErrorResponseBody = `{
  "error": {
    "type": "invalid_api_key",
    "message": "invalid api token"
  }
}`

func TestRerankSpan_Cohere(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://api.cohere.com/v2/rerank", cohereRerankRequestBody)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, cohereRerankResponseBody)

	base := &request.Span{}
	span, ok := RerankSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Rerank)
	assert.Equal(t, request.HTTPSubtypeRerank, span.SubType)

	ai := span.GenAI.Rerank
	assert.Equal(t, "cohere", ai.Provider)
	assert.Equal(t, "rerank-v3.5", ai.Input.Model)
	assert.Equal(t, "What is the capital of the United States?", ai.Input.Query)
	assert.Equal(t, 3, ai.Input.TopN)
	assert.NotEmpty(t, ai.Input.Documents)
	assert.Equal(t, "abc-123-rerank", ai.Output.ID)
	assert.NotEmpty(t, ai.Output.Results)

	// Cohere uses meta.tokens for token counts
	require.NotNil(t, ai.Output.Meta)
	require.NotNil(t, ai.Output.Meta.Tokens)
	assert.Equal(t, 411, ai.Output.Meta.Tokens.InputTokens)
	assert.Equal(t, 411, ai.Output.GetTotalTokens())
}

func TestRerankSpan_CohereAI(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://api.cohere.ai/v1/rerank", cohereRerankRequestBody)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, cohereRerankResponseBody)

	base := &request.Span{}
	span, ok := RerankSpan(base, req, resp)

	require.True(t, ok)
	assert.Equal(t, "cohere", span.GenAI.Rerank.Provider)
}

func TestRerankSpan_JinaAI(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://api.jina.ai/v1/rerank", jinaRerankRequestBody)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, jinaRerankResponseBody)

	base := &request.Span{}
	span, ok := RerankSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.Rerank)
	assert.Equal(t, request.HTTPSubtypeRerank, span.SubType)

	ai := span.GenAI.Rerank
	assert.Equal(t, "jina", ai.Provider)
	assert.Equal(t, "jina-reranker-v2-base-multilingual", ai.Input.Model)
	assert.Equal(t, "Organic skincare products for sensitive skin", ai.Input.Query)
	assert.Equal(t, 3, ai.Input.TopN)
	assert.Equal(t, "jina-reranker-v2-base-multilingual", ai.Output.Model)
	assert.Equal(t, 128, ai.Output.Usage.TotalTokens)
	assert.Equal(t, 42, ai.Output.Usage.PromptTokens)
	assert.Equal(t, 128, ai.Output.GetTotalTokens())
}

func TestRerankSpan_VoyageAI(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://api.voyageai.com/v1/rerank", cohereRerankRequestBody)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, cohereRerankResponseBody)

	base := &request.Span{}
	span, ok := RerankSpan(base, req, resp)

	require.True(t, ok)
	assert.Equal(t, "voyageai", span.GenAI.Rerank.Provider)
}

func TestRerankSpan_UnknownProvider(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://custom-rerank.example.com/v1/rerank", cohereRerankRequestBody)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, cohereRerankResponseBody)

	base := &request.Span{}
	span, ok := RerankSpan(base, req, resp)

	require.True(t, ok)
	assert.Equal(t, "unknown", span.GenAI.Rerank.Provider)
}

func TestRerankSpan_ErrorResponse(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://api.cohere.com/v2/rerank", cohereRerankRequestBody)
	resp := makePlainResponse(http.StatusUnauthorized, http.Header{
		"Content-Type": []string{"application/json"},
	}, rerankErrorResponseBody)

	base := &request.Span{}
	span, ok := RerankSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.Rerank)

	ai := span.GenAI.Rerank
	require.NotNil(t, ai.Output.Error)
	assert.Equal(t, "invalid_api_key", ai.Output.Error.Type)
	assert.Equal(t, "invalid api token", ai.Output.Error.Message)
}

func TestRerankSpan_NotRerank(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://api.cohere.com/v1/chat", `{"query":"hello"}`)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, `{"result":"ok"}`)

	base := &request.Span{}
	_, ok := RerankSpan(base, req, resp)

	assert.False(t, ok, "should not be detected as rerank when path does not contain /rerank")
}

func TestRerankSpan_MalformedBody(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://api.cohere.com/v1/rerank", `not-json`)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, `also-not-json`)

	base := &request.Span{}
	span, ok := RerankSpan(base, req, resp)

	// Still detected as rerank (path matches), span returned even if JSON is junk
	assert.True(t, ok)
	assert.NotNil(t, span.GenAI.Rerank)
	assert.Empty(t, span.GenAI.Rerank.Input.Model)
}

func TestRerankSpan_GzipResponse(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://api.cohere.com/v1/rerank", cohereRerankRequestBody)
	resp := makeGzipResponse(t, http.StatusOK, http.Header{
		"Content-Type":     []string{"application/json"},
		"Content-Encoding": []string{"gzip"},
	}, cohereRerankResponseBody)

	base := &request.Span{}
	span, ok := RerankSpan(base, req, resp)

	require.True(t, ok)
	assert.Equal(t, "abc-123-rerank", span.GenAI.Rerank.Output.ID)
}

func TestRerankSpan_EmptyResponseBody(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://api.cohere.com/v1/rerank", cohereRerankRequestBody)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader("")),
	}

	base := &request.Span{}
	_, ok := RerankSpan(base, req, resp)

	// Empty response body: detection still succeeds (path matched)
	// but the parsed response will be empty
	assert.True(t, ok)
}

func TestRerankResponse_GetTotalTokens(t *testing.T) {
	// usage.total_tokens takes precedence (Jina/Voyage)
	r := request.RerankResponse{Usage: request.RerankUsage{TotalTokens: 100, PromptTokens: 42}}
	assert.Equal(t, 100, r.GetTotalTokens())

	// falls back to usage.prompt_tokens
	r2 := request.RerankResponse{Usage: request.RerankUsage{PromptTokens: 42}}
	assert.Equal(t, 42, r2.GetTotalTokens())

	// falls back to meta.tokens.input_tokens (Cohere)
	r3 := request.RerankResponse{
		Meta: &request.RerankMeta{
			Tokens: &request.RerankMetaTokens{InputTokens: 411},
		},
	}
	assert.Equal(t, 411, r3.GetTotalTokens())

	// all zero
	r4 := request.RerankResponse{}
	assert.Equal(t, 0, r4.GetTotalTokens())
}

func TestRerankSpan_TruncatedRequestBody(t *testing.T) {
	// Simulate eBPF buffer truncation: JSON is cut off mid-way but
	// the model field at the beginning is still intact.
	truncatedBody := `{"model":"rerank-v3.5","query":"What is the capital","documents":["Carson City is the cap`
	req := makeRequest(t, http.MethodPost, "http://api.cohere.com/v1/rerank", truncatedBody)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, cohereRerankResponseBody)

	base := &request.Span{}
	span, ok := RerankSpan(base, req, resp)

	require.True(t, ok)
	// Model should be extracted even from truncated JSON via regex fallback.
	assert.Equal(t, "rerank-v3.5", span.GenAI.Rerank.Input.Model)
}

func TestRerankSpan_TraceName(t *testing.T) {
	span := &request.Span{
		Type:    request.EventTypeHTTPClient,
		SubType: request.HTTPSubtypeRerank,
		GenAI: &request.GenAI{
			Rerank: &request.VendorRerank{
				Input:    request.RerankRequest{Model: "rerank-v3.5"},
				Provider: "cohere",
			},
		},
	}
	assert.Equal(t, "rerank rerank-v3.5", span.TraceName())

	// without model
	span2 := &request.Span{
		Type:    request.EventTypeHTTPClient,
		SubType: request.HTTPSubtypeRerank,
		GenAI: &request.GenAI{
			Rerank: &request.VendorRerank{
				Provider: "cohere",
			},
		},
	}
	assert.Equal(t, "rerank", span2.TraceName())
}
