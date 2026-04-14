// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bufio"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const geminiRequestBody = `{
  "contents": [{"parts":[{"text":"Explain how AI works in a few words"}],"role":"user"}],
  "systemInstruction": {"parts":[{"text":"Be concise and helpful."}],"role":"system"},
  "generationConfig": {"temperature":0.7,"topP":0.9,"topK":40,"maxOutputTokens":256,"frequencyPenalty":0.5,"presencePenalty":0.3,"stopSequences":["END","STOP"],"seed":42,"candidateCount":1}
}`

const geminiResponseBody = `{
  "candidates": [
    {
      "content": {
        "parts": [{"text":"AI uses machine learning algorithms to find patterns in data and make predictions."}],
        "role": "model"
      },
      "finishReason": "STOP"
    }
  ],
  "usageMetadata": {
    "promptTokenCount": 12,
    "candidatesTokenCount": 18,
    "totalTokenCount": 30
  },
  "modelVersion": "gemini-2.0-flash",
  "responseId": "resp_abc123"
}`

const geminiErrorResponseBody = `{
  "error": {
    "code": 429,
    "message": "Resource has been exhausted (e.g. check quota).",
    "status": "RESOURCE_EXHAUSTED"
  }
}`

func geminiResponseHeaders() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-Gemini-Service-Tier", "standard")
	return h
}

func TestGeminiSpan_GenerateContent(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent", geminiRequestBody)
	resp := makePlainResponse(http.StatusOK, geminiResponseHeaders(), geminiResponseBody)

	base := &request.Span{}
	span, ok := GeminiSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Gemini)

	ai := span.GenAI.Gemini
	assert.Equal(t, request.HTTPSubtypeGemini, span.SubType)
	assert.Equal(t, "gemini-2.0-flash", ai.Model)
	assert.Equal(t, "gemini-2.0-flash", ai.Output.ModelVersion)
	assert.Equal(t, "resp_abc123", ai.Output.ResponseID)
	assert.Equal(t, 12, ai.Output.UsageMetadata.PromptTokenCount)
	assert.Equal(t, 18, ai.Output.UsageMetadata.CandidatesTokenCount)
	assert.Equal(t, 30, ai.Output.UsageMetadata.TotalTokenCount)
	assert.NotEmpty(t, ai.GetOutput())
	assert.NotEmpty(t, ai.GetInput())
	assert.NotEmpty(t, ai.GetSystemInstruction())
	assert.Equal(t, []string{"STOP"}, ai.GetFinishReasons())

	require.NotNil(t, ai.Input.GenerationConfig)
	cfg := ai.Input.GenerationConfig
	assert.InDelta(t, 0.7, cfg.Temperature, 0.01)
	assert.InDelta(t, 0.9, cfg.TopP, 0.01)
	assert.Equal(t, 40, cfg.TopK)
	assert.Equal(t, 256, cfg.MaxOutputTokens)
	assert.InDelta(t, 0.5, cfg.FrequencyPenalty, 0.01)
	assert.InDelta(t, 0.3, cfg.PresencePenalty, 0.01)
	assert.Equal(t, []string{"END", "STOP"}, cfg.StopSequences)
	require.NotNil(t, cfg.Seed)
	assert.Equal(t, 42, *cfg.Seed)
	assert.Equal(t, 1, cfg.CandidateCount)
}

func TestGeminiSpan_ErrorResponse(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent", geminiRequestBody)
	resp := makePlainResponse(http.StatusTooManyRequests, geminiResponseHeaders(), geminiErrorResponseBody)

	base := &request.Span{}
	span, ok := GeminiSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Gemini)

	assert.Equal(t, "RESOURCE_EXHAUSTED", span.GenAI.Gemini.Output.Error.Status)
	assert.NotEmpty(t, span.GenAI.Gemini.Output.Error.Message)
}

func TestGeminiSpan_NotGemini(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "http://example.com/api", `{"query":"hello"}`)
	resp := makePlainResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, `{"result":"ok"}`)

	base := &request.Span{}
	_, ok := GeminiSpan(base, req, resp)

	assert.False(t, ok)
}

func TestGeminiSpan_RelativeURL(t *testing.T) {
	rawReq := "POST /v1beta/models/gemini-2.0-flash:generateContent HTTP/1.1\r\n" +
		"Host: generativelanguage.googleapis.com\r\n" +
		"Content-Type: application/json\r\n" +
		"X-Goog-Api-Key: test-key\r\n" +
		"\r\n" +
		geminiRequestBody
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawReq)))
	require.NoError(t, err)

	resp := makePlainResponse(http.StatusOK, geminiResponseHeaders(), geminiResponseBody)

	base := &request.Span{}
	span, ok := GeminiSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Gemini)
	assert.Equal(t, request.HTTPSubtypeGemini, span.SubType)
	assert.Equal(t, "gemini-2.0-flash", span.GenAI.Gemini.Model)
}

func TestGeminiSpan_VertexAIEndpoint(t *testing.T) {
	req := makeRequest(t, http.MethodPost, "https://us-central1-aiplatform.googleapis.com/v1/projects/my-project/locations/us-central1/publishers/google/models/gemini-2.0-flash:generateContent", geminiRequestBody)
	req.Header.Set("X-Goog-Api-Key", "test-key")
	resp := makePlainResponse(http.StatusOK, geminiResponseHeaders(), geminiResponseBody)

	base := &request.Span{}
	span, ok := GeminiSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.Gemini)
	assert.Equal(t, "gemini-2.0-flash", span.GenAI.Gemini.Model)
}

func TestExtractGeminiModel(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "standard generateContent",
			url:  "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
			want: "gemini-2.0-flash",
		},
		{
			name: "vertex AI path",
			url:  "https://us-central1-aiplatform.googleapis.com/v1/projects/my-project/locations/us-central1/publishers/google/models/gemini-2.0-flash:generateContent",
			want: "gemini-2.0-flash",
		},
		{
			name: "no model in path",
			url:  "https://example.com/api/chat",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := makeRequest(t, http.MethodPost, tt.url, "{}")
			assert.Equal(t, tt.want, extractGeminiModel(req))
		})
	}
}
