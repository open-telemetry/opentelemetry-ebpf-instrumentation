// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenAIInputTokenCountAvailability(t *testing.T) {
	tests := []struct {
		name string
		span *Span
		want bool
	}{
		{
			name: "nil GenAI returns false",
			span: &Span{GenAI: nil},
			want: false,
		},
		{
			name: "OpenAI with PromptTokens > 0",
			span: &Span{GenAI: &GenAI{
				OpenAI: &VendorOpenAI{Usage: OpenAIUsage{PromptTokens: NewTokenCount(100)}},
			}},
			want: true,
		},
		{
			name: "OpenAI with InputTokens > 0",
			span: &Span{GenAI: &GenAI{
				OpenAI: &VendorOpenAI{Usage: OpenAIUsage{InputTokens: NewTokenCount(50)}},
			}},
			want: true,
		},
		{
			name: "OpenAI all zero",
			span: &Span{GenAI: &GenAI{
				OpenAI: &VendorOpenAI{Usage: OpenAIUsage{}},
			}},
			want: false,
		},
		{
			name: "Anthropic with InputTokens > 0",
			span: &Span{GenAI: &GenAI{
				Anthropic: &VendorAnthropic{
					Output: AnthropicResponse{
						Usage: AnthropicUsage{InputTokens: NewTokenCount(200)},
					},
				},
			}},
			want: true,
		},
		{
			name: "Anthropic with only CacheReadInputTokens > 0",
			span: &Span{GenAI: &GenAI{
				Anthropic: &VendorAnthropic{
					Output: AnthropicResponse{
						Usage: AnthropicUsage{CacheReadInputTokens: NewTokenCount(50)},
					},
				},
			}},
			want: true,
		},
		{
			name: "Gemini with PromptTokenCount > 0",
			span: &Span{GenAI: &GenAI{
				Gemini: &VendorGemini{
					Output: GeminiResponse{
						UsageMetadata: GeminiUsage{PromptTokenCount: NewTokenCount(150)},
					},
				},
			}},
			want: true,
		},
		{
			name: "Gemini all zero",
			span: &Span{GenAI: &GenAI{
				Gemini: &VendorGemini{
					Output: GeminiResponse{
						UsageMetadata: GeminiUsage{},
					},
				},
			}},
			want: false,
		},
		{
			name: "Bedrock with InputTokens > 0",
			span: &Span{GenAI: &GenAI{
				Bedrock: &VendorBedrock{
					Output: BedrockResponse{InputTokens: NewTokenCount(300)},
				},
			}},
			want: true,
		},
		{
			name: "Bedrock all zero",
			span: &Span{GenAI: &GenAI{
				Bedrock: &VendorBedrock{
					Output: BedrockResponse{},
				},
			}},
			want: false,
		},
		{
			name: "Embedding with TotalTokens > 0",
			span: &Span{GenAI: &GenAI{
				Embedding: &VendorEmbedding{
					Output: EmbeddingResponse{
						Usage: EmbeddingUsage{TotalTokens: NewTokenCount(500)},
					},
				},
			}},
			want: true,
		},
		{
			name: "Embedding all zero",
			span: &Span{GenAI: &GenAI{
				Embedding: &VendorEmbedding{
					Output: EmbeddingResponse{
						Usage: EmbeddingUsage{},
					},
				},
			}},
			want: false,
		},
		{
			name: "Rerank with TotalTokens > 0",
			span: &Span{GenAI: &GenAI{
				Rerank: &VendorRerank{
					Output: RerankResponse{
						Usage: RerankUsage{TotalTokens: NewTokenCount(120)},
					},
				},
			}},
			want: true,
		},
		{
			name: "Qwen with PromptTokens > 0",
			span: &Span{GenAI: &GenAI{
				Qwen: &VendorOpenAI{Usage: OpenAIUsage{PromptTokens: NewTokenCount(80)}},
			}},
			want: true,
		},
		{
			name: "Ollama with InputTokens > 0",
			span: &Span{GenAI: &GenAI{
				Ollama: &VendorOpenAI{Usage: OpenAIUsage{InputTokens: NewTokenCount(60)}},
			}},
			want: true,
		},
		{
			name: "OpenAICompatible with PromptTokens > 0",
			span: &Span{GenAI: &GenAI{
				OpenAICompatible: &VendorOpenAI{Usage: OpenAIUsage{PromptTokens: NewTokenCount(90)}},
			}},
			want: true,
		},
		{
			name: "Retrieval with TotalTokens > 0",
			span: &Span{GenAI: &GenAI{
				Retrieval: &VendorRetrieval{
					Output: RetrievalResponse{
						Usage: RetrievalUsage{TotalTokens: NewTokenCount(45)},
					},
				},
			}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isReported(tt.span.GenAIInputTokenCount()))
		})
	}
}

func TestGenAIOutputTokenCountAvailability(t *testing.T) {
	tests := []struct {
		name string
		span *Span
		want bool
	}{
		{
			name: "nil GenAI returns false",
			span: &Span{GenAI: nil},
			want: false,
		},
		{
			name: "OpenAI with CompletionTokens > 0",
			span: &Span{GenAI: &GenAI{
				OpenAI: &VendorOpenAI{Usage: OpenAIUsage{CompletionTokens: NewTokenCount(200)}},
			}},
			want: true,
		},
		{
			name: "OpenAI with OutputTokens > 0",
			span: &Span{GenAI: &GenAI{
				OpenAI: &VendorOpenAI{Usage: OpenAIUsage{OutputTokens: NewTokenCount(150)}},
			}},
			want: true,
		},
		{
			name: "OpenAI all zero",
			span: &Span{GenAI: &GenAI{
				OpenAI: &VendorOpenAI{Usage: OpenAIUsage{}},
			}},
			want: false,
		},
		{
			name: "Anthropic with OutputTokens > 0",
			span: &Span{GenAI: &GenAI{
				Anthropic: &VendorAnthropic{
					Output: AnthropicResponse{
						Usage: AnthropicUsage{OutputTokens: NewTokenCount(100)},
					},
				},
			}},
			want: true,
		},
		{
			name: "Anthropic with zero OutputTokens",
			span: &Span{GenAI: &GenAI{
				Anthropic: &VendorAnthropic{
					Output: AnthropicResponse{
						Usage: AnthropicUsage{InputTokens: NewTokenCount(200)},
					},
				},
			}},
			want: false,
		},
		{
			name: "Gemini with CandidatesTokenCount > 0",
			span: &Span{GenAI: &GenAI{
				Gemini: &VendorGemini{
					Output: GeminiResponse{
						UsageMetadata: GeminiUsage{CandidatesTokenCount: NewTokenCount(80)},
					},
				},
			}},
			want: true,
		},
		{
			name: "Bedrock with OutputTokens > 0",
			span: &Span{GenAI: &GenAI{
				Bedrock: &VendorBedrock{
					Output: BedrockResponse{OutputTokens: NewTokenCount(250)},
				},
			}},
			want: true,
		},
		{
			name: "Bedrock only input, no output",
			span: &Span{GenAI: &GenAI{
				Bedrock: &VendorBedrock{
					Output: BedrockResponse{InputTokens: NewTokenCount(100)},
				},
			}},
			want: false,
		},
		{
			name: "Embedding does not report output usage",
			span: &Span{GenAI: &GenAI{
				Embedding: &VendorEmbedding{
					Output: EmbeddingResponse{
						Usage: EmbeddingUsage{TotalTokens: NewTokenCount(500), PromptTokens: NewTokenCount(500)},
					},
				},
			}},
			want: false,
		},
		{
			name: "Qwen with CompletionTokens > 0",
			span: &Span{GenAI: &GenAI{
				Qwen: &VendorOpenAI{Usage: OpenAIUsage{CompletionTokens: NewTokenCount(70)}},
			}},
			want: true,
		},
		{
			name: "Ollama with OutputTokens > 0",
			span: &Span{GenAI: &GenAI{
				Ollama: &VendorOpenAI{Usage: OpenAIUsage{OutputTokens: NewTokenCount(40)}},
			}},
			want: true,
		},
		{
			name: "OpenAICompatible with CompletionTokens > 0",
			span: &Span{GenAI: &GenAI{
				OpenAICompatible: &VendorOpenAI{Usage: OpenAIUsage{CompletionTokens: NewTokenCount(55)}},
			}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isReported(tt.span.GenAIOutputTokenCount()))
		})
	}
}

func TestHasGenAITokens_InputOnlyNoOutput(t *testing.T) {
	// Scenario: provider reports input tokens but no output tokens
	span := &Span{GenAI: &GenAI{
		OpenAI: &VendorOpenAI{Usage: OpenAIUsage{PromptTokens: NewTokenCount(100)}},
	}}
	assert.True(t, isReported(span.GenAIInputTokenCount()))
	assert.False(t, isReported(span.GenAIOutputTokenCount()))
}

func TestHasGenAITokens_OutputOnlyNoInput(t *testing.T) {
	// Scenario: provider reports output tokens but no input tokens
	span := &Span{GenAI: &GenAI{
		OpenAI: &VendorOpenAI{Usage: OpenAIUsage{CompletionTokens: NewTokenCount(200)}},
	}}
	assert.False(t, isReported(span.GenAIInputTokenCount()))
	assert.True(t, isReported(span.GenAIOutputTokenCount()))
}

func TestHasGenAITokens_BothAvailable(t *testing.T) {
	// Scenario: provider reports both input and output tokens
	span := &Span{GenAI: &GenAI{
		OpenAI: &VendorOpenAI{Usage: OpenAIUsage{PromptTokens: NewTokenCount(100), CompletionTokens: NewTokenCount(200)}},
	}}
	assert.True(t, isReported(span.GenAIInputTokenCount()))
	assert.True(t, isReported(span.GenAIOutputTokenCount()))
}

func TestParsedGenAITokenAvailability(t *testing.T) {
	t.Run("OpenAI", func(t *testing.T) {
		var usage OpenAIUsage
		require.NoError(t, json.Unmarshal([]byte(`{"prompt_tokens":0,"completion_tokens":0}`), &usage))
		span := Span{GenAI: &GenAI{OpenAI: &VendorOpenAI{Usage: usage}}}
		assertReportedZero(t, &span, true)

		require.NoError(t, json.Unmarshal([]byte(`{}`), &usage))
		span.GenAI.OpenAI.Usage = usage
		assertNotReported(t, &span)
	})

	t.Run("negative counts", func(t *testing.T) {
		var usage OpenAIUsage
		require.NoError(t, json.Unmarshal([]byte(`{"prompt_tokens":-1,"completion_tokens":-2}`), &usage))
		span := Span{GenAI: &GenAI{OpenAI: &VendorOpenAI{Usage: usage}}}
		assertNotReported(t, &span)
		assert.Zero(t, reportedValue(span.GenAIInputTokenCount()))
		assert.Zero(t, reportedValue(span.GenAIOutputTokenCount()))
	})

	t.Run("non-integer counts", func(t *testing.T) {
		var usage OpenAIUsage
		require.NoError(t, json.Unmarshal([]byte(`{"prompt_tokens":7.5,"completion_tokens":7e2}`), &usage))
		span := Span{GenAI: &GenAI{OpenAI: &VendorOpenAI{Usage: usage}}}
		assertNotReported(t, &span)
		assert.Zero(t, reportedValue(span.GenAIInputTokenCount()))
		assert.Zero(t, reportedValue(span.GenAIOutputTokenCount()))
	})

	t.Run("negative cache count does not reduce Anthropic input", func(t *testing.T) {
		var usage AnthropicUsage
		require.NoError(t, json.Unmarshal([]byte(`{"input_tokens":10,"cache_read_input_tokens":-3,"output_tokens":-1}`), &usage))
		span := Span{GenAI: &GenAI{Anthropic: &VendorAnthropic{
			Output: AnthropicResponse{Usage: usage},
		}}}
		assert.True(t, isReported(span.GenAIInputTokenCount()))
		assert.Equal(t, 10, reportedValue(span.GenAIInputTokenCount()))
		assert.False(t, isReported(span.GenAIOutputTokenCount()))
		assert.Zero(t, reportedValue(span.GenAIOutputTokenCount()))
	})

	t.Run("Anthropic", func(t *testing.T) {
		var usage AnthropicUsage
		require.NoError(t, json.Unmarshal([]byte(`{"input_tokens":0,"output_tokens":0}`), &usage))
		span := Span{GenAI: &GenAI{Anthropic: &VendorAnthropic{
			Output: AnthropicResponse{Usage: usage},
		}}}
		assertReportedZero(t, &span, true)

		require.NoError(t, json.Unmarshal([]byte(`{}`), &usage))
		span.GenAI.Anthropic.Output.Usage = usage
		assertNotReported(t, &span)
	})

	t.Run("Gemini", func(t *testing.T) {
		var usage GeminiUsage
		require.NoError(t, json.Unmarshal([]byte(`{"promptTokenCount":0,"candidatesTokenCount":0}`), &usage))
		span := Span{GenAI: &GenAI{Gemini: &VendorGemini{
			Output: GeminiResponse{UsageMetadata: usage},
		}}}
		assertReportedZero(t, &span, true)

		require.NoError(t, json.Unmarshal([]byte(`{}`), &usage))
		span.GenAI.Gemini.Output.UsageMetadata = usage
		assertNotReported(t, &span)
	})

	t.Run("Embedding", func(t *testing.T) {
		var response EmbeddingResponse
		require.NoError(t, json.Unmarshal([]byte(`{"usage":{"prompt_tokens":0,"total_tokens":0}}`), &response))
		span := Span{GenAI: &GenAI{Embedding: &VendorEmbedding{Output: response}}}
		assertReportedZero(t, &span, false)

		require.NoError(t, json.Unmarshal([]byte(`{"usage":{}}`), &response))
		span.GenAI.Embedding.Output = response
		assertNotReported(t, &span)
	})

	t.Run("Rerank", func(t *testing.T) {
		var response RerankResponse
		require.NoError(t, json.Unmarshal([]byte(`{"usage":{"total_tokens":0}}`), &response))
		span := Span{GenAI: &GenAI{Rerank: &VendorRerank{Output: response}}}
		assertReportedZero(t, &span, false)

		require.NoError(t, json.Unmarshal([]byte(`{"usage":{}}`), &response))
		span.GenAI.Rerank.Output = response
		assertNotReported(t, &span)
	})

	t.Run("Retrieval", func(t *testing.T) {
		var response RetrievalResponse
		require.NoError(t, json.Unmarshal([]byte(`{"usage":{"prompt_tokens":0}}`), &response))
		span := Span{GenAI: &GenAI{Retrieval: &VendorRetrieval{Output: response}}}
		assertReportedZero(t, &span, false)

		require.NoError(t, json.Unmarshal([]byte(`{"usage":{}}`), &response))
		span.GenAI.Retrieval.Output = response
		assertNotReported(t, &span)
	})

	t.Run("Bedrock", func(t *testing.T) {
		response := BedrockResponse{}
		response.InputTokens = NewTokenCount(0)
		response.OutputTokens = NewTokenCount(0)
		span := Span{GenAI: &GenAI{Bedrock: &VendorBedrock{Output: response}}}
		assertReportedZero(t, &span, true)
		assertNotReported(t, &Span{GenAI: &GenAI{Bedrock: &VendorBedrock{}}})
	})
}

func assertReportedZero(t *testing.T, span *Span, hasOutput bool) {
	t.Helper()
	assert.True(t, isReported(span.GenAIInputTokenCount()))
	assert.Zero(t, reportedValue(span.GenAIInputTokenCount()))
	assert.Equal(t, hasOutput, isReported(span.GenAIOutputTokenCount()))
	assert.Zero(t, reportedValue(span.GenAIOutputTokenCount()))
}

func assertNotReported(t *testing.T, span *Span) {
	t.Helper()
	assert.False(t, isReported(span.GenAIInputTokenCount()))
	assert.False(t, isReported(span.GenAIOutputTokenCount()))
}
