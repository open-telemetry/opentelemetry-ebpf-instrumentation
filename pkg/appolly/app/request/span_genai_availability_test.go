// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasGenAIInputTokens(t *testing.T) {
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
				OpenAI: &VendorOpenAI{Usage: OpenAIUsage{PromptTokens: 100}},
			}},
			want: true,
		},
		{
			name: "OpenAI with InputTokens > 0",
			span: &Span{GenAI: &GenAI{
				OpenAI: &VendorOpenAI{Usage: OpenAIUsage{InputTokens: 50}},
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
						Usage: AnthropicUsage{InputTokens: 200},
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
						Usage: AnthropicUsage{CacheReadInputTokens: 50},
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
						UsageMetadata: GeminiUsage{PromptTokenCount: 150},
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
					Output: BedrockResponse{InputTokens: 300},
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
						Usage: EmbeddingUsage{TotalTokens: 500},
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
						Usage: RerankUsage{TotalTokens: 120},
					},
				},
			}},
			want: true,
		},
		{
			name: "Qwen with PromptTokens > 0",
			span: &Span{GenAI: &GenAI{
				Qwen: &VendorOpenAI{Usage: OpenAIUsage{PromptTokens: 80}},
			}},
			want: true,
		},
		{
			name: "Ollama with InputTokens > 0",
			span: &Span{GenAI: &GenAI{
				Ollama: &VendorOpenAI{Usage: OpenAIUsage{InputTokens: 60}},
			}},
			want: true,
		},
		{
			name: "OpenAICompatible with PromptTokens > 0",
			span: &Span{GenAI: &GenAI{
				OpenAICompatible: &VendorOpenAI{Usage: OpenAIUsage{PromptTokens: 90}},
			}},
			want: true,
		},
		{
			name: "Retrieval with TotalTokens > 0",
			span: &Span{GenAI: &GenAI{
				Retrieval: &VendorRetrieval{
					Output: RetrievalResponse{
						Usage: RetrievalUsage{TotalTokens: 45},
					},
				},
			}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.span.HasGenAIInputTokens())
		})
	}
}

func TestHasGenAIOutputTokens(t *testing.T) {
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
				OpenAI: &VendorOpenAI{Usage: OpenAIUsage{CompletionTokens: 200}},
			}},
			want: true,
		},
		{
			name: "OpenAI with OutputTokens > 0",
			span: &Span{GenAI: &GenAI{
				OpenAI: &VendorOpenAI{Usage: OpenAIUsage{OutputTokens: 150}},
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
						Usage: AnthropicUsage{OutputTokens: 100},
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
						Usage: AnthropicUsage{InputTokens: 200, OutputTokens: 0},
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
						UsageMetadata: GeminiUsage{CandidatesTokenCount: 80},
					},
				},
			}},
			want: true,
		},
		{
			name: "Bedrock with OutputTokens > 0",
			span: &Span{GenAI: &GenAI{
				Bedrock: &VendorBedrock{
					Output: BedrockResponse{OutputTokens: 250},
				},
			}},
			want: true,
		},
		{
			name: "Bedrock only input, no output",
			span: &Span{GenAI: &GenAI{
				Bedrock: &VendorBedrock{
					Output: BedrockResponse{InputTokens: 100, OutputTokens: 0},
				},
			}},
			want: false,
		},
		{
			name: "Embedding always returns false for output",
			span: &Span{GenAI: &GenAI{
				Embedding: &VendorEmbedding{
					Output: EmbeddingResponse{
						Usage: EmbeddingUsage{TotalTokens: 500, PromptTokens: 500},
					},
				},
			}},
			want: false,
		},
		{
			name: "Qwen with CompletionTokens > 0",
			span: &Span{GenAI: &GenAI{
				Qwen: &VendorOpenAI{Usage: OpenAIUsage{CompletionTokens: 70}},
			}},
			want: true,
		},
		{
			name: "Ollama with OutputTokens > 0",
			span: &Span{GenAI: &GenAI{
				Ollama: &VendorOpenAI{Usage: OpenAIUsage{OutputTokens: 40}},
			}},
			want: true,
		},
		{
			name: "OpenAICompatible with CompletionTokens > 0",
			span: &Span{GenAI: &GenAI{
				OpenAICompatible: &VendorOpenAI{Usage: OpenAIUsage{CompletionTokens: 55}},
			}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.span.HasGenAIOutputTokens())
		})
	}
}

func TestHasGenAITokens_InputOnlyNoOutput(t *testing.T) {
	// Scenario: provider reports input tokens but no output tokens
	span := &Span{GenAI: &GenAI{
		OpenAI: &VendorOpenAI{Usage: OpenAIUsage{PromptTokens: 100, CompletionTokens: 0}},
	}}
	assert.True(t, span.HasGenAIInputTokens())
	assert.False(t, span.HasGenAIOutputTokens())
}

func TestHasGenAITokens_OutputOnlyNoInput(t *testing.T) {
	// Scenario: provider reports output tokens but no input tokens
	span := &Span{GenAI: &GenAI{
		OpenAI: &VendorOpenAI{Usage: OpenAIUsage{PromptTokens: 0, CompletionTokens: 200}},
	}}
	assert.False(t, span.HasGenAIInputTokens())
	assert.True(t, span.HasGenAIOutputTokens())
}

func TestHasGenAITokens_BothAvailable(t *testing.T) {
	// Scenario: provider reports both input and output tokens
	span := &Span{GenAI: &GenAI{
		OpenAI: &VendorOpenAI{Usage: OpenAIUsage{PromptTokens: 100, CompletionTokens: 200}},
	}}
	assert.True(t, span.HasGenAIInputTokens())
	assert.True(t, span.HasGenAIOutputTokens())
}
