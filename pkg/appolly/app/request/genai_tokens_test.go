// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenCount(t *testing.T) {
	t.Run("construction", func(t *testing.T) {
		value, reported := NewTokenCount(0).Get()
		assert.Zero(t, value)
		assert.True(t, reported)

		value, reported = NewTokenCount(42).Get()
		assert.Equal(t, 42, value)
		assert.True(t, reported)

		value, reported = NewTokenCount(-1).Get()
		assert.Zero(t, value)
		assert.False(t, reported)

		value, reported = (TokenCount{}).Get()
		assert.Zero(t, value)
		assert.False(t, reported)
	})

	for _, tt := range []struct {
		name         string
		input        string
		want         int
		wantReported bool
	}{
		{name: "zero", input: `0`, wantReported: true},
		{name: "positive", input: `42`, want: 42, wantReported: true},
		{name: "negative", input: `-1`},
		{name: "fraction", input: `7.5`},
		{name: "exponent", input: `7e2`},
		{name: "string", input: `"7"`},
		{name: "null", input: `null`},
	} {
		t.Run("unmarshal "+tt.name, func(t *testing.T) {
			count := NewTokenCount(99)
			require.NoError(t, json.Unmarshal([]byte(tt.input), &count))
			value, reported := count.Get()
			assert.Equal(t, tt.want, value)
			assert.Equal(t, tt.wantReported, reported)
		})
	}

	t.Run("marshal", func(t *testing.T) {
		missing, err := json.Marshal(TokenCount{})
		require.NoError(t, err)
		assert.JSONEq(t, `null`, string(missing))

		zero, err := json.Marshal(NewTokenCount(0))
		require.NoError(t, err)
		assert.JSONEq(t, `0`, string(zero))

		positive, err := json.Marshal(NewTokenCount(42))
		require.NoError(t, err)
		assert.JSONEq(t, `42`, string(positive))
	})

	t.Run("usage round trip", func(t *testing.T) {
		original := OpenAIUsage{InputTokens: NewTokenCount(0)}
		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded OpenAIUsage
		require.NoError(t, json.Unmarshal(data, &decoded))
		input, inputReported := decoded.InputTokenCount()
		_, outputReported := decoded.OutputTokenCount()
		assert.Zero(t, input)
		assert.True(t, inputReported)
		assert.False(t, outputReported)
	})

	t.Run("Anthropic aggregate overflow", func(t *testing.T) {
		usage := AnthropicUsage{
			InputTokens:          NewTokenCount(math.MaxInt),
			CacheReadInputTokens: NewTokenCount(1),
		}
		value, reported := usage.InputTokenCount()
		assert.Zero(t, value)
		assert.False(t, reported)
	})

	t.Run("derived output cannot be negative", func(t *testing.T) {
		usage := OpenAIUsage{
			PromptTokens: NewTokenCount(5),
			TotalTokens:  NewTokenCount(3),
		}
		assert.Zero(t, reportedValue(usage.OutputTokenCount()))
	})

	t.Run("derived output uses either input alias", func(t *testing.T) {
		for _, usage := range []OpenAIUsage{
			{PromptTokens: NewTokenCount(5), TotalTokens: NewTokenCount(5)},
			{InputTokens: NewTokenCount(5), TotalTokens: NewTokenCount(5)},
		} {
			assert.Zero(t, reportedValue(usage.OutputTokenCount()))
			assert.True(t, isReported(usage.OutputTokenCount()))
		}
	})
}

func TestTokenDetailAvailability(t *testing.T) {
	t.Run("OpenAI", func(t *testing.T) {
		var usage OpenAIUsage
		require.NoError(t, json.Unmarshal([]byte(`{
			"completion_tokens_details":{"reasoning_tokens":0},
			"prompt_tokens_details":{"cached_tokens":0,"cache_creation_tokens":0}
		}`), &usage))

		require.NotNil(t, usage.OutputDetails)
		assertTokenCount(t, usage.OutputDetails.ReasoningTokens, 0, true)
		require.NotNil(t, usage.InputDetails)
		assertTokenCount(t, usage.InputDetails.CachedTokens, 0, true)
		assertTokenCount(t, usage.InputDetails.CacheCreationTokens, 0, true)

		require.NoError(t, json.Unmarshal([]byte(`{
			"completion_tokens_details":{},
			"prompt_tokens_details":{}
		}`), &usage))
		assertTokenCount(t, usage.OutputDetails.ReasoningTokens, 0, false)
		assertTokenCount(t, usage.InputDetails.CachedTokens, 0, false)
		assertTokenCount(t, usage.InputDetails.CacheCreationTokens, 0, false)
	})

	t.Run("OpenAI aliases", func(t *testing.T) {
		for _, input := range []string{
			`{"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}`,
			`{"prompt_tokens_details":{"cached_tokens":0},"completion_tokens_details":{"reasoning_tokens":0}}`,
		} {
			var usage OpenAIUsage
			require.NoError(t, json.Unmarshal([]byte(input), &usage))
			assertTokenCount(t, usage.InputDetails.CachedTokens, 0, true)
			assertTokenCount(t, usage.OutputDetails.ReasoningTokens, 0, true)
		}

		var usage OpenAIUsage
		require.NoError(t, json.Unmarshal([]byte(`{
			"input_tokens_details":{"cached_tokens":0},
			"prompt_tokens_details":{"cached_tokens":7},
			"output_tokens_details":{"reasoning_tokens":"invalid"},
			"completion_tokens_details":{"reasoning_tokens":9}
		}`), &usage))
		assertTokenCount(t, usage.InputDetails.CachedTokens, 0, true)
		assertTokenCount(t, usage.OutputDetails.ReasoningTokens, 9, true)
	})

	t.Run("Anthropic", func(t *testing.T) {
		var usage AnthropicUsage
		require.NoError(t, json.Unmarshal([]byte(`{
			"reasoning_output_tokens":0,
			"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":0}
		}`), &usage))
		assertTokenCount(t, usage.ReasoningOutputTokens, 0, true)
		require.NotNil(t, usage.CacheCreation)
		assertTokenCount(t, usage.CacheCreation.Ephemeral5mInputTokens, 0, true)
		assertTokenCount(t, usage.CacheCreation.Ephemeral1hInputTokens, 0, true)

		require.NoError(t, json.Unmarshal([]byte(`{}`), &usage))
		assertTokenCount(t, usage.ReasoningOutputTokens, 0, false)
	})

	t.Run("Gemini", func(t *testing.T) {
		var usage GeminiUsage
		require.NoError(t, json.Unmarshal([]byte(`{
			"toolUsePromptTokenCount":0,
			"thoughtsTokenCount":0,
			"cachedContentTokenCount":0,
			"cacheTokensDetails":[{"modality":"TEXT","tokenCount":0}]
		}`), &usage))
		assertTokenCount(t, usage.ToolUsePromptTokenCount, 0, true)
		assertTokenCount(t, usage.ThoughtsTokenCount, 0, true)
		assertTokenCount(t, usage.CachedContentTokenCount, 0, true)
		require.Len(t, usage.CacheTokensDetails, 1)
		assertTokenCount(t, usage.CacheTokensDetails[0].TokenCount, 0, true)
	})

	t.Run("Bedrock aliases", func(t *testing.T) {
		for _, input := range []string{
			`{"inputTokens":0,"outputTokens":0,"cacheReadInputTokens":0,"cacheWriteInputTokens":0}`,
			`{"input_tokens":0,"output_tokens":0,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}`,
		} {
			var usage BedrockUsage
			require.NoError(t, json.Unmarshal([]byte(input), &usage))
			assertTokenCount(t, usage.InputTokens, 0, true)
			assertTokenCount(t, usage.OutputTokens, 0, true)
			assertTokenCount(t, usage.CacheReadInputTokens, 0, true)
			assertTokenCount(t, usage.CacheWriteInputTokens, 0, true)
		}
	})

	t.Run("JSON round trip", func(t *testing.T) {
		original := struct {
			OpenAI    OpenAIUsage    `json:"openai"`
			Anthropic AnthropicUsage `json:"anthropic"`
			Gemini    GeminiUsage    `json:"gemini"`
			Bedrock   BedrockUsage   `json:"bedrock"`
		}{
			OpenAI: OpenAIUsage{
				OutputDetails: &OpenAIOutputTokensDetails{
					ReasoningTokens:          NewTokenCount(0),
					AudioTokens:              NewTokenCount(0),
					AcceptedPredictionTokens: NewTokenCount(0),
					RejectedPredictionTokens: NewTokenCount(0),
				},
				InputDetails: &OpenAIInputTokensDetails{
					CachedTokens:        NewTokenCount(0),
					CacheCreationTokens: NewTokenCount(0),
					AudioTokens:         NewTokenCount(0),
				},
			},
			Anthropic: AnthropicUsage{
				ReasoningOutputTokens: NewTokenCount(0),
				CacheCreation: &AnthropicCacheCreation{
					Ephemeral5mInputTokens: NewTokenCount(0),
					Ephemeral1hInputTokens: NewTokenCount(0),
				},
			},
			Gemini: GeminiUsage{
				ToolUsePromptTokenCount: NewTokenCount(0),
				ThoughtsTokenCount:      NewTokenCount(0),
				CachedContentTokenCount: NewTokenCount(0),
				CacheTokensDetails: []GeminiModalityTokenCount{{
					Modality:   "TEXT",
					TokenCount: NewTokenCount(0),
				}},
			},
			Bedrock: BedrockUsage{
				CacheReadInputTokens:  NewTokenCount(0),
				CacheWriteInputTokens: NewTokenCount(0),
				CacheDetails: []BedrockCacheDetail{{
					InputTokens: NewTokenCount(0),
					TTL:         "5m",
				}},
			},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)
		var decoded struct {
			OpenAI    OpenAIUsage    `json:"openai"`
			Anthropic AnthropicUsage `json:"anthropic"`
			Gemini    GeminiUsage    `json:"gemini"`
			Bedrock   BedrockUsage   `json:"bedrock"`
		}
		require.NoError(t, json.Unmarshal(data, &decoded))

		assertTokenCount(t, decoded.OpenAI.OutputDetails.ReasoningTokens, 0, true)
		assertTokenCount(t, decoded.OpenAI.OutputDetails.AudioTokens, 0, true)
		assertTokenCount(t, decoded.OpenAI.OutputDetails.AcceptedPredictionTokens, 0, true)
		assertTokenCount(t, decoded.OpenAI.OutputDetails.RejectedPredictionTokens, 0, true)
		assertTokenCount(t, decoded.OpenAI.InputDetails.CachedTokens, 0, true)
		assertTokenCount(t, decoded.OpenAI.InputDetails.CacheCreationTokens, 0, true)
		assertTokenCount(t, decoded.OpenAI.InputDetails.AudioTokens, 0, true)
		assertTokenCount(t, decoded.Anthropic.ReasoningOutputTokens, 0, true)
		assertTokenCount(t, decoded.Anthropic.CacheCreation.Ephemeral5mInputTokens, 0, true)
		assertTokenCount(t, decoded.Anthropic.CacheCreation.Ephemeral1hInputTokens, 0, true)
		assertTokenCount(t, decoded.Gemini.ToolUsePromptTokenCount, 0, true)
		assertTokenCount(t, decoded.Gemini.ThoughtsTokenCount, 0, true)
		assertTokenCount(t, decoded.Gemini.CachedContentTokenCount, 0, true)
		assertTokenCount(t, decoded.Gemini.CacheTokensDetails[0].TokenCount, 0, true)
		assertTokenCount(t, decoded.Bedrock.CacheReadInputTokens, 0, true)
		assertTokenCount(t, decoded.Bedrock.CacheWriteInputTokens, 0, true)
		assertTokenCount(t, decoded.Bedrock.CacheDetails[0].InputTokens, 0, true)
		assert.Contains(t, string(data), `"input_tokens_details"`)
		assert.Contains(t, string(data), `"output_tokens_details"`)
	})
}

func TestProviderTokenFieldsRejectInvalidJSONScalars(t *testing.T) {
	for _, tt := range []struct {
		name   string
		decode func(string) TokenCount
	}{
		{
			name: "OpenAI",
			decode: func(value string) TokenCount {
				var usage OpenAIUsage
				_ = json.Unmarshal([]byte(`{"prompt_tokens":`+value+`}`), &usage)
				return usage.PromptTokens
			},
		},
		{
			name: "Anthropic",
			decode: func(value string) TokenCount {
				var usage AnthropicUsage
				_ = json.Unmarshal([]byte(`{"input_tokens":`+value+`}`), &usage)
				return usage.InputTokens
			},
		},
		{
			name: "Gemini",
			decode: func(value string) TokenCount {
				var usage GeminiUsage
				_ = json.Unmarshal([]byte(`{"promptTokenCount":`+value+`}`), &usage)
				return usage.PromptTokenCount
			},
		},
		{
			name: "embedding",
			decode: func(value string) TokenCount {
				var usage EmbeddingUsage
				_ = json.Unmarshal([]byte(`{"prompt_tokens":`+value+`}`), &usage)
				return usage.PromptTokens
			},
		},
		{
			name: "Cohere embedding",
			decode: func(value string) TokenCount {
				var usage CohereBilledUnits
				_ = json.Unmarshal([]byte(`{"input_tokens":`+value+`}`), &usage)
				return usage.InputTokens
			},
		},
		{
			name: "rerank usage",
			decode: func(value string) TokenCount {
				var usage RerankUsage
				_ = json.Unmarshal([]byte(`{"total_tokens":`+value+`}`), &usage)
				return usage.TotalTokens
			},
		},
		{
			name: "rerank metadata",
			decode: func(value string) TokenCount {
				var usage RerankMetaTokens
				_ = json.Unmarshal([]byte(`{"input_tokens":`+value+`}`), &usage)
				return usage.InputTokens
			},
		},
		{
			name: "retrieval",
			decode: func(value string) TokenCount {
				var usage RetrievalUsage
				_ = json.Unmarshal([]byte(`{"total_tokens":`+value+`}`), &usage)
				return usage.TotalTokens
			},
		},
		{
			name: "Bedrock",
			decode: func(value string) TokenCount {
				var usage BedrockUsage
				_ = json.Unmarshal([]byte(`{"inputTokens":`+value+`}`), &usage)
				return usage.InputTokens
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, value := range []string{
				`null`, `"7"`, `7.5`, `7e2`, `-1`, `18446744073709551616`,
			} {
				_, reported := tt.decode(value).Get()
				assert.False(t, reported, value)
			}

			assertTokenCount(t, tt.decode(`0`), 0, true)
			assertTokenCount(t, tt.decode(`42`), 42, true)
		})
	}
}

func TestTokenOnlyUsageUnmarshalClearsMissingFields(t *testing.T) {
	t.Run("embedding", func(t *testing.T) {
		usage := EmbeddingUsage{
			PromptTokens: NewTokenCount(0),
			TotalTokens:  NewTokenCount(1),
		}
		require.NoError(t, json.Unmarshal([]byte(`{}`), &usage))
		assertTokenCount(t, usage.PromptTokens, 0, false)
		assertTokenCount(t, usage.TotalTokens, 0, false)
	})

	t.Run("Cohere billed units", func(t *testing.T) {
		usage := CohereBilledUnits{InputTokens: NewTokenCount(0)}
		require.NoError(t, json.Unmarshal([]byte(`{}`), &usage))
		assertTokenCount(t, usage.InputTokens, 0, false)
	})

	t.Run("rerank metadata", func(t *testing.T) {
		usage := RerankMetaTokens{InputTokens: NewTokenCount(0)}
		require.NoError(t, json.Unmarshal([]byte(`{}`), &usage))
		assertTokenCount(t, usage.InputTokens, 0, false)
	})

	t.Run("retrieval", func(t *testing.T) {
		usage := RetrievalUsage{
			PromptTokens: NewTokenCount(0),
			TotalTokens:  NewTokenCount(1),
		}
		require.NoError(t, json.Unmarshal([]byte(`{}`), &usage))
		assertTokenCount(t, usage.PromptTokens, 0, false)
		assertTokenCount(t, usage.TotalTokens, 0, false)
	})
}

func TestTokenFieldsSurviveMalformedSiblings(t *testing.T) {
	var openAI OpenAIUsage
	require.NoError(t, json.Unmarshal([]byte(`{
		"completion_tokens":"invalid",
		"completion_tokens_details":{"reasoning_tokens":7},
		"prompt_tokens_details":{"cached_tokens":5,"cache_creation_tokens":"invalid"}
	}`), &openAI))
	assertTokenCount(t, openAI.OutputDetails.ReasoningTokens, 7, true)
	assertTokenCount(t, openAI.InputDetails.CachedTokens, 5, true)
	assertTokenCount(t, openAI.InputDetails.CacheCreationTokens, 0, false)

	var anthropic AnthropicUsage
	require.NoError(t, json.Unmarshal([]byte(`{
		"output_tokens":"invalid",
		"reasoning_output_tokens":11,
		"service_tier":{},
		"cache_creation":{"ephemeral_5m_input_tokens":13}
	}`), &anthropic))
	assertTokenCount(t, anthropic.OutputTokens, 0, false)
	assertTokenCount(t, anthropic.ReasoningOutputTokens, 11, true)
	assertTokenCount(t, anthropic.CacheCreation.Ephemeral5mInputTokens, 13, true)

	var gemini GeminiUsage
	require.NoError(t, json.Unmarshal([]byte(`{
		"candidatesTokenCount":"invalid",
		"promptTokenCount":13,
		"promptTokensDetails":{},
		"cacheTokensDetails":[{"modality":"TEXT","tokenCount":17}]
	}`), &gemini))
	assertTokenCount(t, gemini.CandidatesTokenCount, 0, false)
	assertTokenCount(t, gemini.PromptTokenCount, 13, true)
	assertTokenCount(t, gemini.CacheTokensDetails[0].TokenCount, 17, true)

	var bedrock BedrockUsage
	require.NoError(t, json.Unmarshal([]byte(`{
		"cacheDetails":{},
		"cache_creation":{"ephemeral_1h_input_tokens":19}
	}`), &bedrock))
	assertTokenCount(t, bedrock.CacheCreation.Ephemeral1hInputTokens, 19, true)

	var rerank RerankUsage
	require.NoError(t, json.Unmarshal([]byte(`{"search_units":{},"total_tokens":23}`), &rerank))
	assertTokenCount(t, rerank.TotalTokens, 23, true)
}

func TestUsageMergePreservesAndReplacesReportedFields(t *testing.T) {
	t.Run("OpenAI", func(t *testing.T) {
		usage := OpenAIUsage{
			PromptTokens: NewTokenCount(5),
			OutputDetails: &OpenAIOutputTokensDetails{
				ReasoningTokens: NewTokenCount(3),
			},
		}
		usage.Merge(OpenAIUsage{
			CompletionTokens: NewTokenCount(0),
			OutputDetails: &OpenAIOutputTokensDetails{
				ReasoningTokens: NewTokenCount(0),
			},
		})

		assertTokenCount(t, usage.PromptTokens, 5, true)
		assertTokenCount(t, usage.CompletionTokens, 0, true)
		assertTokenCount(t, usage.OutputDetails.ReasoningTokens, 0, true)
	})

	t.Run("Gemini", func(t *testing.T) {
		usage := GeminiUsage{
			PromptTokenCount:        NewTokenCount(5),
			CandidatesTokenCount:    NewTokenCount(3),
			ThoughtsTokenCount:      NewTokenCount(2),
			CachedContentTokenCount: NewTokenCount(4),
			PromptTokensDetails: []GeminiModalityTokenCount{{
				Modality: "TEXT", TokenCount: NewTokenCount(5),
			}},
			CacheTokensDetails: []GeminiModalityTokenCount{{
				Modality: "TEXT", TokenCount: NewTokenCount(5),
			}},
			CandidatesTokensDetails: []GeminiModalityTokenCount{{
				Modality: "TEXT", TokenCount: NewTokenCount(5),
			}},
			ToolUsePromptTokensDetails: []GeminiModalityTokenCount{{
				Modality: "TEXT", TokenCount: NewTokenCount(5),
			}},
		}
		var malformed GeminiUsage
		require.NoError(t, json.Unmarshal([]byte(`{
			"promptTokensDetails":[{"modality":"TEXT","tokenCount":"invalid"}],
			"cacheTokensDetails":[{"modality":"TEXT","tokenCount":"invalid"}],
			"candidatesTokensDetails":[{"modality":"TEXT","tokenCount":"invalid"}],
			"toolUsePromptTokensDetails":[{"modality":"TEXT","tokenCount":"invalid"}]
		}`), &malformed))
		usage.Merge(malformed)

		for _, details := range [][]GeminiModalityTokenCount{
			usage.PromptTokensDetails,
			usage.CacheTokensDetails,
			usage.CandidatesTokensDetails,
			usage.ToolUsePromptTokensDetails,
		} {
			require.Len(t, details, 1)
			assertTokenCount(t, details[0].TokenCount, 5, true)
		}

		zero := GeminiModalityTokenCount{Modality: "TEXT", TokenCount: NewTokenCount(0)}
		usage.Merge(GeminiUsage{
			CandidatesTokenCount:       NewTokenCount(0),
			ThoughtsTokenCount:         NewTokenCount(0),
			CachedContentTokenCount:    NewTokenCount(0),
			PromptTokensDetails:        []GeminiModalityTokenCount{zero},
			CacheTokensDetails:         []GeminiModalityTokenCount{zero},
			CandidatesTokensDetails:    []GeminiModalityTokenCount{zero},
			ToolUsePromptTokensDetails: []GeminiModalityTokenCount{zero},
		})

		assertTokenCount(t, usage.PromptTokenCount, 5, true)
		assertTokenCount(t, usage.CandidatesTokenCount, 0, true)
		assertTokenCount(t, usage.ThoughtsTokenCount, 0, true)
		assertTokenCount(t, usage.CachedContentTokenCount, 0, true)
		for _, details := range [][]GeminiModalityTokenCount{
			usage.PromptTokensDetails,
			usage.CacheTokensDetails,
			usage.CandidatesTokensDetails,
			usage.ToolUsePromptTokensDetails,
		} {
			assertTokenCount(t, details[0].TokenCount, 0, true)
		}
	})
}

func TestSupplementaryTokenAggregation(t *testing.T) {
	t.Run("Gemini", func(t *testing.T) {
		usage := GeminiUsage{
			PromptTokenCount:        NewTokenCount(5),
			ToolUsePromptTokenCount: NewTokenCount(2),
			CandidatesTokenCount:    NewTokenCount(3),
			ThoughtsTokenCount:      NewTokenCount(4),
		}
		assert.Equal(t, 7, reportedValue(usage.InputTokenCount()))
		assert.Equal(t, 7, reportedValue(usage.OutputTokenCount()))
	})

	t.Run("Bedrock", func(t *testing.T) {
		response := BedrockResponse{Usage: BedrockUsage{
			InputTokens:           NewTokenCount(5),
			OutputTokens:          NewTokenCount(4),
			CacheReadInputTokens:  NewTokenCount(2),
			CacheWriteInputTokens: NewTokenCount(3),
		}}
		assert.Equal(t, 10, reportedValue(response.InputTokenCount()))
		assert.Equal(t, 4, reportedValue(response.OutputTokenCount()))

		response.InputTokens = NewTokenCount(7)
		assert.Equal(t, 12, reportedValue(response.InputTokenCount()))
	})

	t.Run("overflow", func(t *testing.T) {
		usage := GeminiUsage{
			PromptTokenCount:        NewTokenCount(math.MaxInt),
			ToolUsePromptTokenCount: NewTokenCount(1),
		}
		assert.False(t, isReported(usage.InputTokenCount()))

		response := BedrockResponse{Usage: BedrockUsage{
			InputTokens:          NewTokenCount(math.MaxInt),
			CacheReadInputTokens: NewTokenCount(1),
		}}
		assert.False(t, isReported(response.InputTokenCount()))
	})
}

func TestAnthropicUsageMergeReasoningOutputTokens(t *testing.T) {
	usage := AnthropicUsage{
		ReasoningOutputTokens: NewTokenCount(5),
		CacheCreation: &AnthropicCacheCreation{
			Ephemeral5mInputTokens: NewTokenCount(3),
		},
	}
	usage.Merge(AnthropicUsage{
		ReasoningOutputTokens: NewTokenCount(0),
		CacheCreation: &AnthropicCacheCreation{
			Ephemeral5mInputTokens: NewTokenCount(0),
		},
	})
	assertTokenCount(t, usage.ReasoningOutputTokens, 0, true)
	assertTokenCount(t, usage.CacheCreation.Ephemeral5mInputTokens, 0, true)

	usage.Merge(AnthropicUsage{})
	assertTokenCount(t, usage.ReasoningOutputTokens, 0, true)
}

func assertTokenCount(t *testing.T, count TokenCount, want int, wantReported bool) {
	t.Helper()

	value, reported := count.Get()
	assert.Equal(t, want, value)
	assert.Equal(t, wantReported, reported)
}

func reportedValue(value int, _ bool) int {
	return value
}

func isReported(_ int, reported bool) bool {
	return reported
}
