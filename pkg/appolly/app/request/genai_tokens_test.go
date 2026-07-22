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
		embedding := VendorEmbedding{Output: EmbeddingResponse{Usage: EmbeddingUsage{
			PromptTokens: NewTokenCount(5),
			TotalTokens:  NewTokenCount(3),
		}}}
		value, reported := embedding.OutputTokenCount()
		assert.Zero(t, value)
		assert.False(t, reported)
		assert.Zero(t, embedding.GetOutputTokens())

		usage := OpenAIUsage{
			PromptTokens: NewTokenCount(5),
			TotalTokens:  NewTokenCount(3),
		}
		assert.Zero(t, usage.GetOutputTokens())
	})
}
