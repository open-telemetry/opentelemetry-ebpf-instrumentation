// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"math"
	"strconv"

	jsoniter "github.com/json-iterator/go"
)

var tokenJSON = jsoniter.ConfigCompatibleWithStandardLibrary

// TokenCount retains a valid non-negative token count and whether the provider
// reported it. Its zero value represents an unavailable count.
type TokenCount struct {
	value    int
	reported bool
}

// NewTokenCount creates a reported token count. Negative values produce an
// unavailable count.
func NewTokenCount(value int) TokenCount {
	var count TokenCount
	count.set(value)
	return count
}

func (c *TokenCount) set(value int) {
	if value < 0 {
		*c = TokenCount{}
		return
	}
	c.value = value
	c.reported = true
}

// Get returns the token count and whether it was reported.
func (c TokenCount) Get() (int, bool) {
	return c.value, c.reported
}

// Value returns the token count, or zero when it was not reported.
func (c TokenCount) Value() int {
	return c.value
}

func (c *TokenCount) merge(other TokenCount) {
	if other.reported {
		*c = other
	}
}

func (c *TokenCount) UnmarshalJSON(data []byte) error {
	*c = TokenCount{}
	value, err := strconv.Atoi(string(data))
	if err != nil {
		return nil
	}
	c.set(value)
	return nil
}

func (c TokenCount) MarshalJSON() ([]byte, error) {
	if !c.reported {
		return []byte("null"), nil
	}
	return []byte(strconv.Itoa(c.value)), nil
}

func decodeTokenFields(data []byte, value any) {
	_ = tokenJSON.Unmarshal(data, value)
}

func decodeTokenField(data []byte, name string) TokenCount {
	field := tokenJSON.Get(data, name)
	if field.ValueType() != jsoniter.NumberValue {
		return TokenCount{}
	}
	var count TokenCount
	_ = count.UnmarshalJSON([]byte(field.ToString()))
	return count
}

func (u *OpenAIUsage) UnmarshalJSON(data []byte) error {
	type plain OpenAIUsage
	var decoded plain
	decodeTokenFields(data, &decoded)

	*u = OpenAIUsage(decoded)
	u.InputTokens = decodeTokenField(data, "input_tokens")
	u.OutputTokens = decodeTokenField(data, "output_tokens")
	u.TotalTokens = decodeTokenField(data, "total_tokens")
	u.PromptTokens = decodeTokenField(data, "prompt_tokens")
	u.CompletionTokens = decodeTokenField(data, "completion_tokens")
	return nil
}

func (u *OpenAIUsage) InputTokenCount() (int, bool) {
	if tokens, reported := u.InputTokens.Get(); reported {
		return tokens, true
	}
	if tokens, reported := u.PromptTokens.Get(); reported {
		return tokens, true
	}
	return 0, false
}

func (u *OpenAIUsage) OutputTokenCount() (int, bool) {
	if tokens, reported := u.OutputTokens.Get(); reported {
		return tokens, true
	}
	if tokens, reported := u.CompletionTokens.Get(); reported {
		return tokens, true
	}
	return 0, false
}

func (u *OpenAIUsage) SetInputTokens(tokens int) {
	u.InputTokens.set(tokens)
}

func (u *OpenAIUsage) SetOutputTokens(tokens int) {
	u.OutputTokens.set(tokens)
}

func (u *AnthropicUsage) UnmarshalJSON(data []byte) error {
	type plain AnthropicUsage
	var decoded plain
	decodeTokenFields(data, &decoded)

	*u = AnthropicUsage(decoded)
	u.InputTokens = decodeTokenField(data, "input_tokens")
	u.OutputTokens = decodeTokenField(data, "output_tokens")
	u.CacheCreationInputTokens = decodeTokenField(data, "cache_creation_input_tokens")
	u.CacheReadInputTokens = decodeTokenField(data, "cache_read_input_tokens")
	return nil
}

func (u *AnthropicUsage) InputTokenCount() (int, bool) {
	total := 0
	reported := false
	for _, count := range []TokenCount{
		u.InputTokens,
		u.CacheCreationInputTokens,
		u.CacheReadInputTokens,
	} {
		if value, ok := count.Get(); ok {
			if value > math.MaxInt-total {
				return 0, false
			}
			total += value
			reported = true
		}
	}
	return total, reported
}

func (u *AnthropicUsage) OutputTokenCount() (int, bool) {
	return u.OutputTokens.Get()
}

func (u *AnthropicUsage) Merge(other AnthropicUsage) {
	u.InputTokens.merge(other.InputTokens)
	u.OutputTokens.merge(other.OutputTokens)
	u.CacheCreationInputTokens.merge(other.CacheCreationInputTokens)
	u.CacheReadInputTokens.merge(other.CacheReadInputTokens)
}

func (u *GeminiUsage) UnmarshalJSON(data []byte) error {
	type plain GeminiUsage
	var decoded plain
	decodeTokenFields(data, &decoded)

	*u = GeminiUsage(decoded)
	u.PromptTokenCount = decodeTokenField(data, "promptTokenCount")
	u.CandidatesTokenCount = decodeTokenField(data, "candidatesTokenCount")
	u.TotalTokenCount = decodeTokenField(data, "totalTokenCount")
	return nil
}

func (u *GeminiUsage) InputTokenCount() (int, bool) {
	return u.PromptTokenCount.Get()
}

func (u *GeminiUsage) OutputTokenCount() (int, bool) {
	return u.CandidatesTokenCount.Get()
}

func (u *GeminiUsage) HasTokenCounts() bool {
	_, input := u.InputTokenCount()
	_, output := u.OutputTokenCount()
	_, total := u.TotalTokenCount.Get()
	return input || output || total
}

func (b *BedrockResponse) SetInputTokens(tokens int) {
	b.InputTokens.set(tokens)
}

func (b *BedrockResponse) SetOutputTokens(tokens int) {
	b.OutputTokens.set(tokens)
}

func (b *BedrockResponse) InputTokenCount() (int, bool) {
	return b.InputTokens.Get()
}

func (b *BedrockResponse) OutputTokenCount() (int, bool) {
	return b.OutputTokens.Get()
}

func (u *EmbeddingUsage) UnmarshalJSON(data []byte) error {
	type plain EmbeddingUsage
	var decoded plain
	decodeTokenFields(data, &decoded)

	*u = EmbeddingUsage(decoded)
	u.PromptTokens = decodeTokenField(data, "prompt_tokens")
	u.TotalTokens = decodeTokenField(data, "total_tokens")
	return nil
}

func (u *CohereBilledUnits) UnmarshalJSON(data []byte) error {
	type plain CohereBilledUnits
	var decoded plain
	decodeTokenFields(data, &decoded)

	*u = CohereBilledUnits(decoded)
	u.InputTokens = decodeTokenField(data, "input_tokens")
	return nil
}

func (e *VendorEmbedding) InputTokenCount() (int, bool) {
	usage := &e.Output.Usage
	if tokens, reported := usage.PromptTokens.Get(); reported {
		return tokens, true
	}
	if tokens, reported := usage.TotalTokens.Get(); reported {
		return tokens, true
	}
	if e.Output.Meta != nil && e.Output.Meta.BilledUnits != nil {
		billed := e.Output.Meta.BilledUnits
		return billed.InputTokens.Get()
	}
	return 0, false
}

func (e *VendorEmbedding) OutputTokenCount() (int, bool) {
	usage := &e.Output.Usage
	if total, totalReported := usage.TotalTokens.Get(); totalReported {
		if prompt, promptReported := usage.PromptTokens.Get(); promptReported {
			if total >= prompt {
				return total - prompt, true
			}
		}
	}
	return 0, false
}

func (u *RerankUsage) UnmarshalJSON(data []byte) error {
	type plain RerankUsage
	var decoded plain
	decodeTokenFields(data, &decoded)

	*u = RerankUsage(decoded)
	u.TotalTokens = decodeTokenField(data, "total_tokens")
	u.PromptTokens = decodeTokenField(data, "prompt_tokens")
	return nil
}

func (u *RerankUsage) InputTokenCount() (int, bool) {
	if tokens, reported := u.PromptTokens.Get(); reported {
		return tokens, true
	}
	return u.TotalTokens.Get()
}

func (u *RerankMetaTokens) UnmarshalJSON(data []byte) error {
	type plain RerankMetaTokens
	var decoded plain
	decodeTokenFields(data, &decoded)

	*u = RerankMetaTokens(decoded)
	u.InputTokens = decodeTokenField(data, "input_tokens")
	return nil
}

func (r *RerankResponse) InputTokenCount() (int, bool) {
	if tokens, reported := r.Usage.TotalTokens.Get(); reported {
		return tokens, true
	}
	if tokens, reported := r.Usage.PromptTokens.Get(); reported {
		return tokens, true
	}
	if r.Meta != nil && r.Meta.Tokens != nil {
		tokens := r.Meta.Tokens
		return tokens.InputTokens.Get()
	}
	return 0, false
}

func (u *RetrievalUsage) UnmarshalJSON(data []byte) error {
	type plain RetrievalUsage
	var decoded plain
	decodeTokenFields(data, &decoded)

	*u = RetrievalUsage(decoded)
	u.TotalTokens = decodeTokenField(data, "total_tokens")
	u.PromptTokens = decodeTokenField(data, "prompt_tokens")
	return nil
}

func (r *VendorRetrieval) InputTokenCount() (int, bool) {
	usage := &r.Output.Usage
	if tokens, reported := usage.PromptTokens.Get(); reported {
		return tokens, true
	}
	return usage.TotalTokens.Get()
}
