// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"strconv"

	jsoniter "github.com/json-iterator/go"
)

var tokenJSON = jsoniter.ConfigCompatibleWithStandardLibrary

func decodeTokenFields(data []byte, value any) {
	_ = tokenJSON.Unmarshal(data, value)
}

func decodeTokenField(data []byte, name string) (int, bool) {
	field := tokenJSON.Get(data, name)
	if field.ValueType() != jsoniter.NumberValue {
		return 0, false
	}
	tokens, err := strconv.Atoi(field.ToString())
	if err != nil {
		return 0, false
	}
	return tokens, true
}

func tokenReported(reported bool, value int) bool {
	return value > 0 || (reported && value == 0)
}

func reportedTokenCount(value int, reported bool) (int, bool) {
	if tokenReported(reported, value) {
		return value, true
	}
	return 0, false
}

func (u *OpenAIUsage) UnmarshalJSON(data []byte) error {
	type plain OpenAIUsage
	var decoded plain
	decodeTokenFields(data, &decoded)

	*u = OpenAIUsage(decoded)
	u.InputTokens, u.inputTokensReported = decodeTokenField(data, "input_tokens")
	u.OutputTokens, u.outputTokensReported = decodeTokenField(data, "output_tokens")
	u.TotalTokens, u.totalTokensReported = decodeTokenField(data, "total_tokens")
	u.PromptTokens, u.promptTokensReported = decodeTokenField(data, "prompt_tokens")
	u.CompletionTokens, u.completionTokensReported = decodeTokenField(data, "completion_tokens")
	return nil
}

func (u *OpenAIUsage) InputTokenCount() (int, bool) {
	if tokenReported(u.inputTokensReported, u.InputTokens) {
		return u.InputTokens, true
	}
	if tokenReported(u.promptTokensReported, u.PromptTokens) {
		return u.PromptTokens, true
	}
	return 0, false
}

func (u *OpenAIUsage) OutputTokenCount() (int, bool) {
	if tokenReported(u.outputTokensReported, u.OutputTokens) {
		return u.OutputTokens, true
	}
	if tokenReported(u.completionTokensReported, u.CompletionTokens) {
		return u.CompletionTokens, true
	}
	return 0, false
}

func (u *OpenAIUsage) SetInputTokens(tokens int) {
	u.InputTokens = tokens
	u.inputTokensReported = true
}

func (u *OpenAIUsage) SetOutputTokens(tokens int) {
	u.OutputTokens = tokens
	u.outputTokensReported = true
}

func (u *AnthropicUsage) UnmarshalJSON(data []byte) error {
	type plain AnthropicUsage
	var decoded plain
	decodeTokenFields(data, &decoded)

	*u = AnthropicUsage(decoded)
	u.InputTokens, u.inputTokensReported = decodeTokenField(data, "input_tokens")
	u.OutputTokens, u.outputTokensReported = decodeTokenField(data, "output_tokens")
	u.CacheCreationInputTokens, u.cacheCreationReported = decodeTokenField(data, "cache_creation_input_tokens")
	u.CacheReadInputTokens, u.cacheReadReported = decodeTokenField(data, "cache_read_input_tokens")
	return nil
}

func (u *AnthropicUsage) InputTokenCount() (int, bool) {
	total := 0
	reported := false
	for _, count := range []struct {
		value    int
		reported bool
	}{
		{u.InputTokens, u.inputTokensReported},
		{u.CacheCreationInputTokens, u.cacheCreationReported},
		{u.CacheReadInputTokens, u.cacheReadReported},
	} {
		if value, ok := reportedTokenCount(count.value, count.reported); ok {
			total += value
			reported = true
		}
	}
	return total, reported
}

func (u *AnthropicUsage) OutputTokenCount() (int, bool) {
	return reportedTokenCount(u.OutputTokens, u.outputTokensReported)
}

func (u *AnthropicUsage) Merge(other AnthropicUsage) {
	if tokenReported(other.inputTokensReported, other.InputTokens) {
		u.InputTokens = other.InputTokens
		u.inputTokensReported = true
	}
	if tokenReported(other.outputTokensReported, other.OutputTokens) {
		u.OutputTokens = other.OutputTokens
		u.outputTokensReported = true
	}
	if tokenReported(other.cacheCreationReported, other.CacheCreationInputTokens) {
		u.CacheCreationInputTokens = other.CacheCreationInputTokens
		u.cacheCreationReported = true
	}
	if tokenReported(other.cacheReadReported, other.CacheReadInputTokens) {
		u.CacheReadInputTokens = other.CacheReadInputTokens
		u.cacheReadReported = true
	}
}

func (u *GeminiUsage) UnmarshalJSON(data []byte) error {
	type plain GeminiUsage
	var decoded plain
	decodeTokenFields(data, &decoded)

	*u = GeminiUsage(decoded)
	u.PromptTokenCount, u.promptTokensReported = decodeTokenField(data, "promptTokenCount")
	u.CandidatesTokenCount, u.candidateTokensReported = decodeTokenField(data, "candidatesTokenCount")
	u.TotalTokenCount, u.totalTokensReported = decodeTokenField(data, "totalTokenCount")
	return nil
}

func (u *GeminiUsage) InputTokenCount() (int, bool) {
	return reportedTokenCount(u.PromptTokenCount, u.promptTokensReported)
}

func (u *GeminiUsage) OutputTokenCount() (int, bool) {
	return reportedTokenCount(u.CandidatesTokenCount, u.candidateTokensReported)
}

func (u *GeminiUsage) HasTokenCounts() bool {
	_, input := u.InputTokenCount()
	_, output := u.OutputTokenCount()
	return input || output || tokenReported(u.totalTokensReported, u.TotalTokenCount)
}

func (b *BedrockResponse) SetInputTokens(tokens int) {
	b.InputTokens = tokens
	b.inputTokensReported = true
}

func (b *BedrockResponse) SetOutputTokens(tokens int) {
	b.OutputTokens = tokens
	b.outputTokensReported = true
}

func (b *BedrockResponse) InputTokenCount() (int, bool) {
	return reportedTokenCount(b.InputTokens, b.inputTokensReported)
}

func (b *BedrockResponse) OutputTokenCount() (int, bool) {
	return reportedTokenCount(b.OutputTokens, b.outputTokensReported)
}

func (u *EmbeddingUsage) UnmarshalJSON(data []byte) error {
	type plain EmbeddingUsage
	var decoded plain
	decodeTokenFields(data, &decoded)

	*u = EmbeddingUsage(decoded)
	u.PromptTokens, u.promptTokensReported = decodeTokenField(data, "prompt_tokens")
	u.TotalTokens, u.totalTokensReported = decodeTokenField(data, "total_tokens")
	return nil
}

func (u *CohereBilledUnits) UnmarshalJSON(data []byte) error {
	type plain CohereBilledUnits
	var decoded plain
	decodeTokenFields(data, &decoded)

	*u = CohereBilledUnits(decoded)
	u.InputTokens, u.inputTokensReported = decodeTokenField(data, "input_tokens")
	return nil
}

func (e *VendorEmbedding) InputTokenCount() (int, bool) {
	usage := &e.Output.Usage
	if tokenReported(usage.promptTokensReported, usage.PromptTokens) {
		return usage.PromptTokens, true
	}
	if tokenReported(usage.totalTokensReported, usage.TotalTokens) {
		return usage.TotalTokens, true
	}
	if e.Output.Meta != nil && e.Output.Meta.BilledUnits != nil {
		billed := e.Output.Meta.BilledUnits
		return reportedTokenCount(billed.InputTokens, billed.inputTokensReported)
	}
	return 0, false
}

func (e *VendorEmbedding) OutputTokenCount() (int, bool) {
	usage := &e.Output.Usage
	if tokenReported(usage.totalTokensReported, usage.TotalTokens) &&
		tokenReported(usage.promptTokensReported, usage.PromptTokens) {
		return usage.TotalTokens - usage.PromptTokens, true
	}
	return 0, false
}

func (u *RerankUsage) UnmarshalJSON(data []byte) error {
	type plain RerankUsage
	var decoded plain
	decodeTokenFields(data, &decoded)

	*u = RerankUsage(decoded)
	u.TotalTokens, u.totalTokensReported = decodeTokenField(data, "total_tokens")
	u.PromptTokens, u.promptTokensReported = decodeTokenField(data, "prompt_tokens")
	return nil
}

func (u *RerankUsage) InputTokenCount() (int, bool) {
	if tokenReported(u.promptTokensReported, u.PromptTokens) {
		return u.PromptTokens, true
	}
	return reportedTokenCount(u.TotalTokens, u.totalTokensReported)
}

func (u *RerankMetaTokens) UnmarshalJSON(data []byte) error {
	type plain RerankMetaTokens
	var decoded plain
	decodeTokenFields(data, &decoded)

	*u = RerankMetaTokens(decoded)
	u.InputTokens, u.inputTokensReported = decodeTokenField(data, "input_tokens")
	return nil
}

func (r *RerankResponse) InputTokenCount() (int, bool) {
	if tokenReported(r.Usage.totalTokensReported, r.Usage.TotalTokens) {
		return r.Usage.TotalTokens, true
	}
	if tokenReported(r.Usage.promptTokensReported, r.Usage.PromptTokens) {
		return r.Usage.PromptTokens, true
	}
	if r.Meta != nil && r.Meta.Tokens != nil {
		tokens := r.Meta.Tokens
		return reportedTokenCount(tokens.InputTokens, tokens.inputTokensReported)
	}
	return 0, false
}

func (u *RetrievalUsage) UnmarshalJSON(data []byte) error {
	type plain RetrievalUsage
	var decoded plain
	decodeTokenFields(data, &decoded)

	*u = RetrievalUsage(decoded)
	u.TotalTokens, u.totalTokensReported = decodeTokenField(data, "total_tokens")
	u.PromptTokens, u.promptTokensReported = decodeTokenField(data, "prompt_tokens")
	return nil
}

func (r *VendorRetrieval) InputTokenCount() (int, bool) {
	usage := &r.Output.Usage
	if tokenReported(usage.promptTokensReported, usage.PromptTokens) {
		return usage.PromptTokens, true
	}
	return reportedTokenCount(usage.TotalTokens, usage.totalTokensReported)
}
