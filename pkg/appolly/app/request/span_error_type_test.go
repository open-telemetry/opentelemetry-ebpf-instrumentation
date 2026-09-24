// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSpanErrorType_GenAI(t *testing.T) {
	for _, tc := range []struct {
		name     string
		genAI    *GenAI
		expected string
	}{
		{
			name:     "openai",
			genAI:    &GenAI{OpenAI: &VendorOpenAI{Error: OpenAIError{Type: "rate_limit_error"}}},
			expected: "rate_limit_error",
		},
		{
			name:     "qwen shares VendorOpenAI",
			genAI:    &GenAI{Qwen: &VendorOpenAI{Error: OpenAIError{Type: "Throttling"}}},
			expected: "Throttling",
		},
		{
			name:     "openai-compatible shares VendorOpenAI",
			genAI:    &GenAI{OpenAICompatible: &VendorOpenAI{Error: OpenAIError{Type: "invalid_request_error"}}},
			expected: "invalid_request_error",
		},
		{
			name: "anthropic reports Output.Error.Type",
			genAI: &GenAI{Anthropic: &VendorAnthropic{
				Output: AnthropicResponse{Error: &AnthropicError{Type: "overloaded_error"}},
			}},
			expected: "overloaded_error",
		},
		{
			name: "gemini reports Output.Error.Status",
			genAI: &GenAI{Gemini: &VendorGemini{
				Output: GeminiResponse{Error: &GeminiError{Status: "RESOURCE_EXHAUSTED"}},
			}},
			expected: "RESOURCE_EXHAUSTED",
		},
		{
			name: "bedrock reports Output.ErrorType",
			genAI: &GenAI{Bedrock: &VendorBedrock{
				Output: BedrockResponse{ErrorType: "ThrottlingException"},
			}},
			expected: "ThrottlingException",
		},
		{
			name: "rerank reports Output.Error.Type",
			genAI: &GenAI{Rerank: &VendorRerank{
				Output: RerankResponse{Error: &RerankError{Type: "invalid_model"}},
			}},
			expected: "invalid_model",
		},
		{
			name:     "provider with no error falls back to the status",
			genAI:    &GenAI{OpenAI: &VendorOpenAI{}},
			expected: "429",
		},
		{
			name:     "nil GenAI falls back to the status",
			genAI:    nil,
			expected: "429",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			span := &Span{
				Type: EventTypeHTTPClient, SubType: HTTPSubtypeOpenAI,
				Method: "POST", Path: "/v1/chat", Status: 429, GenAI: tc.genAI,
			}

			assert.Equal(t, tc.expected, SpanErrorType(span))
		})
	}
}
