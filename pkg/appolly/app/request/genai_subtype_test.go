// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMCPIsNotRecordedOnTheGenAIMetrics(t *testing.T) {
	assert.False(t, IsGenAISubtype(HTTPSubtypeMCP))
}

func TestGenAIProvidersAreRecordedOnTheGenAIMetrics(t *testing.T) {
	for _, subtype := range []int{
		HTTPSubtypeOpenAI,
		HTTPSubtypeAnthropic,
		HTTPSubtypeGemini,
		HTTPSubtypeQwen,
		HTTPSubtypeAWSBedrock,
		HTTPSubtypeEmbedding,
		HTTPSubtypeRerank,
		HTTPSubtypeRetrieval,
		HTTPSubtypeOpenAICompatible,
		HTTPSubtypeOllama,
	} {
		assert.True(t, IsGenAISubtype(subtype), "subtype %d", subtype)
	}
}
