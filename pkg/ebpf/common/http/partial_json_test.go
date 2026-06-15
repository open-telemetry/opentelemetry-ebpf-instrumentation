// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractModelField(t *testing.T) {
	full := `{"messages":[{"role":"user","content":"hi"}],"model":"gpt-4o-mini","temperature":1.0}`
	truncated := full[:len(full)-len(`,"temperature":1.0}`)]

	assert.Equal(t, "gpt-4o-mini", extractModelField([]byte(full)))
	assert.Equal(t, "gpt-4o-mini", extractModelField([]byte(truncated)))
	assert.Empty(t, extractModelField(nil))
}

func TestExtractJSONStringField_respectsWindow(t *testing.T) {
	body := []byte(`{"nested":{"id":"inner"},"id":"outer"}`)
	assert.Equal(t, "inner", extractJSONStringField(body, "id", 0))
	assert.NotEmpty(t, extractJSONStringField(body, "id", 50))
}

func TestParseOpenAIInput_truncated(t *testing.T) {
	body := []byte(`{"model":"gpt-5-mini","input":"hello`)
	parsed := parseOpenAIInput(body)
	assert.Equal(t, "gpt-5-mini", parsed.Model)
}

func TestParseVendorOpenAI_truncated(t *testing.T) {
	body := []byte(`{"id":"resp_123","object":"response","model":"gpt-5-mini","output":[`)
	parsed := parseVendorOpenAI(body)
	assert.Equal(t, "resp_123", parsed.ID)
	assert.Equal(t, "response", parsed.OperationName)
	assert.Equal(t, "gpt-5-mini", parsed.ResponseModel)
}

func TestParseAnthropicRequest_truncated(t *testing.T) {
	body := []byte(`{"model":"claude-3-opus","messages":[{"role":"user","content":"hi"}`)
	parsed := parseAnthropicRequest(body)
	assert.Equal(t, "claude-3-opus", parsed.Model)
}

func TestParseEmbeddingRequest_truncated(t *testing.T) {
	body := []byte(`{"model":"text-embedding-3-small","input":"food`)
	parsed := parseEmbeddingRequest(body)
	assert.Equal(t, "text-embedding-3-small", parsed.Model)
}
