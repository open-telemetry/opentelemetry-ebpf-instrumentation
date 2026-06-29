// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"strings"
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
	assert.Equal(t, "outer", extractJSONStringField(body, "id", 0))
	assert.Empty(t, extractJSONStringField(body, "id", 30))
}

func TestExtractJSONStringField_ignoresNestedField(t *testing.T) {
	body := []byte(`{"nested":{"id":"inner","model":"attacker"},"id":"outer","model":"gpt-5-mini"}`)
	assert.Equal(t, "outer", extractJSONStringField(body, "id", 0))
	assert.Equal(t, "gpt-5-mini", extractModelField(body))
}

func TestExtractModelField_ignoresNestedModelWithoutTopLevel(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":{"model":"attacker"}}]}`)
	assert.Empty(t, extractModelField(body))
}

func TestExtractModelField_ignoresNestedModelAfterSearchWindow(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"` + strings.Repeat("x", 220) + `","metadata":{"model":"attacker"}}]}`)
	assert.Empty(t, extractModelField(body))
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

func TestExtractJSONRawField(t *testing.T) {
	t.Run("complete array", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`)
		raw := extractJSONRawField(body, "messages")
		assert.JSONEq(t, `[{"role":"user","content":"hi"}]`, string(raw))
	})

	t.Run("complete array in truncated body", func(t *testing.T) {
		body := []byte(`{"model":"qwen-plus","messages":[{"role":"user","content":"hello"}],"stre`)
		raw := extractJSONRawField(body, "messages")
		assert.JSONEq(t, `[{"role":"user","content":"hello"}]`, string(raw))
	})

	t.Run("truncated array returns nil", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"he`)
		raw := extractJSONRawField(body, "messages")
		assert.Nil(t, raw)
	})

	t.Run("nested objects", func(t *testing.T) {
		body := []byte(`{"messages":[{"role":"user","content":"say \"hi\""}]}`)
		raw := extractJSONRawField(body, "messages")
		assert.JSONEq(t, `[{"role":"user","content":"say \"hi\""}]`, string(raw))
	})

	t.Run("object field", func(t *testing.T) {
		body := []byte(`{"config":{"key":"val"},"other":1}`)
		raw := extractJSONRawField(body, "config")
		assert.JSONEq(t, `{"key":"val"}`, string(raw))
	})

	t.Run("field not found", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4"}`)
		raw := extractJSONRawField(body, "messages")
		assert.Nil(t, raw)
	})

	t.Run("nil body", func(t *testing.T) {
		assert.Nil(t, extractJSONRawField(nil, "messages"))
	})

	t.Run("scalar value", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4","count":5}`)
		raw := extractJSONRawField(body, "count")
		assert.Equal(t, "5", string(raw))
	})

	t.Run("does not match value as key", func(t *testing.T) {
		body := []byte(`{"label":"field","field":99}`)
		raw := extractJSONRawField(body, "field")
		assert.Equal(t, "99", string(raw))
	})
}

func TestParseOpenAIInput_messagesFromTruncatedBody(t *testing.T) {
	body := []byte(`{"model":"qwen-plus","messages":[{"role":"user","content":"你好"}],"stre`)
	parsed := parseOpenAIInput(body)
	assert.Equal(t, "qwen-plus", parsed.Model)
	assert.NotNil(t, parsed.Messages)
	assert.JSONEq(t, `[{"role":"user","content":"你好"}]`, string(parsed.Messages))
}
