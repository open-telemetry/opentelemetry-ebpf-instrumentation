// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	ebpfhttp "go.opentelemetry.io/obi/pkg/ebpf/common/http"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
)

// Responses captured from Ollama v0.40.13 (qwen2.5:0.5b) by sending the same
// /api/chat request twice. The second request reuses the cached prompt prefix.
// The request body is trimmed; only the model is relevant here.
const (
	ollamaCacheRequest = `{"model":"qwen2.5:0.5b","stream":false,"messages":[{"role":"user","content":"Say hi."}]}`

	ollamaFirstCallResponse = `{"model":"qwen2.5:0.5b","created_at":"2026-11-01T04:34:29.411643886Z","message":{"role":"assistant","content":"Hi!"},"done":true,"done_reason":"stop","total_duration":23671921428,"load_duration":11330557255,"prompt_eval_count":66,"prompt_eval_cached_count":0,"prompt_eval_duration":3645078000,"eval_count":3,"eval_duration":8676961000}`

	ollamaCachedCallResponse = `{"model":"qwen2.5:0.5b","created_at":"2026-11-01T04:34:46.276647963Z","message":{"role":"assistant","content":"Hi!"},"done":true,"done_reason":"stop","total_duration":16521351965,"load_duration":3592666,"prompt_eval_count":66,"prompt_eval_cached_count":65,"prompt_eval_duration":6156203000,"eval_count":3,"eval_duration":10338652000}`

	ollamaCachedCallStreamResponse = `{"model":"qwen2.5:0.5b","created_at":"2026-11-01T04:35:37.354502209Z","message":{"role":"assistant","content":"Hi"},"done":false}
{"model":"qwen2.5:0.5b","created_at":"2026-11-01T04:35:40.215645418Z","message":{"role":"assistant","content":"!"},"done":false}
{"model":"qwen2.5:0.5b","created_at":"2026-11-01T04:35:42.434530253Z","message":{"role":"assistant","content":""},"done":true,"done_reason":"stop","total_duration":55756341526,"load_duration":13744333,"prompt_eval_count":66,"prompt_eval_cached_count":65,"prompt_eval_duration":2713732000,"eval_count":3,"eval_duration":5079019000}`

	// Hand-written: servers older than v0.33.3 omit prompt_eval_cached_count.
	ollamaNoCacheFieldResponse = `{"model":"qwen2.5:0.5b","message":{"role":"assistant","content":"Hi!"},"done":true,"done_reason":"stop","prompt_eval_count":66,"eval_count":3}`
)

func TestOllamaSpan_ExportsCacheReadInputTokens(t *testing.T) {
	const (
		inputKey     = "gen_ai.usage.input_tokens"
		outputKey    = "gen_ai.usage.output_tokens"
		cacheReadKey = "gen_ai.usage.cache_read.input_tokens"
	)

	defaultAttrs, err := tracesgen.UserSelectedAttributes(&attributes.SelectorConfig{})
	require.NoError(t, err)

	for _, tt := range []struct {
		name      string
		response  string
		cacheRead int64
		hasCache  bool
	}{
		{name: "first call", response: ollamaFirstCallResponse, cacheRead: 0, hasCache: true},
		{name: "cached call", response: ollamaCachedCallResponse, cacheRead: 65, hasCache: true},
		{name: "cached call streaming", response: ollamaCachedCallStreamResponse, cacheRead: 65, hasCache: true},
		{name: "older Ollama without cache field", response: ollamaNoCacheFieldResponse},
	} {
		t.Run(tt.name, func(t *testing.T) {
			span, ok := ollamaSpan(ollamaCacheRequest, tt.response)
			require.True(t, ok)

			selected := tracesgen.AttrsToMap(tracesgen.TraceAttributesSelector(&span, defaultAttrs))

			input, ok := selected.Get(inputKey)
			require.True(t, ok)
			assert.Equal(t, int64(66), input.Int())
			output, ok := selected.Get(outputKey)
			require.True(t, ok)
			assert.Equal(t, int64(3), output.Int())

			cacheRead, ok := selected.Get(cacheReadKey)
			require.Equal(t, tt.hasCache, ok)
			if tt.hasCache {
				assert.Equal(t, tt.cacheRead, cacheRead.Int())
			}
		})
	}
}

func ollamaSpan(reqBody, respBody string) (request.Span, bool) {
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/api/chat"},
		Body:   io.NopCloser(strings.NewReader(reqBody)),
		Header: http.Header{"Content-Type": []string{"application/json"}},
	}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(respBody)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
	baseSpan := &request.Span{
		Type:   request.EventTypeHTTPClient,
		Method: http.MethodPost,
		Path:   "/api/chat",
	}
	return ebpfhttp.OllamaSpan(baseSpan, req, resp)
}
