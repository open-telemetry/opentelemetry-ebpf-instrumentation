// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
)

func TestGenAIHTTP1FallbackProviders(t *testing.T) {
	cfg := config.GenAIConfig{
		OpenAI: config.OpenAIConfig{Enabled: true}, Anthropic: config.AnthropicConfig{Enabled: true},
		Gemini: config.GeminiConfig{Enabled: true}, Bedrock: config.BedrockConfig{Enabled: true},
	}
	for _, tc := range []struct {
		name, path, requestBody, responseBody string
		subtype                               int
		legacy                                func(*request.Span, *http.Request, *http.Response) (request.Span, bool)
	}{
		{"OpenAI", "/v1/chat/completions", completionsRequestBody, completionsResponseBody, request.HTTPSubtypeOpenAI, OpenAISpan},
		{"Anthropic", "/v1/messages", anthropicRequestBody, anthropicResponseBody, request.HTTPSubtypeAnthropic, AnthropicSpan},
		{"Gemini", "/v1beta/models/gemini-2.0-flash:generateContent", geminiRequestBody, geminiResponseBody, request.HTTPSubtypeGemini, GeminiSpan},
		{"Bedrock", "/model/anthropic.claude-v1/invoke", bedrockClaudeRequestBody, bedrockClaudeResponseBody, request.HTTPSubtypeAWSBedrock, BedrockSpan},
	} {
		for _, suffix := range []string{"", "/extra"} {
			t.Run(tc.name+suffix, func(t *testing.T) {
				req := makeRequest(t, http.MethodPost, tc.path+suffix, tc.requestBody)
				resp := makePlainResponse(http.StatusOK, http.Header{}, tc.responseBody)
				original := request.Span{Type: request.EventTypeHTTPClient, Path: tc.path + suffix, Host: "captured-host"}
				base := original
				_, legacyOK := tc.legacy(&base, req, resp)
				assert.False(t, legacyOK)
				assert.Equal(t, original, base)
				original.Path, base.Path = "/captured", "/captured"

				span, ok := GenAIHTTP1Fallback(&base, req, resp, cfg)

				assert.Equal(t, suffix == "", ok)
				if suffix == "" {
					assert.Equal(t, tc.subtype, span.SubType)
					require.NotNil(t, span.GenAI)
					req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/2.0", 2, 0
					legacyBase := request.Span{Type: request.EventTypeHTTPClient, Path: tc.path}
					legacySpan, legacyOK := tc.legacy(&legacyBase, req, resp)
					assert.True(t, legacyOK)
					assert.Equal(t, tc.subtype, legacySpan.SubType)
				} else {
					assert.Equal(t, original, span)
					assert.Equal(t, original, base)
				}
			})
		}
	}
}

func TestGenAIHTTP1FallbackGates(t *testing.T) {
	for _, tc := range []struct {
		name, target, protocol                              string
		disabled, noEvidence, gateway, nilRequest, detected bool
	}{
		{name: "HTTP1_1", detected: true},
		{name: "HTTP1_0", protocol: "HTTP/1.0"},
		{name: "HTTP2", protocol: "HTTP/2.0"},
		{name: "HTTP3", protocol: "HTTP/3.0"},
		{name: "unknown", protocol: "unknown"},
		{name: "nil_request", nilRequest: true},
		{name: "disabled", disabled: true},
		{name: "missing_evidence", noEvidence: true},
		{name: "gateway_extraction_disabled", gateway: true},
		{name: "query", target: "/v1/chat/completions?foo=bar", detected: true},
		{name: "absolute", target: "http://api.openai.com/v1/chat/completions", detected: true},
		{name: "absolute_query", target: "http://api.openai.com/v1/chat/completions?foo=bar", detected: true},
		{name: "near_miss_query", target: "/v1/chat/completions/extra?foo=bar"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := tc.target
			if target == "" {
				target = "/v1/chat/completions"
			}
			reqBody, respBody := completionsRequestBody, completionsResponseBody
			if tc.noEvidence {
				reqBody, respBody = "{}", "{}"
			}
			req := makeRequest(t, http.MethodPost, target, reqBody)
			req.Host = "litellm.local:8080"
			if tc.protocol != "" {
				req.Proto = tc.protocol
				req.ProtoMajor, req.ProtoMinor, _ = http.ParseHTTPVersion(tc.protocol)
			}
			if tc.nilRequest {
				req = nil
			}
			cfg := config.GenAIConfig{OpenAI: config.OpenAIConfig{Enabled: !tc.disabled}}
			if tc.gateway {
				cfg.OpenAICompatible.Gateways = []config.OpenAICompatibleGateway{{Host: "litellm.local"}}
			}
			resp := makePlainResponse(http.StatusOK, http.Header{}, respBody)
			original := request.Span{Type: request.EventTypeHTTPClient, Path: "/captured", Host: "captured-host"}
			base := original

			span, ok := GenAIHTTP1Fallback(&base, req, resp, cfg)

			assert.Equal(t, tc.detected, ok)
			if tc.detected {
				assert.Equal(t, request.HTTPSubtypeOpenAI, span.SubType)
				require.NotNil(t, span.GenAI)
			} else {
				assert.Equal(t, original, span)
				assert.Equal(t, original, base)
			}
		})
	}
}
