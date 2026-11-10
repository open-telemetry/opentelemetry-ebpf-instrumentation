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
		t.Run(tc.name, func(t *testing.T) {
			req := makeRequest(t, http.MethodPost, tc.path, tc.requestBody)
			resp := makePlainResponse(http.StatusOK, http.Header{}, tc.responseBody)

			// The existing detector declines the header-less HTTP/1.1 exchange.
			declined := request.Span{Type: request.EventTypeHTTPClient, Path: tc.path}
			legacyBase := declined
			_, ok := tc.legacy(&legacyBase, req, resp)
			require.False(t, ok)
			assert.Equal(t, declined, legacyBase)

			// The fallback claims it from the request path, not the span path.
			base := request.Span{Type: request.EventTypeHTTPClient, Path: "/captured"}
			span, ok := GenAIHTTP1Fallback(&base, req, resp, cfg)
			require.True(t, ok)
			assert.Equal(t, tc.subtype, span.SubType)
			require.NotNil(t, span.GenAI)

			// A path just past the provider endpoint is left untouched.
			nearMissReq := makeRequest(t, http.MethodPost, tc.path+"/extra", tc.requestBody)
			nearMissResp := makePlainResponse(http.StatusOK, http.Header{}, tc.responseBody)
			original := request.Span{Type: request.EventTypeHTTPClient, Path: "/captured"}
			nearMiss := original
			span, ok = GenAIHTTP1Fallback(&nearMiss, nearMissReq, nearMissResp, cfg)
			assert.False(t, ok)
			assert.Equal(t, original, span)
			assert.Equal(t, original, nearMiss)

			// With every provider disabled, the same exchange is left untouched.
			disabledReq := makeRequest(t, http.MethodPost, tc.path, tc.requestBody)
			disabledResp := makePlainResponse(http.StatusOK, http.Header{}, tc.responseBody)
			disabled := original
			span, ok = GenAIHTTP1Fallback(&disabled, disabledReq, disabledResp, config.GenAIConfig{})
			assert.False(t, ok)
			assert.Equal(t, original, span)
			assert.Equal(t, original, disabled)

			// Over HTTP/2 the existing detector still claims the same exchange.
			req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/2.0", 2, 0
			legacyBase = request.Span{Type: request.EventTypeHTTPClient, Path: tc.path}
			legacySpan, ok := tc.legacy(&legacyBase, req, resp)
			require.True(t, ok)
			assert.Equal(t, tc.subtype, legacySpan.SubType)
		})
	}
}

func TestGenAIHTTP1FallbackGates(t *testing.T) {
	for _, tc := range []struct {
		name, target, protocol                                      string
		disabled, noEvidence, gateway, nilRequest, server, detected bool
	}{
		{name: "HTTP1_1", detected: true},
		{name: "server_span", server: true},
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
			if tc.server {
				original.Type = request.EventTypeHTTP
			}
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

func TestGenAIHTTP1FallbackAnthropic(t *testing.T) {
	type testCase struct {
		name, requestBody, responseBody string
		gateway, detected               bool
	}
	cases := []testCase{
		{name: "JSON", requestBody: anthropicCompatibleRequestBody, responseBody: anthropicResponseBody, detected: true},
		{name: "SSE", requestBody: anthropicCompatibleRequestBody, responseBody: anthropicStreamingResponseBody, detected: true},
		{name: "gateway", requestBody: anthropicRequestBody, responseBody: anthropicResponseBody, gateway: true},
	}
	for _, fp := range anthropicHTTP1FalsePositives {
		cases = append(cases, testCase{name: fp.name, requestBody: fp.request, responseBody: fp.response})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := makeRequest(t, http.MethodPost, anthropicMessagesPath, tc.requestBody)
			req.Host = "litellm.local:8080"
			resp := makePlainResponse(http.StatusOK, http.Header{}, tc.responseBody)
			cfg := config.GenAIConfig{Anthropic: config.AnthropicConfig{Enabled: true}}
			if tc.gateway {
				cfg.OpenAICompatible.Gateways = []config.OpenAICompatibleGateway{{Host: "litellm.local"}}
			}
			original := request.Span{Type: request.EventTypeHTTPClient, Path: anthropicMessagesPath, Host: "captured-host"}
			base := original

			span, ok := GenAIHTTP1Fallback(&base, req, resp, cfg)

			assert.Equal(t, tc.detected, ok)
			if tc.detected {
				assert.Equal(t, request.HTTPSubtypeAnthropic, span.SubType)
				require.NotNil(t, span.GenAI)
				require.NotNil(t, span.GenAI.Anthropic)
			} else {
				assert.Equal(t, original, span)
				assert.Equal(t, original, base)
			}
		})
	}
}

// TestGenAIBedrockTitanDeclined checks that a header-less Titan call is not
// claimed as Bedrock: its body has no Claude-on-Bedrock anthropic_version.
func TestGenAIBedrockTitanDeclined(t *testing.T) {
	const path = "/model/amazon.titan-text-premier-v1:0/invoke"
	cfg := config.GenAIConfig{Bedrock: config.BedrockConfig{Enabled: true}}
	for _, tc := range []struct {
		name   string
		http2  bool
		detect func(*request.Span, *http.Request, *http.Response) (request.Span, bool)
	}{
		{name: "HTTP1_1_fallback", detect: func(span *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
			return GenAIHTTP1Fallback(span, req, resp, cfg)
		}},
		{name: "HTTP2_BedrockSpan", http2: true, detect: BedrockSpan},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := makeRequest(t, http.MethodPost, path, bedrockTitanRequestBody)
			if tc.http2 {
				req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/2.0", 2, 0
			}
			resp := makePlainResponse(http.StatusOK, http.Header{}, bedrockTitanResponseBody)
			original := request.Span{Type: request.EventTypeHTTPClient, Path: path}
			base := original

			span, ok := tc.detect(&base, req, resp)

			assert.False(t, ok)
			assert.Equal(t, original, span)
			assert.Equal(t, original, base)
		})
	}
}
