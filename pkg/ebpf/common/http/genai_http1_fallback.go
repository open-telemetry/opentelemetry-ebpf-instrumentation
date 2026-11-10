// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"net/http"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
)

// GenAIHTTP1Fallback classifies an HTTP/1.1 client span whose request path
// exactly matches an endpoint of an enabled OpenAI, Anthropic, Gemini or
// Bedrock provider. It is meant to run after the existing detectors decline.
// Configured OpenAI-compatible gateway hosts are skipped, even when gateway
// extraction is disabled. Each provider must also pass its evidence check:
// OpenAI and Bedrock check the payload, Gemini also accepts a gemini model
// named in the path, and Anthropic uses a stricter check than over HTTP/2.
func GenAIHTTP1Fallback(baseSpan *request.Span, req *http.Request, resp *http.Response, cfg config.GenAIConfig) (request.Span, bool) {
	if !baseSpan.IsClientSpan() {
		return *baseSpan, false
	}
	if req == nil || req.ProtoMajor != 1 || req.ProtoMinor != 1 {
		return *baseSpan, false
	}
	if matchOpenAICompatibleGateway(req, cfg.OpenAICompatible.Gateways) != nil {
		return *baseSpan, false
	}

	const requireEvidence = true
	path := requestPath(req)
	if cfg.OpenAI.Enabled && isOpenAIHTTP1Path(path) {
		if span, ok := openAISpan(baseSpan, req, resp, requireEvidence); ok {
			return span, true
		}
	}
	if cfg.Anthropic.Enabled && isAnthropicHTTP1Path(path) {
		if span, ok := anthropicSpan(baseSpan, req, resp, looksLikeAnthropicHTTP1Body); ok {
			return span, true
		}
	}
	if cfg.Gemini.Enabled && isGeminiHTTP1Path(path) {
		if span, ok := geminiSpan(baseSpan, req, resp, path, requireEvidence); ok {
			return span, true
		}
	}
	if cfg.Bedrock.Enabled && isBedrockHTTP1Path(path) {
		if span, ok := bedrockSpan(baseSpan, req, resp, requireEvidence); ok {
			return span, true
		}
	}

	return *baseSpan, false
}
