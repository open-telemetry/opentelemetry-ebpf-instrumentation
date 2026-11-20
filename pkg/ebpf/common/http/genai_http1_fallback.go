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
	if !cfg.OpenAI.Enabled && !cfg.Anthropic.Enabled && !cfg.Gemini.Enabled && !cfg.Bedrock.Enabled {
		return *baseSpan, false
	}

	// The provider paths are disjoint, so at most one provider can match.
	const requireEvidence = true
	path := requestPath(req)
	var classify func() (request.Span, bool)
	switch {
	case cfg.OpenAI.Enabled && isOpenAIHTTP1Path(path):
		classify = func() (request.Span, bool) { return openAISpan(baseSpan, req, resp, requireEvidence) }
	case cfg.Anthropic.Enabled && isAnthropicHTTP1Path(path):
		classify = func() (request.Span, bool) { return anthropicSpan(baseSpan, req, resp, looksLikeAnthropicHTTP1Body) }
	case cfg.Gemini.Enabled && isGeminiHTTP1Path(path):
		classify = func() (request.Span, bool) { return geminiSpan(baseSpan, req, resp, path, requireEvidence) }
	case cfg.Bedrock.Enabled && isBedrockHTTP1Path(path):
		classify = func() (request.Span, bool) { return bedrockSpan(baseSpan, req, resp, requireEvidence) }
	default:
		return *baseSpan, false
	}

	if matchOpenAICompatibleGateway(req, cfg.OpenAICompatible.Gateways) != nil {
		return *baseSpan, false
	}

	return classify()
}
