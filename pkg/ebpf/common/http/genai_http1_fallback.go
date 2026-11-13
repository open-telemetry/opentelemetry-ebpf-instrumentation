// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"net/http"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
)

// GenAIHTTP1Fallback tries enabled OpenAI, Anthropic, Gemini, then Bedrock
// heuristics for HTTP/1.1 after existing detectors decline, using their existing
// payload evidence checks. Configured OpenAI-compatible gateway hosts are excluded
// even when their extraction is disabled. Callers must restrict use to client spans.
func GenAIHTTP1Fallback(baseSpan *request.Span, req *http.Request, resp *http.Response, cfg config.GenAIConfig) (request.Span, bool) {
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
		if span, ok := anthropicSpan(baseSpan, req, resp, requireEvidence); ok {
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
