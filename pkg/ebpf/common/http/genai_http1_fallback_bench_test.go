// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
)

// newGenAIHTTP1BenchmarkExchange parses the request off the wire so the Host
// header carries no port, as for a default-port HTTPS client.
func newGenAIHTTP1BenchmarkExchange(b *testing.B, target, requestBody, responseBody string) (*http.Request, *http.Response) {
	b.Helper()
	raw := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		target, len(requestBody), requestBody)
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	require.NoError(b, err)
	resp := &http.Response{
		StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(strings.NewReader(responseBody)),
	}
	return req, resp
}

func BenchmarkGenAIHTTP1Fallback(b *testing.B) {
	providers := config.GenAIConfig{
		OpenAI: config.OpenAIConfig{Enabled: true}, Anthropic: config.AnthropicConfig{Enabled: true},
		Gemini: config.GeminiConfig{Enabled: true}, Bedrock: config.BedrockConfig{Enabled: true},
	}
	withGateway := providers
	withGateway.OpenAICompatible.Gateways = []config.OpenAICompatibleGateway{{Host: "gateway.example", Port: 4000, Provider: "test-gateway"}}

	const plainPath, plainRequest, plainResponse = "/api/users", `{"name":"alice"}`, `{"id":1,"name":"alice"}`

	for _, tc := range []struct {
		name                              string
		cfg                               config.GenAIConfig
		target, requestBody, responseBody string
		http2, want                       bool
	}{
		{name: "disabled", target: plainPath, requestBody: plainRequest, responseBody: plainResponse},
		{name: "enabled_nonmatching_path", cfg: providers, target: plainPath, requestBody: plainRequest, responseBody: plainResponse},
		{name: "http2_request", cfg: providers, target: "/v1/chat/completions", requestBody: completionsRequestBody, responseBody: completionsResponseBody, http2: true},
		{name: "gateway_configured_nonmatching_path", cfg: withGateway, target: plainPath, requestBody: plainRequest, responseBody: plainResponse},
		{name: "matching_path_rejected_body", cfg: providers, target: "/v1/messages", requestBody: `{"to":"+15550100","text":"hi"}`, responseBody: `{"type":"message","id":"m1","status":"queued"}`},
		{name: "openai_detected", cfg: providers, target: "/v1/chat/completions", requestBody: completionsRequestBody, responseBody: completionsResponseBody, want: true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			// Detectors restore the bodies they read, so one exchange serves every iteration.
			req, resp := newGenAIHTTP1BenchmarkExchange(b, tc.target, tc.requestBody, tc.responseBody)
			if tc.http2 {
				req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/2.0", 2, 0
			}
			base := request.Span{Type: request.EventTypeHTTPClient, Method: http.MethodPost, Path: tc.target}

			b.ReportAllocs()

			var ok bool
			for b.Loop() {
				span := base
				_, ok = GenAIHTTP1Fallback(&span, req, resp, tc.cfg)
			}

			require.Equal(b, tc.want, ok)
		})
	}
}
