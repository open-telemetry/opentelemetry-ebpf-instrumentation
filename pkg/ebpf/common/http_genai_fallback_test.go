// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfhttp "go.opentelemetry.io/obi/pkg/ebpf/common/http"
)

const (
	genAIHTTP1GatewayHost    = "gateway.example"
	genAIHTTP1OpenAIRequest  = `{"model":"gpt-4o-mini","messages":[]}`
	genAIHTTP1OpenAIResponse = `{"model":"gpt-4o-mini","choices":[]}`
	genAIHTTP1GeminiPath     = "/v1beta/models/gemini-2.0-flash:generateContent"
)

func newGenAIHTTP1ParseContext() *EBPFParseContext {
	ctx := &EBPFParseContext{payloadExtraction: config.PayloadExtraction{HTTP: config.HTTPConfig{
		GenAI: config.GenAIConfig{OpenAI: config.OpenAIConfig{Enabled: true}, Gemini: config.GeminiConfig{Enabled: true}},
	}}}
	ctx.payloadExtraction.HTTP.Enrichment = config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{DefaultAction: config.HTTPParsingDefaultAction{
			Headers: config.HTTPParsingActionExclude,
			Body:    config.HTTPParsingActionInclude,
		}},
	}
	ctx.httpEnricher = ebpfhttp.NewHTTPEnricher(ctx.payloadExtraction.HTTP.Enrichment)
	return ctx
}

func newGenAIHTTP1Exchange(t *testing.T, target, requestBody, responseBody string) (*http.Request, *http.Response) {
	t.Helper()
	raw := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		target, genAIHTTP1GatewayHost, len(requestBody), requestBody)
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	require.NoError(t, err)
	resp := &http.Response{
		StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(strings.NewReader(responseBody)),
	}
	return req, resp
}

func TestPostProcessHTTPSpanGenAIHTTP1Wiring(t *testing.T) {
	for _, tc := range []struct {
		name, target                                        string
		server, nilContext, gateway, gatewayEnabled, strong bool
		subtype                                             int
	}{
		{name: "server", server: true},
		{name: "nil_context", nilContext: true},
		{name: "absolute_query", target: "http://api.openai.com/v1/chat/completions?foo=bar", subtype: request.HTTPSubtypeOpenAI},
		{name: "gateway_enabled", gateway: true, gatewayEnabled: true, subtype: request.HTTPSubtypeOpenAICompatible},
		{name: "strong_gateway", target: "/unrelated", gateway: true, gatewayEnabled: true, strong: true, subtype: request.HTTPSubtypeOpenAI},
		{name: "strong_gateway_disabled", target: "/unrelated", gateway: true, strong: true, subtype: request.HTTPSubtypeOpenAI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parseCtx := newGenAIHTTP1ParseContext()
			parseCtx.payloadExtraction.HTTP.GenAI.OpenAICompatible.Enabled = tc.gatewayEnabled
			if tc.gateway {
				parseCtx.payloadExtraction.HTTP.GenAI.OpenAICompatible.Gateways = []config.OpenAICompatibleGateway{{Host: genAIHTTP1GatewayHost, Provider: "test-gateway"}}
			}
			target := tc.target
			if target == "" {
				target = "/v1/chat/completions"
			}
			req, resp := newGenAIHTTP1Exchange(t, target, genAIHTTP1OpenAIRequest, genAIHTTP1OpenAIResponse)
			if tc.strong {
				resp.Header.Set("Openai-Version", "2020-10-01")
			}
			event := &BPFHTTPInfo{Type: uint8(request.EventTypeHTTPClient)}
			if tc.server {
				event.Type = uint8(request.EventTypeHTTP)
			}
			if tc.nilContext {
				parseCtx = nil
			}

			span := httpRequestResponseToSpan(parseCtx, event, req, resp)

			assert.Equal(t, tc.subtype, span.SubType)
			assert.Equal(t, request.EventType(event.Type), span.Type)
			if tc.subtype == request.HTTPSubtypeNone {
				assert.Nil(t, span.GenAI)
			} else {
				require.NotNil(t, span.GenAI)
				assert.Empty(t, span.RequestBodyContent)
				assert.Empty(t, span.ResponseBodyContent)
			}
			if tc.name == "absolute_query" {
				assert.Equal(t, "http://api.openai.com/v1/chat/completions", span.Path)
				assert.Equal(t, target, span.FullPath)
				assert.Equal(t, request.ChatOperationName, span.GenAI.OpenAI.OperationName)
			}
		})
	}
}

func TestPostProcessHTTPSpanGenAIHTTP1RPCPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, requestBody, responseBody string
		subtype                         int
	}{
		{"JSONRPC", `{"jsonrpc":"2.0","id":1,"method":"subtract","params":[42,23]}`, `{"jsonrpc":"2.0","id":1,"result":19}`, request.HTTPSubtypeJSONRPC},
		{"MCP", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05"}}`, request.HTTPSubtypeMCP},
		{"GenAI_after_RPC_rejection", `{"contents":[{"parts":[{"text":"hi"}]}]}`, `{"modelVersion":"gemini-2.0-flash","candidates":[]}`, request.HTTPSubtypeGemini},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parseCtx := newGenAIHTTP1ParseContext()
			parseCtx.payloadExtraction.HTTP.GenAI.MCP.Enabled = true
			parseCtx.payloadExtraction.HTTP.JSONRPC.Enabled = true
			req, resp := newGenAIHTTP1Exchange(t, genAIHTTP1GeminiPath, tc.requestBody, tc.responseBody)

			span := httpRequestResponseToSpan(parseCtx, &BPFHTTPInfo{Type: uint8(request.EventTypeHTTPClient)}, req, resp)

			assert.Equal(t, tc.subtype, span.SubType)
		})
	}
}

func TestPostProcessHTTPSpanGenAIHTTP1RPCReadError(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(enabled), func(t *testing.T) {
			parseCtx := newGenAIHTTP1ParseContext()
			parseCtx.payloadExtraction.HTTP.JSONRPC.Enabled = enabled
			req, resp := newGenAIHTTP1Exchange(t, "/v1/chat/completions", genAIHTTP1OpenAIRequest, "{}")
			req.Body = io.NopCloser(io.MultiReader(strings.NewReader(genAIHTTP1OpenAIRequest), readErrorCloser{err: io.ErrUnexpectedEOF}))

			span := httpRequestResponseToSpan(parseCtx, &BPFHTTPInfo{Type: uint8(request.EventTypeHTTPClient)}, req, resp)

			if enabled {
				assert.Equal(t, request.HTTPSubtypeNone, span.SubType)
				assert.Nil(t, span.GenAI)
			} else {
				assert.Equal(t, request.HTTPSubtypeOpenAI, span.SubType)
				require.NotNil(t, span.GenAI)
			}
		})
	}
}

func TestPostProcessHTTPSpanGenAIHTTP1BodyPreservation(t *testing.T) {
	parseCtx := newGenAIHTTP1ParseContext()
	requestBody, responseBody := `{"request":"preserve me"}`, `{"response":"preserve me"}`
	req, resp := newGenAIHTTP1Exchange(t, "/v1/chat/completions", requestBody, responseBody)
	event := &BPFHTTPInfo{Type: uint8(request.EventTypeHTTPClient)}

	span := httpRequestResponseToSpan(parseCtx, event, req, resp)

	assert.Equal(t, request.HTTPSubtypeNone, span.SubType)
	assert.Nil(t, span.GenAI)
	assert.Equal(t, requestBody, span.RequestBodyContent, "request body after rejected fallback")
	assert.Equal(t, responseBody, span.ResponseBodyContent, "response body after rejected fallback")
}
