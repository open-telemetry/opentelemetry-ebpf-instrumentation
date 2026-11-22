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

// newGenAIHTTP1GatewayParseContext configures genAIHTTP1GatewayHost as an
// OpenAI-compatible gateway, with gateway extraction on or off.
func newGenAIHTTP1GatewayParseContext(extractionEnabled bool) *EBPFParseContext {
	parseCtx := newGenAIHTTP1ParseContext()
	parseCtx.payloadExtraction.HTTP.GenAI.OpenAICompatible = config.OpenAICompatibleConfig{
		Enabled:  extractionEnabled,
		Gateways: []config.OpenAICompatibleGateway{{Host: genAIHTTP1GatewayHost, Provider: "test-gateway"}},
	}
	return parseCtx
}

// assertGenAIHTTP1Classified checks the span's subtype and that the GenAI
// payload replaced the raw bodies.
func assertGenAIHTTP1Classified(t *testing.T, span request.Span, subtype int) {
	t.Helper()
	assert.Equal(t, subtype, span.SubType)
	require.NotNil(t, span.GenAI)
	assert.Empty(t, span.RequestBodyContent)
	assert.Empty(t, span.ResponseBodyContent)
}

func TestPostProcessHTTPSpanGenAIHTTP1Wiring(t *testing.T) {
	req, resp := newGenAIHTTP1Exchange(t, "/v1/chat/completions", genAIHTTP1OpenAIRequest, genAIHTTP1OpenAIResponse)
	event := &BPFHTTPInfo{Type: uint8(request.EventTypeHTTPClient)}

	span := httpRequestResponseToSpan(newGenAIHTTP1ParseContext(), event, req, resp)

	assert.Equal(t, request.EventTypeHTTPClient, span.Type)
	assertGenAIHTTP1Classified(t, span, request.HTTPSubtypeOpenAI)
}

func TestPostProcessHTTPSpanGenAIHTTP1SkipsServerSpan(t *testing.T) {
	req, resp := newGenAIHTTP1Exchange(t, "/v1/chat/completions", genAIHTTP1OpenAIRequest, genAIHTTP1OpenAIResponse)
	event := &BPFHTTPInfo{Type: uint8(request.EventTypeHTTP)}

	span := httpRequestResponseToSpan(newGenAIHTTP1ParseContext(), event, req, resp)

	assert.Equal(t, request.EventTypeHTTP, span.Type)
	assert.Equal(t, request.HTTPSubtypeNone, span.SubType)
	assert.Nil(t, span.GenAI)
}

func TestPostProcessHTTPSpanGenAIHTTP1SkipsNilContext(t *testing.T) {
	req, resp := newGenAIHTTP1Exchange(t, "/v1/chat/completions", genAIHTTP1OpenAIRequest, genAIHTTP1OpenAIResponse)
	event := &BPFHTTPInfo{Type: uint8(request.EventTypeHTTPClient)}

	span := httpRequestResponseToSpan(nil, event, req, resp)

	assert.Equal(t, request.EventTypeHTTPClient, span.Type)
	assert.Equal(t, request.HTTPSubtypeNone, span.SubType)
	assert.Nil(t, span.GenAI)
}

// With gateway extraction enabled, the gateway detector claims the exchange first.
func TestPostProcessHTTPSpanGenAIHTTP1GatewayExtractionEnabled(t *testing.T) {
	req, resp := newGenAIHTTP1Exchange(t, "/v1/chat/completions", genAIHTTP1OpenAIRequest, genAIHTTP1OpenAIResponse)
	event := &BPFHTTPInfo{Type: uint8(request.EventTypeHTTPClient)}

	span := httpRequestResponseToSpan(newGenAIHTTP1GatewayParseContext(true), event, req, resp)

	assertGenAIHTTP1Classified(t, span, request.HTTPSubtypeOpenAICompatible)
}

// With gateway extraction disabled, vendor headers still let the existing
// OpenAI detector claim a gateway exchange on any path.
func TestPostProcessHTTPSpanGenAIHTTP1GatewayVendorHeaders(t *testing.T) {
	req, resp := newGenAIHTTP1Exchange(t, "/unrelated", genAIHTTP1OpenAIRequest, genAIHTTP1OpenAIResponse)
	resp.Header.Set("Openai-Version", "2020-10-01")
	event := &BPFHTTPInfo{Type: uint8(request.EventTypeHTTPClient)}

	span := httpRequestResponseToSpan(newGenAIHTTP1GatewayParseContext(false), event, req, resp)

	assertGenAIHTTP1Classified(t, span, request.HTTPSubtypeOpenAI)
}

func TestPostProcessHTTPSpanGenAIHTTP1OpenAIEndpoints(t *testing.T) {
	for _, tc := range []struct {
		name, target, requestBody, responseBody, wantPath, wantOperation string
		wantSubtype                                                      int
	}{
		{
			name: "absolute_form_with_query", target: "http://api.openai.com/v1/chat/completions?foo=bar",
			requestBody: genAIHTTP1OpenAIRequest, responseBody: genAIHTTP1OpenAIResponse,
			wantPath: "http://api.openai.com/v1/chat/completions", wantOperation: request.ChatOperationName, wantSubtype: request.HTTPSubtypeOpenAI,
		},
		{
			name: "embeddings", target: "/v1/embeddings",
			requestBody:  `{"model":"text-embedding-3-small","input":"hi"}`,
			responseBody: `{"object":"list","model":"text-embedding-3-small","data":[{"object":"embedding","index":0,"embedding":[0.1]}]}`,
			wantPath:     "/v1/embeddings", wantOperation: request.EmbeddingOperationName, wantSubtype: request.HTTPSubtypeOpenAI,
		},
		{
			name: "DashScope_embeddings_left_for_Qwen", target: "/v1/embeddings",
			requestBody:  `{"model":"text-embedding-v3","input":["hi"]}`,
			responseBody: `{"object":"list","model":"text-embedding-v3","data":[]}`,
			wantPath:     "/v1/embeddings", wantSubtype: request.HTTPSubtypeNone,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, resp := newGenAIHTTP1Exchange(t, tc.target, tc.requestBody, tc.responseBody)

			span := httpRequestResponseToSpan(newGenAIHTTP1ParseContext(), &BPFHTTPInfo{Type: uint8(request.EventTypeHTTPClient)}, req, resp)

			assert.Equal(t, tc.wantSubtype, span.SubType)
			assert.Equal(t, tc.wantPath, span.Path)
			assert.Equal(t, tc.target, span.FullPath)
			if tc.wantSubtype == request.HTTPSubtypeNone {
				assert.Nil(t, span.GenAI)
				return
			}
			require.NotNil(t, span.GenAI)
			require.NotNil(t, span.GenAI.OpenAI)
			assert.Equal(t, tc.wantOperation, span.GenAI.OpenAI.OperationName)
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

// With JSON-RPC enabled, TryParseJSONRPC consumes a request body that fails to
// read without restoring it, so the fallback no longer sees the body. This pins
// that existing TryParseJSONRPC limitation.
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

func TestPostProcessHTTPSpanGenAIHTTP1AnthropicBodyPreservation(t *testing.T) {
	parseCtx := newGenAIHTTP1ParseContext()
	parseCtx.payloadExtraction.HTTP.GenAI.Anthropic.Enabled = true
	requestBody, responseBody := `{"to":"+15550100","text":"hi"}`, `{"type":"message","id":"m1","status":"queued"}`
	req, resp := newGenAIHTTP1Exchange(t, "/v1/messages", requestBody, responseBody)
	event := &BPFHTTPInfo{Type: uint8(request.EventTypeHTTPClient)}

	span := httpRequestResponseToSpan(parseCtx, event, req, resp)

	assert.Equal(t, request.HTTPSubtypeNone, span.SubType)
	assert.Nil(t, span.GenAI)
	assert.Equal(t, requestBody, span.RequestBodyContent, "request body after rejected fallback")
	assert.Equal(t, responseBody, span.ResponseBodyContent, "response body after rejected fallback")
}
