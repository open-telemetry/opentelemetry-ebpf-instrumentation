// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bufio"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// BenchmarkPostProcessHTTPSpanPlainHTTP1 measures a plain HTTP/1.1 client
// exchange that no payload detector claims, with every GenAI provider enabled.
func BenchmarkPostProcessHTTPSpanPlainHTTP1(b *testing.B) {
	parseCtx := &EBPFParseContext{}
	genAI := &parseCtx.payloadExtraction.HTTP.GenAI
	genAI.OpenAI.Enabled = true
	genAI.Anthropic.Enabled = true
	genAI.Gemini.Enabled = true
	genAI.Qwen.Enabled = true
	genAI.Bedrock.Enabled = true
	genAI.Embedding.Enabled = true
	genAI.Rerank.Enabled = true
	genAI.Retrieval.Enabled = true
	genAI.Ollama.Enabled = true
	genAI.Cohere.Enabled = true

	const requestBody = `{"name":"alice"}`
	raw := "POST /api/users HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(requestBody)) + "\r\n\r\n" + requestBody
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	require.NoError(b, err)
	resp := &http.Response{
		StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(strings.NewReader(`{"id":1,"name":"alice"}`)),
	}
	base := request.Span{Type: request.EventTypeHTTPClient, Method: http.MethodPost, Path: "/api/users"}

	b.ReportAllocs()

	var span request.Span
	for b.Loop() {
		httpSpan := base
		span = postProcessHTTPSpan(parseCtx, &httpSpan, req, resp)
	}

	require.Equal(b, request.HTTPSubtypeNone, span.SubType)
	require.Nil(b, span.GenAI)
}
