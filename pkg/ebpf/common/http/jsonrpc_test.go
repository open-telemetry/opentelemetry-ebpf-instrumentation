// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func newJSONRPCRequest(t *testing.T, contentType, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/rpc", bytes.NewBufferString(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req
}

func newJSONRPCResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}

func TestJSONRPCSpan_DetectionViaBody(t *testing.T) {
	reqBody := `{"jsonrpc":"2.0","method":"tools/call","id":1}`
	respBody := `{"jsonrpc":"2.0","result":{"ok":true},"id":1}`

	span := request.Span{}
	req := newJSONRPCRequest(t, "application/json", reqBody)
	resp := newJSONRPCResponse(respBody)

	result, ok := JSONRPCSpan(&span, req, resp)
	require.True(t, ok)
	assert.Equal(t, request.HTTPSubtypeJSONRPC, result.SubType)
	require.NotNil(t, result.JSONRPC)
	assert.Equal(t, "tools/call", result.JSONRPC.Method)
	assert.Equal(t, "2.0", result.JSONRPC.Version)
	assert.Equal(t, "1", result.JSONRPC.RequestID)
	assert.Equal(t, 0, result.JSONRPC.ErrorCode)
	assert.Empty(t, result.JSONRPC.ErrorMessage)
}

func TestJSONRPCSpan_DetectionViaHeader(t *testing.T) {
	// Body has jsonrpc field but we also check that header-only detection works
	// when Content-Type is application/json-rpc
	reqBody := `{"jsonrpc":"2.0","method":"initialize","id":"req-1"}`
	respBody := `{"jsonrpc":"2.0","result":{},"id":"req-1"}`

	span := request.Span{}
	req := newJSONRPCRequest(t, "application/json-rpc", reqBody)
	resp := newJSONRPCResponse(respBody)

	result, ok := JSONRPCSpan(&span, req, resp)
	require.True(t, ok)
	assert.Equal(t, request.HTTPSubtypeJSONRPC, result.SubType)
	assert.Equal(t, "initialize", result.JSONRPC.Method)
	assert.Equal(t, "req-1", result.JSONRPC.RequestID)
}

func TestJSONRPCSpan_DetectionViaHeaderCaseInsensitive(t *testing.T) {
	// Media types are case-insensitive and may include parameters.
	// Body omits jsonrpc field — only header detection should succeed.
	reqBody := `{"method":"test","id":1}`

	cases := []string{
		"Application/JSON-RPC",
		"application/json-rpc; charset=utf-8",
		"APPLICATION/JSON-RPC; charset=UTF-8",
	}
	for _, ct := range cases {
		t.Run(ct, func(t *testing.T) {
			span := request.Span{}
			result, ok := JSONRPCSpan(&span, newJSONRPCRequest(t, ct, reqBody), newJSONRPCResponse(""))
			require.True(t, ok)
			assert.Equal(t, "test", result.JSONRPC.Method)
			assert.Equal(t, "2.0", result.JSONRPC.Version)
		})
	}
}

func TestJSONRPCSpan_StringID(t *testing.T) {
	reqBody := `{"jsonrpc":"2.0","method":"resources/read","id":"abc-123"}`
	respBody := `{"jsonrpc":"2.0","result":{},"id":"abc-123"}`

	span := request.Span{}
	result, ok := JSONRPCSpan(&span, newJSONRPCRequest(t, "", reqBody), newJSONRPCResponse(respBody))
	require.True(t, ok)
	assert.Equal(t, "abc-123", result.JSONRPC.RequestID)
}

func TestJSONRPCSpan_Notification(t *testing.T) {
	// Notifications have no "id" field
	reqBody := `{"jsonrpc":"2.0","method":"notifications/cancelled"}`

	span := request.Span{}
	result, ok := JSONRPCSpan(&span, newJSONRPCRequest(t, "", reqBody), newJSONRPCResponse(""))
	require.True(t, ok)
	assert.Equal(t, "notifications/cancelled", result.JSONRPC.Method)
	assert.Empty(t, result.JSONRPC.RequestID)
}

func TestJSONRPCSpan_NullID(t *testing.T) {
	reqBody := `{"jsonrpc":"2.0","method":"test","id":null}`

	span := request.Span{}
	result, ok := JSONRPCSpan(&span, newJSONRPCRequest(t, "", reqBody), newJSONRPCResponse(""))
	require.True(t, ok)
	assert.Empty(t, result.JSONRPC.RequestID)
}

func TestJSONRPCSpan_BatchRequest(t *testing.T) {
	reqBody := `[
		{"jsonrpc":"2.0","method":"tools/list","id":1},
		{"jsonrpc":"2.0","method":"tools/call","id":2},
		{"jsonrpc":"2.0","method":"resources/read","id":3}
	]`
	respBody := `[
		{"jsonrpc":"2.0","result":{},"id":1},
		{"jsonrpc":"2.0","result":{},"id":2},
		{"jsonrpc":"2.0","result":{},"id":3}
	]`

	span := request.Span{}
	result, ok := JSONRPCSpan(&span, newJSONRPCRequest(t, "", reqBody), newJSONRPCResponse(respBody))
	require.True(t, ok)
	assert.Equal(t, "tools/list", result.JSONRPC.Method) // first item in batch
	assert.Equal(t, "1", result.JSONRPC.RequestID)
}

func TestJSONRPCSpan_BatchErrorResponse(t *testing.T) {
	reqBody := `[
		{"jsonrpc":"2.0","method":"tools/list","id":1},
		{"jsonrpc":"2.0","method":"tools/call","id":2}
	]`
	respBody := `[
		{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":1},
		{"jsonrpc":"2.0","result":{},"id":2}
	]`

	span := request.Span{}
	result, ok := JSONRPCSpan(&span, newJSONRPCRequest(t, "", reqBody), newJSONRPCResponse(respBody))
	require.True(t, ok)
	assert.Equal(t, "tools/list", result.JSONRPC.Method)
	assert.Equal(t, -32601, result.JSONRPC.ErrorCode)
	assert.Equal(t, "Method not found", result.JSONRPC.ErrorMessage)
}

func TestJSONRPCSpan_ErrorResponse(t *testing.T) {
	reqBody := `{"jsonrpc":"2.0","method":"tools/call","id":1}`
	respBody := `{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":1}`

	span := request.Span{}
	result, ok := JSONRPCSpan(&span, newJSONRPCRequest(t, "", reqBody), newJSONRPCResponse(respBody))
	require.True(t, ok)
	assert.Equal(t, -32601, result.JSONRPC.ErrorCode)
	assert.Equal(t, "Method not found", result.JSONRPC.ErrorMessage)
}

func TestJSONRPCSpan_ParseError(t *testing.T) {
	reqBody := `{"jsonrpc":"2.0","method":"test","id":1}`
	respBody := `{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}`

	span := request.Span{}
	result, ok := JSONRPCSpan(&span, newJSONRPCRequest(t, "", reqBody), newJSONRPCResponse(respBody))
	require.True(t, ok)
	assert.Equal(t, -32700, result.JSONRPC.ErrorCode)
	assert.Equal(t, "Parse error", result.JSONRPC.ErrorMessage)
}

func TestJSONRPCSpan_NotJSONRPC(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"plain JSON", `{"foo":"bar"}`},
		{"missing version", `{"method":"test","id":1}`},
		{"wrong version", `{"jsonrpc":"1.0","method":"test","id":1}`},
		{"missing method", `{"jsonrpc":"2.0","id":1}`},
		{"empty body", ""},
		{"malformed JSON", `{`},
		{"plain text", "hello world"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span := request.Span{}
			_, ok := JSONRPCSpan(&span, newJSONRPCRequest(t, "", tt.body), newJSONRPCResponse(""))
			assert.False(t, ok)
		})
	}
}

func TestJSONRPCSpan_NotPost(t *testing.T) {
	span := request.Span{}
	req := httptest.NewRequest(http.MethodGet, "/rpc", nil)
	resp := newJSONRPCResponse("")

	_, ok := JSONRPCSpan(&span, req, resp)
	assert.False(t, ok)
}

func TestJSONRPCSpan_HeaderDetectionWithMissingVersion(t *testing.T) {
	// When Content-Type is application/json-rpc and jsonrpc field is missing,
	// we should still detect and default version to "2.0"
	reqBody := `{"method":"test","id":1}`

	span := request.Span{}
	result, ok := JSONRPCSpan(&span, newJSONRPCRequest(t, "application/json-rpc", reqBody), newJSONRPCResponse(""))
	require.True(t, ok)
	assert.Equal(t, "test", result.JSONRPC.Method)
	assert.Equal(t, "2.0", result.JSONRPC.Version)
}

func TestJSONRPCSpan_RejectsNon2_0Version(t *testing.T) {
	// Explicit non-2.0 version should be rejected even with header detection
	reqBody := `{"jsonrpc":"1.0","method":"test","id":1}`

	span := request.Span{}
	_, ok := JSONRPCSpan(&span, newJSONRPCRequest(t, "application/json-rpc", reqBody), newJSONRPCResponse(""))
	assert.False(t, ok)
}

func TestJSONRPCSpan_EmptyBatch(t *testing.T) {
	span := request.Span{}
	_, ok := JSONRPCSpan(&span, newJSONRPCRequest(t, "", "[]"), newJSONRPCResponse(""))
	assert.False(t, ok)
}

func TestJSONRPCSpan_BodyRestoredAfterRead(t *testing.T) {
	reqBody := `{"jsonrpc":"2.0","method":"test","id":1}`
	respBody := `{"jsonrpc":"2.0","result":{},"id":1}`

	span := request.Span{}
	req := newJSONRPCRequest(t, "", reqBody)
	resp := newJSONRPCResponse(respBody)

	_, _ = JSONRPCSpan(&span, req, resp)

	// Verify request body can still be read
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, reqBody, string(body))

	// Verify response body can still be read
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, respBody, string(body))
}
