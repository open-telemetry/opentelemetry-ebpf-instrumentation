// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func makeMCPRequest(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	return req
}

const mcpToolCallRequest = `{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "get-weather",
    "arguments": {"location": "San Francisco"}
  },
  "id": 1
}`

const mcpToolCallResponse = `{
  "jsonrpc": "2.0",
  "result": {
    "content": [{"type": "text", "text": "Sunny, 72°F"}]
  },
  "id": 1
}`

const mcpToolCallErrorResponse = `{
  "jsonrpc": "2.0",
  "error": {
    "code": -32602,
    "message": "Unknown tool: nonexistent"
  },
  "id": 2
}`

const mcpResourceReadRequest = `{
  "jsonrpc": "2.0",
  "method": "resources/read",
  "params": {
    "uri": "file:///home/user/documents/report.pdf"
  },
  "id": 3
}`

const mcpResourceReadResponse = `{
  "jsonrpc": "2.0",
  "result": {
    "contents": [{"uri": "file:///home/user/documents/report.pdf", "mimeType": "application/pdf", "text": "..."}]
  },
  "id": 3
}`

const mcpPromptGetRequest = `{
  "jsonrpc": "2.0",
  "method": "prompts/get",
  "params": {
    "name": "analyze-code"
  },
  "id": 4
}`

const mcpPromptGetResponse = `{
  "jsonrpc": "2.0",
  "result": {
    "description": "Analyzes code for potential issues",
    "messages": [{"role": "user", "content": {"type": "text", "text": "Analyze this code"}}]
  },
  "id": 4
}`

const mcpInitializeRequest = `{
  "jsonrpc": "2.0",
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-03-26",
    "capabilities": {},
    "clientInfo": {"name": "TestClient", "version": "1.0"}
  },
  "id": 5
}`

const mcpInitializeResponse = `{
  "jsonrpc": "2.0",
  "result": {
    "protocolVersion": "2025-03-26",
    "capabilities": {"tools": {}},
    "serverInfo": {"name": "TestServer", "version": "1.0"}
  },
  "id": 5
}`

const mcpToolsListRequest = `{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "params": {},
  "id": 6
}`

const mcpToolsListResponse = `{
  "jsonrpc": "2.0",
  "result": {
    "tools": [{"name": "get-weather", "description": "Get weather info"}]
  },
  "id": 6
}`

const mcpPingRequest = `{
  "jsonrpc": "2.0",
  "method": "ping",
  "id": 7
}`

const mcpPingResponse = `{
  "jsonrpc": "2.0",
  "result": {},
  "id": 7
}`

func mcpHeaders() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	return h
}

func TestMCPSpan_ToolCall(t *testing.T) {
	req := makeMCPRequest(t, http.MethodPost, "http://localhost:8080/mcp", mcpToolCallRequest)
	req.Header.Set("Mcp-Session-Id", "sess-abc-123")
	resp := makePlainResponse(http.StatusOK, mcpHeaders(), mcpToolCallResponse)

	base := &request.Span{}
	span, ok := MCPSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.MCP)

	mcp := span.GenAI.MCP
	assert.Equal(t, request.HTTPSubtypeMCP, span.SubType)
	assert.Equal(t, "tools/call", mcp.Method)
	assert.Equal(t, "get-weather", mcp.ToolName)
	assert.Equal(t, "sess-abc-123", mcp.SessionID)
	assert.Equal(t, "1", mcp.RequestID)
	assert.Equal(t, 0, mcp.ErrorCode)
	assert.Empty(t, mcp.ErrorMessage)
	assert.Equal(t, "execute_tool", mcp.OperationName())
}

func TestMCPSpan_ToolCallError(t *testing.T) {
	req := makeMCPRequest(t, http.MethodPost, "http://localhost:8080/mcp", mcpToolCallRequest)
	req.Header.Set("Mcp-Session-Id", "sess-err-123")
	resp := makePlainResponse(http.StatusOK, mcpHeaders(), mcpToolCallErrorResponse)

	base := &request.Span{}
	span, ok := MCPSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.MCP)

	mcp := span.GenAI.MCP
	assert.Equal(t, "tools/call", mcp.Method)
	assert.Equal(t, "get-weather", mcp.ToolName)
	assert.Equal(t, -32602, mcp.ErrorCode)
	assert.Equal(t, "Unknown tool: nonexistent", mcp.ErrorMessage)
}

func TestMCPSpan_ResourceRead(t *testing.T) {
	req := makeMCPRequest(t, http.MethodPost, "http://localhost:8080/mcp", mcpResourceReadRequest)
	req.Header.Set("Mcp-Session-Id", "sess-xyz-456")
	resp := makePlainResponse(http.StatusOK, mcpHeaders(), mcpResourceReadResponse)

	base := &request.Span{}
	span, ok := MCPSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.MCP)

	mcp := span.GenAI.MCP
	assert.Equal(t, "resources/read", mcp.Method)
	assert.Equal(t, "file:///home/user/documents/report.pdf", mcp.ResourceURI)
	assert.Equal(t, "sess-xyz-456", mcp.SessionID)
	assert.Equal(t, "3", mcp.RequestID)
	assert.Equal(t, "resources/read", mcp.OperationName())
}

func TestMCPSpan_PromptGet(t *testing.T) {
	req := makeMCPRequest(t, http.MethodPost, "http://localhost:8080/mcp", mcpPromptGetRequest)
	req.Header.Set("Mcp-Session-Id", "sess-prompt-456")
	resp := makePlainResponse(http.StatusOK, mcpHeaders(), mcpPromptGetResponse)

	base := &request.Span{}
	span, ok := MCPSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.MCP)

	mcp := span.GenAI.MCP
	assert.Equal(t, "prompts/get", mcp.Method)
	assert.Equal(t, "analyze-code", mcp.PromptName)
	assert.Equal(t, "4", mcp.RequestID)
	assert.Equal(t, "prompts/get", mcp.OperationName())
}

func TestMCPSpan_Initialize(t *testing.T) {
	req := makeMCPRequest(t, http.MethodPost, "http://localhost:8080/mcp", mcpInitializeRequest)
	resp := makePlainResponse(http.StatusOK, mcpHeaders(), mcpInitializeResponse)

	base := &request.Span{}
	span, ok := MCPSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.MCP)

	mcp := span.GenAI.MCP
	assert.Equal(t, "initialize", mcp.Method)
	assert.Equal(t, "2025-03-26", mcp.ProtocolVer)
	assert.Equal(t, "5", mcp.RequestID)
	assert.Equal(t, "initialize", mcp.OperationName())
}

func TestMCPSpan_InitializeSessionIDFromResponseHeader(t *testing.T) {
	req := makeMCPRequest(t, http.MethodPost, "http://localhost:8080/mcp", mcpInitializeRequest)
	headers := mcpHeaders()
	headers.Set("Mcp-Session-Id", "sess-from-response")
	resp := makePlainResponse(http.StatusOK, headers, mcpInitializeResponse)

	base := &request.Span{}
	span, ok := MCPSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.MCP)

	mcp := span.GenAI.MCP
	assert.Equal(t, "initialize", mcp.Method)
	assert.Equal(t, "sess-from-response", mcp.SessionID)
	assert.Equal(t, "5", mcp.RequestID)
}

func TestMCPSpan_ToolsList(t *testing.T) {
	req := makeMCPRequest(t, http.MethodPost, "http://localhost:8080/mcp", mcpToolsListRequest)
	req.Header.Set("Mcp-Session-Id", "sess-tools-list")
	resp := makePlainResponse(http.StatusOK, mcpHeaders(), mcpToolsListResponse)

	base := &request.Span{}
	span, ok := MCPSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.MCP)

	mcp := span.GenAI.MCP
	assert.Equal(t, "tools/list", mcp.Method)
	assert.Equal(t, "sess-tools-list", mcp.SessionID)
	assert.Empty(t, mcp.ToolName)
}

func TestMCPSpan_Ping(t *testing.T) {
	req := makeMCPRequest(t, http.MethodPost, "http://localhost:8080/mcp", mcpPingRequest)
	req.Header.Set("Mcp-Session-Id", "sess-ping")
	resp := makePlainResponse(http.StatusOK, mcpHeaders(), mcpPingResponse)

	base := &request.Span{}
	span, ok := MCPSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.MCP)

	mcp := span.GenAI.MCP
	assert.Equal(t, "ping", mcp.Method)
	assert.Equal(t, "sess-ping", mcp.SessionID)
	assert.Equal(t, "7", mcp.RequestID)
}

func TestMCPSpan_NotMCP_UnknownMethod(t *testing.T) {
	body := `{"jsonrpc": "2.0", "method": "eth_getBalance", "params": ["0xabc", "latest"], "id": 1}`
	req := makeMCPRequest(t, http.MethodPost, "http://localhost:8545", body)
	resp := makePlainResponse(http.StatusOK, mcpHeaders(), `{"jsonrpc":"2.0","result":"0x1","id":1}`)

	base := &request.Span{}
	_, ok := MCPSpan(base, req, resp)

	assert.False(t, ok)
}

func TestMCPSpan_NotMCP_GetMethod(t *testing.T) {
	req := makeMCPRequest(t, http.MethodGet, "http://localhost:8080/mcp", "")
	resp := makePlainResponse(http.StatusOK, mcpHeaders(), "{}")

	base := &request.Span{}
	_, ok := MCPSpan(base, req, resp)

	assert.False(t, ok)
}

func TestMCPSpan_NotMCP_InvalidJSON(t *testing.T) {
	req := makeMCPRequest(t, http.MethodPost, "http://localhost:8080/mcp", "not json")
	resp := makePlainResponse(http.StatusOK, mcpHeaders(), "{}")

	base := &request.Span{}
	_, ok := MCPSpan(base, req, resp)

	assert.False(t, ok)
}

func TestMCPSpan_NotMCP_EmptyBody(t *testing.T) {
	req := makeMCPRequest(t, http.MethodPost, "http://localhost:8080/mcp", "")
	resp := makePlainResponse(http.StatusOK, mcpHeaders(), "{}")

	base := &request.Span{}
	_, ok := MCPSpan(base, req, resp)

	assert.False(t, ok)
}

func TestMCPSpan_NotMCP_NotJSONRPC2(t *testing.T) {
	// A valid JSON object with an MCP method but without jsonrpc: "2.0" should be rejected.
	body := `{"method": "tools/call", "params": {"name": "get-weather"}, "id": 1}`
	req := makeMCPRequest(t, http.MethodPost, "http://localhost:8080/mcp", body)
	resp := makePlainResponse(http.StatusOK, mcpHeaders(), "{}")

	base := &request.Span{}
	_, ok := MCPSpan(base, req, resp)

	assert.False(t, ok)
}

func TestMCPSpan_NotMCP_PingWithoutSession(t *testing.T) {
	// "ping" is a generic JSON-RPC method shared with other protocols.
	// Without the Mcp-Session-Id header it must not be classified as MCP.
	req := makeMCPRequest(t, http.MethodPost, "http://localhost:8080/mcp", mcpPingRequest)
	resp := makePlainResponse(http.StatusOK, mcpHeaders(), mcpPingResponse)

	base := &request.Span{}
	_, ok := MCPSpan(base, req, resp)

	assert.False(t, ok)
}

func TestMCPSpan_NotMCP_ToolsCallWithoutSession(t *testing.T) {
	// Known MCP methods like "tools/call" require the Mcp-Session-Id header
	// (or an ambiguousMethods disambiguator) to avoid misclassifying plain
	// JSON-RPC traffic.
	req := makeMCPRequest(t, http.MethodPost, "http://localhost:8080/mcp", mcpToolCallRequest)
	resp := makePlainResponse(http.StatusOK, mcpHeaders(), mcpToolCallResponse)

	base := &request.Span{}
	_, ok := MCPSpan(base, req, resp)

	assert.False(t, ok)
}

func TestMCPSpan_NotMCP_InitializeWithoutProtocolVersion(t *testing.T) {
	// "initialize" without protocolVersion in params and without session
	// header looks like a generic JSON-RPC initialize (e.g. LSP).
	body := `{"jsonrpc": "2.0", "method": "initialize", "params": {"capabilities": {}}, "id": 1}`
	req := makeMCPRequest(t, http.MethodPost, "http://localhost:8080/mcp", body)
	resp := makePlainResponse(http.StatusOK, mcpHeaders(), `{"jsonrpc":"2.0","result":{},"id":1}`)

	base := &request.Span{}
	_, ok := MCPSpan(base, req, resp)

	assert.False(t, ok)
}

func TestMCPSpan_UnknownMethodWithSessionHeader(t *testing.T) {
	// An unknown method should still be detected as MCP if the session header is present.
	body := `{"jsonrpc": "2.0", "method": "custom/extension", "params": {}, "id": 10}`
	req := makeMCPRequest(t, http.MethodPost, "http://localhost:8080/mcp", body)
	req.Header.Set("Mcp-Session-Id", "sess-custom")
	resp := makePlainResponse(http.StatusOK, mcpHeaders(), `{"jsonrpc":"2.0","result":{},"id":10}`)

	base := &request.Span{}
	span, ok := MCPSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.MCP)

	mcp := span.GenAI.MCP
	assert.Equal(t, "custom/extension", mcp.Method)
	assert.Equal(t, "sess-custom", mcp.SessionID)
	assert.Equal(t, "10", mcp.RequestID)
}

func TestMCPSpan_StringRequestID(t *testing.T) {
	body := `{"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": "req-abc-42"}`
	req := makeMCPRequest(t, http.MethodPost, "http://localhost:8080/mcp", body)
	req.Header.Set("Mcp-Session-Id", "sess-str-id")
	resp := makePlainResponse(http.StatusOK, mcpHeaders(), `{"jsonrpc":"2.0","result":{"tools":[]},"id":"req-abc-42"}`)

	base := &request.Span{}
	span, ok := MCPSpan(base, req, resp)

	require.True(t, ok)
	assert.Equal(t, "req-abc-42", span.GenAI.MCP.RequestID)
}

func TestMCPSpan_NoResponseBody(t *testing.T) {
	req := makeMCPRequest(t, http.MethodPost, "http://localhost:8080/mcp", mcpToolCallRequest)
	req.Header.Set("Mcp-Session-Id", "sess-no-resp")
	resp := makePlainResponse(http.StatusOK, mcpHeaders(), "")

	base := &request.Span{}
	span, ok := MCPSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.MCP)
	assert.Equal(t, "tools/call", span.GenAI.MCP.Method)
	assert.Equal(t, "get-weather", span.GenAI.MCP.ToolName)
	assert.Equal(t, 0, span.GenAI.MCP.ErrorCode)
}

func TestMCPCall_OperationName(t *testing.T) {
	tests := []struct {
		method string
		want   string
	}{
		{method: "tools/call", want: "execute_tool"},
		{method: "tools/list", want: "tools/list"},
		{method: "resources/read", want: "resources/read"},
		{method: "prompts/get", want: "prompts/get"},
		{method: "initialize", want: "initialize"},
		{method: "ping", want: "ping"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			mcp := &request.MCPCall{Method: tt.method}
			assert.Equal(t, tt.want, mcp.OperationName())
		})
	}
}

func TestIsGenAISubtype_MCP(t *testing.T) {
	assert.True(t, request.IsGenAISubtype(request.HTTPSubtypeMCP))
}
