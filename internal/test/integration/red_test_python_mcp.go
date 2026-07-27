// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

// mcpCall sends a JSON-RPC 2.0 MCP request over HTTP and returns the response.
// Optional headers are applied as key-value pairs to the outgoing request.
func mcpCall(url, method string, id int, params any, headers ...string) (*http.Response, error) {
	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"id":      id,
	}
	if params != nil {
		reqBody["params"] = params
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body)) //nolint:noctx
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	return http.DefaultClient.Do(req)
}

// mcpNotify sends a JSON-RPC 2.0 notification (no id, no response expected).
func mcpNotify(url, method string, params any, headers ...string) error {
	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
	}
	if params != nil {
		reqBody["params"] = params
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body)) //nolint:noctx
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// mcpInitSession performs the MCP initialization handshake and returns the
// session ID assigned by the server. It retries until the server is ready.
func mcpInitSession(t *testing.T, address string) string {
	t.Helper()
	var sessionID string
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := mcpCall(address, "initialize", 0, map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "TestClient", "version": "1.0"},
		})
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		sessionID = resp.Header.Get("Mcp-Session-Id")
		require.NotEmpty(ct, sessionID, "server must return Mcp-Session-Id header")
		resp.Body.Close()
	}, testTimeout, 100*time.Millisecond)

	// Complete the initialization handshake.
	require.NoError(t, mcpNotify(address, "notifications/initialized", nil,
		"Mcp-Session-Id", sessionID))

	return sessionID
}

func testPythonMCPServer(t *testing.T) {
	const (
		comm    = "python3.14"
		address = "http://localhost:8381/mcp"
	)

	// Establish a real MCP session via the SDK initialization handshake.
	sessionID := mcpInitSession(t, address)

	var tq jaeger.TracesQuery
	params := neturl.Values{}
	params.Add("service", comm)
	fullJaegerURL := fmt.Sprintf("%s?%s", jaegerQueryURL, params.Encode())

	// Test 1: tools/call with a known tool — verify MCP span attributes.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := mcpCall(address, "tools/call", 1, map[string]any{"name": "get-weather"},
			"Mcp-Session-Id", sessionID)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		resp, err = http.Get(fullJaegerURL) //nolint:noctx
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))

		// Find traces with MCP method attribute
		traces := tq.FindBySpan(jaeger.Tag{Key: "mcp.method.name", Type: "string", Value: "tools/call"})
		require.GreaterOrEqual(ct, len(traces), 1)

		lastTrace := traces[len(traces)-1]
		// The trace may contain child spans ("in queue", "processing");
		// locate the MCP server span by its expected operation name.
		res := lastTrace.FindByOperationName("execute_tool get-weather", "server")
		require.GreaterOrEqual(ct, len(res), 1)
		span := res[0]

		sd := span.Diff(
			jaeger.Tag{Key: "mcp.method.name", Type: "string", Value: "tools/call"},
			jaeger.Tag{Key: "gen_ai.operation.name", Type: "string", Value: "execute_tool"},
			jaeger.Tag{Key: "gen_ai.tool.name", Type: "string", Value: "get-weather"},
			jaeger.Tag{Key: "jsonrpc.request.id", Type: "string", Value: "1"},
		)
		assert.Empty(ct, sd, sd.String())

		// Session ID is dynamically assigned; verify it is present.
		sd = span.DiffAsRegexp(
			jaeger.Tag{Key: "mcp.session.id", Type: "string", Value: ".+"},
		)
		assert.Empty(ct, sd, sd.String())
	}, testTimeout, 100*time.Millisecond)

	// Test 2: tools/call with an unknown tool — verify the span is still
	// created with correct request-side MCP attributes.  The real MCP SDK
	// returns errors via SSE (text/event-stream), so OBI's eBPF layer
	// cannot extract the JSON-RPC error from the streamed response body;
	// response-side attributes like otel.status_code are therefore not
	// asserted here.
	var tqErr jaeger.TracesQuery
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := mcpCall(address, "tools/call", 2, map[string]any{"name": "nonexistent"},
			"Mcp-Session-Id", sessionID)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		resp, err = http.Get(fullJaegerURL) //nolint:noctx
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tqErr))

		// Find traces with the error tool call
		traces := tqErr.FindBySpan(
			jaeger.Tag{Key: "mcp.method.name", Type: "string", Value: "tools/call"},
			jaeger.Tag{Key: "gen_ai.tool.name", Type: "string", Value: "nonexistent"},
		)
		require.GreaterOrEqual(ct, len(traces), 1)

		lastTrace := traces[len(traces)-1]
		res := lastTrace.FindByOperationName("execute_tool nonexistent", "server")
		require.GreaterOrEqual(ct, len(res), 1)
		span := res[0]

		sd := span.Diff(
			jaeger.Tag{Key: "mcp.method.name", Type: "string", Value: "tools/call"},
			jaeger.Tag{Key: "gen_ai.operation.name", Type: "string", Value: "execute_tool"},
			jaeger.Tag{Key: "gen_ai.tool.name", Type: "string", Value: "nonexistent"},
			jaeger.Tag{Key: "jsonrpc.request.id", Type: "string", Value: "2"},
		)
		assert.Empty(ct, sd, sd.String())
	}, testTimeout, 100*time.Millisecond)
}

func testPythonMCPInitialize(t *testing.T) {
	const (
		comm    = "python3.14"
		address = "http://localhost:8381/mcp"
	)

	var tq jaeger.TracesQuery
	params := neturl.Values{}
	params.Add("service", comm)
	fullJaegerURL := fmt.Sprintf("%s?%s", jaegerQueryURL, params.Encode())

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := mcpCall(address, "initialize", 10, map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "TestClient", "version": "1.0"},
		})
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		resp, err = http.Get(fullJaegerURL) //nolint:noctx
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))

		traces := tq.FindBySpan(jaeger.Tag{Key: "mcp.method.name", Type: "string", Value: "initialize"})
		require.GreaterOrEqual(ct, len(traces), 1)

		lastTrace := traces[len(traces)-1]
		res := lastTrace.FindByOperationName("initialize", "server")
		require.GreaterOrEqual(ct, len(res), 1)
		span := res[0]

		sd := span.Diff(
			jaeger.Tag{Key: "mcp.method.name", Type: "string", Value: "initialize"},
			jaeger.Tag{Key: "gen_ai.operation.name", Type: "string", Value: "initialize"},
			jaeger.Tag{Key: "mcp.protocol.version", Type: "string", Value: "2025-03-26"},
			jaeger.Tag{Key: "jsonrpc.request.id", Type: "string", Value: "10"},
		)
		assert.Empty(ct, sd, sd.String())
	}, testTimeout, 100*time.Millisecond)
}
