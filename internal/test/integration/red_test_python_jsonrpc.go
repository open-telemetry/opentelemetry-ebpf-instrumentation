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
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

// jsonRPCCall sends a JSON-RPC 2.0 request over HTTP and returns the response.
func jsonRPCCall(url, method string, id int, params any) (*http.Response, error) {
	req := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"id":      id,
	}
	if params != nil {
		req["params"] = params
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return http.Post(url, "application/json", bytes.NewReader(body)) //nolint:noctx
}

func testPythonJSONRPCServer(t *testing.T) {
	const (
		comm    = "python3.14"
		address = "http://localhost:8381/rpc"
	)

	var tq jaeger.TracesQuery
	params := neturl.Values{}
	params.Add("service", comm)
	fullJaegerURL := fmt.Sprintf("%s?%s", jaegerQueryURL, params.Encode())

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := jsonRPCCall(address, "tools/list", 1, nil)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		resp, err = http.Get(fullJaegerURL) //nolint:noctx
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))

		// Find traces with JSON-RPC system attribute
		traces := tq.FindBySpan(jaeger.Tag{Key: "rpc.system", Type: "string", Value: "jsonrpc"})
		require.GreaterOrEqual(ct, len(traces), 1)

		lastTrace := traces[len(traces)-1]
		// The trace may contain child spans ("in queue", "processing");
		// locate the JSON-RPC server span by its expected operation name.
		res := lastTrace.FindByOperationName("tools/list", "server")
		require.GreaterOrEqual(ct, len(res), 1)
		span := res[0]

		tag, found := jaeger.FindIn(span.Tags, "rpc.method")
		assert.True(ct, found, "rpc.method tag not found")
		assert.Equal(ct, "tools/list", tag.Value)

		tag, found = jaeger.FindIn(span.Tags, "jsonrpc.protocol.version")
		assert.True(ct, found, "jsonrpc.protocol.version tag not found")
		assert.Equal(ct, "2.0", tag.Value)

		tag, found = jaeger.FindIn(span.Tags, "jsonrpc.request.id")
		assert.True(ct, found, "jsonrpc.request.id tag not found")
		assert.Equal(ct, "1", tag.Value)
	}, testTimeout, 100*time.Millisecond)

	// Test JSON-RPC error span: call a non-existent method to trigger a -32601 error
	var tqErr jaeger.TracesQuery
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := jsonRPCCall(address, "nonexistent/method", 99, nil)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		resp, err = http.Get(fullJaegerURL) //nolint:noctx
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tqErr))

		// Find traces with the error method
		traces := tqErr.FindBySpan(
			jaeger.Tag{Key: "rpc.system", Type: "string", Value: "jsonrpc"},
			jaeger.Tag{Key: "rpc.method", Type: "string", Value: "nonexistent/method"},
		)
		require.GreaterOrEqual(ct, len(traces), 1)

		lastTrace := traces[len(traces)-1]
		res := lastTrace.FindByOperationName("nonexistent/method", "server")
		require.GreaterOrEqual(ct, len(res), 1)
		span := res[0]

		// Span status should be error
		tag, found := jaeger.FindIn(span.Tags, "otel.status_code")
		assert.True(ct, found, "otel.status_code tag not found")
		assert.Equal(ct, "ERROR", tag.Value)

		// Error message should be present
		tag, found = jaeger.FindIn(span.Tags, "otel.status_description")
		assert.True(ct, found, "otel.status_description tag not found")
		assert.NotEmpty(ct, tag.Value)

		// rpc.response.status_code should contain the JSON-RPC error code
		tag, found = jaeger.FindIn(span.Tags, "rpc.response.status_code")
		assert.True(ct, found, "rpc.response.status_code tag not found")
		assert.Equal(ct, "-32601", tag.Value)
	}, testTimeout, 100*time.Millisecond)
}

func testPythonJSONRPCMetrics(t *testing.T) {
	const address = "http://localhost:8381/rpc"

	// Send a few requests so Prometheus can scrape metrics
	for range 4 {
		_, _ = jsonRPCCall(address, "tools/list", 1, nil)
	}

	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		results, err = pq.Query(`rpc_server_duration_seconds_count{` +
			`rpc_method="tools/list",` +
			`rpc_system="jsonrpc",` +
			`service_namespace="integration-test"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		val := totalPromCount(ct, results)
		assert.LessOrEqual(ct, 3, val)
	}, testTimeout, 100*time.Millisecond)
}
