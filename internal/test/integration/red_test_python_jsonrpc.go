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
		require.GreaterOrEqual(ct, len(lastTrace.Spans), 1)
		span := lastTrace.Spans[0]

		assert.Equal(ct, "tools/list", span.OperationName)

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
}
