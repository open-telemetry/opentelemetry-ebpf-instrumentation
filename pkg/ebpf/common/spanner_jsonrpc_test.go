// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
)

func jsonRPCExtractionConfig() config.EBPFTracer {
	return config.EBPFTracer{
		BufferSizes:               config.EBPFBufferSizes{HTTP: 1024},
		GoHTTPClientBufferTimeout: time.Hour,
		MaxTransactionTime:        2 * time.Hour,
		PayloadExtraction: config.PayloadExtraction{
			HTTP: config.HTTPConfig{JSONRPC: config.JSONRPCConfig{Enabled: true}},
		},
	}
}

func goNetRPCServerTrace(conn BpfConnectionInfoT, serviceMethod string) HTTPRequestTrace {
	trace := makeHTTPRequestTrace("POST", "/rpc", 200, 0, 0, 5)
	pattern := [96]uint8{}
	copy(pattern[:], tocstr(serviceMethod))
	trace.Pattern = pattern
	trace.IsJsonrpc = true
	trace.Conn = conn
	return trace
}

func appendJSONRPCExchange(t *testing.T, parseCtx *EBPFParseContext, conn BpfConnectionInfoT, reqBody string) {
	t.Helper()

	appendGoHTTPClientBuffer(t, parseCtx, conn, [16]uint8{}, packetTypeRequest, directionRecv,
		fmt.Sprintf("POST /rpc HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(reqBody), reqBody))

	respBody := `{"jsonrpc":"2.0","result":{},"id":1}`
	appendGoHTTPClientBuffer(t, parseCtx, conn, [16]uint8{}, packetTypeResponse, directionSend,
		fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(respBody), respBody))
}

// Go's net/rpc/jsonrpc puts `"jsonrpc":"2.0"` on the wire, so once payload
// extraction rewrites the span from the body nothing in it distinguishes a
// `Service.Method` header the uprobe read from an arbitrary dotted JSON-RPC
// method. The provenance has to survive enrichment for the span to stay
// qualified.
func TestHTTPRequestTraceToSpan_GoNetRPCSurvivesJSONRPCExtraction(t *testing.T) {
	cfg := jsonRPCExtractionConfig()
	parseCtx, _ := newGoHTTPClientTestParseContext(t, cfg, 1)

	conn := goHTTPClientTestConnection()
	appendJSONRPCExchange(t, parseCtx, conn, `{"jsonrpc":"2.0","method":"Arith.Traceme","id":1}`)

	trace := goNetRPCServerTrace(conn, "Arith.Traceme")
	span := HTTPRequestTraceToSpan(parseCtx, &trace)

	require.Equal(t, request.HTTPSubtypeJSONRPC, span.SubType)
	require.NotNil(t, span.JSONRPC)
	// Extraction ran: it is the body that supplied the request ID.
	assert.Equal(t, "1", span.JSONRPC.RequestID)
	assert.Equal(t, "Arith.Traceme", span.JSONRPC.Method)
	assert.Equal(t, "Arith/Traceme", span.JSONRPC.QualifiedMethod())
	assert.Equal(t, "Arith/Traceme", span.TraceName())
}

// The same extraction on a span the uprobe never marked must leave a dotted
// method whole.
func TestHTTPRequestTraceToSpan_PayloadOnlyJSONRPCStaysUnqualified(t *testing.T) {
	cfg := jsonRPCExtractionConfig()
	parseCtx, _ := newGoHTTPClientTestParseContext(t, cfg, 1)

	conn := goHTTPClientTestConnection()
	appendJSONRPCExchange(t, parseCtx, conn, `{"jsonrpc":"2.0","method":"inventory.lookup.v2","id":1}`)

	trace := makeHTTPRequestTrace("POST", "/rpc", 200, 0, 0, 5)
	trace.Conn = conn
	span := HTTPRequestTraceToSpan(parseCtx, &trace)

	require.Equal(t, request.HTTPSubtypeJSONRPC, span.SubType)
	require.NotNil(t, span.JSONRPC)
	assert.False(t, span.JSONRPC.ServiceQualified)
	assert.Equal(t, "inventory.lookup.v2", span.JSONRPC.QualifiedMethod())
	assert.Equal(t, "inventory.lookup.v2", span.TraceName())
}
