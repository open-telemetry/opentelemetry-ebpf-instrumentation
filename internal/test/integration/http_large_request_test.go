// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

type httpRequestSize struct {
	size           int
	tpHeaderOffset int
}

const traceBufSize = 1024 // This is identical to TRACE_BUF_SIZE defined in `bpf/common/http_buf_size.h`

// This test will make sure that if a request belonging to an egress flow is slightly bigger than 1KB,
// tpinjector.c:obi_packet_extender_find_existing_tp() will still parse the traceparent.
func testLargeHTTPRequestEgress(t *testing.T) {
	traceID := createTraceID()
	parentID := createParentID()
	traceparent := createTraceparent(traceID, parentID)

	host := "localhost:3030"
	path := "/greeting"
	method := "GET"
	headers := []string{
		"Accept: */*",
		"User-Agent: user_agent",
		"Traceparent: " + traceparent,
	}
	reqSize := getHTTPRequestSize(t, host, method, path, headers...)

	// In previous versions of OBI, obi_packet_extender_find_existing_tp() will only see:
	// > GET /greeting HTTP/1.1\r\nHost: localhost:3030\r\nAccept: */*\r\nUser-Agent: user_agent\r\n
	// which would make it unable to find the header traceparent.
	// (Ref for the old bug: https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/57e7cd462e0300e0acdd3cf76b146e4cd80e225f/bpf/tpinjector/tpinjector.c#L861)
	headers = append(headers, generatePadHeader(t, reqSize, 0))

	rawReq := createRawHTTPRequest(t, method, path, host, headers...)
	dialReq := map[string]string{"rawRequest": rawReq, "host": host}

	bytes, err := json.Marshal(dialReq)
	require.NoError(t, err)
	doHTTPPost(t, "http://localhost:3035/dial", 200, bytes)

	assertRequestTraceID(t, method, path, traceID)
}

// This test will make sure that if a request belonging to an ingress flow is slightly bigger than 1KB,
// bpf/generictracer/protocol_http.h:__obi_continue_protocol_http_tp() will still be able to find and
// parse the traceparent.
func testLargeHTTPRequestIngress(t *testing.T) {
	traceID := createTraceID()
	parentID := createParentID()
	traceparent := createTraceparent(traceID, parentID)

	host := "localhost:3035"
	path := "/bye"
	method := "GET"
	headers := []string{
		"Accept: */*",
		"User-Agent: user_agent",
		"Traceparent: " + traceparent,
	}
	reqSize := getHTTPRequestSize(t, host, method, path, headers...)

	// In previous versions of __obi_continue_protocol_http_tp() where the bitwise operation is used
	// `const u16 buf_len = args->bytes_len & (TRACE_BUF_SIZE - 1);`, the function will only be able to see:
	// > GET /bye HTTP/1.1\r\nHost: localhost:3030\r\nAccept: */*\r\nUser-Agent: user_agent\r\nTraceparent:
	// which will result in an empty trace id (ex: 00-ffffffffffffffffffffffffffffffff-0701cb90f152dc2e-01).
	// (Ref for the old bug: https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/57e7cd462e0300e0acdd3cf76b146e4cd80e225f/bpf/generictracer/protocol_http.h#L475)
	headers = append(headers, generatePadHeader(t, reqSize, len("Traceparent: ")))

	rawReq := createRawHTTPRequest(t, method, path, host, headers...)
	sendRawHTTPRequest(t, host, rawReq, 200)

	assertRequestTraceID(t, method, path, traceID)
}

// Send a large HTTP request with arbitrary size as egress
func testLargeHTTPRequestEgressArbitrarySize(t *testing.T) {
	traceID := createTraceID()
	parentID := createParentID()
	traceparent := createTraceparent(traceID, parentID)

	host := "localhost:3030"
	path := "/arbitrary1"
	method := "GET"
	headers := []string{
		"Accept: */*",
		"User-Agent: user_agent",
		"Traceparent: " + traceparent,
	}
	reqSize := getHTTPRequestSize(t, host, method, path, headers...)
	headers = append(headers, generatePadHeader(t, reqSize, rand.IntN(4096)))

	rawReq := createRawHTTPRequest(t, method, path, host, headers...)
	dialReq := map[string]string{"rawRequest": rawReq, "host": host}

	bytes, err := json.Marshal(dialReq)
	require.NoError(t, err)
	doHTTPPost(t, "http://localhost:3035/dial", 200, bytes)

	assertRequestTraceID(t, method, path, traceID)
}

// Send a large HTTP request with arbitrary size as ingress
func testLargeHTTPRequestIngressArbitrarySize(t *testing.T) {
	traceID := createTraceID()
	parentID := createParentID()
	traceparent := createTraceparent(traceID, parentID)

	host := "localhost:3035"
	path := "/arbitrary2"
	method := "GET"
	headers := []string{
		"Accept: */*",
		"User-Agent: user_agent",
		"Traceparent: " + traceparent,
	}
	reqSize := getHTTPRequestSize(t, host, method, path, headers...)
	headers = append(headers, generatePadHeader(t, reqSize, rand.IntN(4096)))

	rawReq := createRawHTTPRequest(t, method, path, host, headers...)
	sendRawHTTPRequest(t, host, rawReq, 200)

	assertRequestTraceID(t, method, path, traceID)
}

func createRawHTTPRequest(t *testing.T, method, path, host string, headers ...string) string {
	t.Helper()

	var rawReq strings.Builder

	fmt.Fprintf(&rawReq, "%s %s HTTP/1.1\r\n", strings.ToUpper(method), path)
	fmt.Fprintf(&rawReq, "Host: %s\r\n", host)

	for _, header := range headers {
		fmt.Fprintf(&rawReq, "%s\r\n", header)
	}

	rawReq.WriteString("\r\n")

	return rawReq.String()
}

func getHTTPRequestSize(t *testing.T, host, method, path string, headers ...string) httpRequestSize { //nolint:unparam // the linter complains about "method" being always "GET"
	t.Helper()

	rawReq := createRawHTTPRequest(t, host, method, path, headers...)
	reqSize := len(rawReq)
	tpHeaderOffset := strings.Index(strings.ToLower(rawReq), "traceparent")

	return httpRequestSize{
		size:           reqSize,
		tpHeaderOffset: tpHeaderOffset,
	}
}

func generatePadHeader(t *testing.T, reqSize httpRequestSize, tpHeaderSizeToTake int) string {
	t.Helper()

	padHeader := "pad: "

	// Calculate how much bytes left to reach exactly 1KB
	sizeToReach1KB := traceBufSize - (reqSize.size + len(padHeader) + len("\r\n"))
	padSize := sizeToReach1KB + reqSize.tpHeaderOffset + tpHeaderSizeToTake

	var value strings.Builder
	for range padSize {
		value.WriteString("A")
	}

	return fmt.Sprintf("%s%s", padHeader, value.String())
}

func sendRawHTTPRequest(t *testing.T, host, rawReq string, expectedStatus int) {
	t.Helper()

	conn, err := net.Dial("tcp", host)
	require.NoError(t, err)
	defer conn.Close()

	fmt.Fprint(conn, rawReq)
	currentStatus, err := bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, currentStatus, strconv.Itoa(expectedStatus))
}

func assertRequestTraceID(t *testing.T, method, path, traceID string) { //nolint:unparam // the linter complains about "method" being always "GET"
	t.Helper()

	var trace jaeger.Trace

	operationName := fmt.Sprintf("%s %s", strings.ToUpper(method), path)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=httpproxyserver&operation=" + url.QueryEscape(operationName))
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: path})
		require.Len(ct, traces, 1)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	// Check the information of the parent span
	res := trace.FindByOperationName(operationName, "server")
	require.Len(t, res, 1)
	parent := res[0]
	require.NotEmpty(t, parent.TraceID)
	require.Equal(t, traceID, parent.TraceID)
}
