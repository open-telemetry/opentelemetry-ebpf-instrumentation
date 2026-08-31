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

func getHTTPRequestSize(t *testing.T, host, method, path string, headers ...string) httpRequestSize {
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

// k_msg_buffer_size_max in bpf/common/msg_buffer.h — the size of msg_buffer_mem,
// the per-CPU buffer the sk_msg program fills for the tcp_sendmsg kprobe.
const msgBufferSizeMax = 8192

// The uninstrumented peer the proxy sends to. OBI shares only
// httpproxyserver's namespaces, so a request sent here is a genuine egress hop
// whose only span is the sending side's client span. A request the proxy sends
// to itself over loopback produces a server span and no client span at all, so
// it cannot show this defect.
const echoServerHost = "httpechoserver:3030"

// An outgoing message at or above the size of msg_buffer_mem is where a length
// bounded by a power-of-two mask rather than by a clamp collapses to zero:
// 8192 & 8191 is 0, so the copy writes nothing while the recorded length still
// says 8192. The tcp_sendmsg kprobe is then handed bytes this call never wrote,
// protocol detection fails, and the request produces no client span at all. The
// receiving side parses the request normally throughout, which is why this
// needs an assertion on the sending side.
//
// The sizes are exact and they bracket the boundary. The two arbitrary-size
// subtests above pad by rand.IntN(4096) on top of a 1 KB floor, so their
// largest request is around 5 KB and neither has ever reached this boundary; a
// randomized size that only sometimes crossed it would report a deterministic
// defect as a flake. The small size is the control: it fails with the rest if
// the fixture itself is broken, and passes alone if the boundary is.
func testLargeHTTPRequestEgressAtMsgBufferBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		size int
	}{
		{name: "well below the msg buffer size", path: "/arbitrary3", size: 700},
		{name: "one byte below the msg buffer size", path: "/arbitrary4", size: msgBufferSizeMax - 1},
		{name: "exactly the msg buffer size", path: "/arbitrary5", size: msgBufferSizeMax},
		{name: "above the msg buffer size", path: "/arbitrary6", size: msgBufferSizeMax + 512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := []string{
				"Accept: */*",
				"User-Agent: user_agent",
				"Connection: close",
				"Traceparent: " + createTraceparent(createTraceID(), createParentID()),
			}
			dialRawRequest(t, "GET", tc.path, headers, tc.size)

			// The client span is what the boundary removes. The request carries
			// a traceparent of its own so that the subtest exercises the
			// existing-traceparent path through fill_msg_buffers(), which is
			// the one a real caller with an upstream context takes.
			awaitEgressClientSpan(t, "GET", tc.path)
		})
	}
}

// The same boundary for a request carrying no traceparent of its own, read off
// the wire at the far end. fill_msg_buffers() feeds the decision to extend the
// packet as well as the kprobe's buffer, so a fix that restored client spans by
// suppressing injection would pass the test above and fail this one.
func testLargeHTTPRequestEgressInjectionAtMsgBufferBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		size int
	}{
		{name: "well below the msg buffer size", path: "/echoheaders1", size: 700},
		{name: "above the msg buffer size", path: "/echoheaders2", size: msgBufferSizeMax + 512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := []string{
				"Accept: */*",
				"User-Agent: user_agent",
				"Connection: close",
			}
			received := dialRawRequest(t, "GET", tc.path, headers, tc.size)

			var echoed map[string]string
			require.NoError(t, json.Unmarshal([]byte(received), &echoed))

			tp, ok := echoed["traceparent"]
			require.True(t, ok, "no traceparent was injected into the outgoing request: %v", echoed)

			client := awaitEgressClientSpan(t, "GET", tc.path)
			require.Equal(t, "00-"+client.TraceID+"-"+client.SpanID+"-01", tp)
		})
	}
}

// Sends a raw request of exactly totalSize bytes from httpproxyserver to the
// uninstrumented echo server, and returns the response body the echo server
// sent back. totalSize is the length of the single write the proxy makes, and
// therefore the sk_msg size the BPF program sees.
func dialRawRequest(t *testing.T, method, path string, headers []string, totalSize int) string {
	t.Helper()

	const padHeader = "pad: "

	reqSize := getHTTPRequestSize(t, echoServerHost, method, path, headers...)
	padSize := totalSize - (reqSize.size + len(padHeader) + len("\r\n"))
	require.Positive(t, padSize, "the request is already at least as large as the requested size")

	headers = append(headers, padHeader+strings.Repeat("A", padSize))
	rawReq := createRawHTTPRequest(t, method, path, echoServerHost, headers...)
	require.Len(t, rawReq, totalSize, "the request must be exactly the size under test")

	body, err := json.Marshal(map[string]string{"rawRequest": rawReq, "host": echoServerHost})
	require.NoError(t, err)

	resp := doHTTPPostReturnBody(t, "http://localhost:3035/dial", 200, body)

	var dialResp struct {
		Status string `json:"status"`
		Body   string `json:"body"`
	}
	require.NoError(t, json.Unmarshal(resp, &dialResp))
	require.Contains(t, dialResp.Status, "200")

	return dialResp.Body
}

// Waits for the client span of the egress hop identified by path. Nothing
// instruments the echo server, so this span is the only one the hop can
// produce and its absence is exactly the defect under test. Each subtest uses a
// path of its own, so the operation name identifies the hop on its own — a
// client span carries the target as url.full rather than url.path, which is
// asserted here rather than used to select the span.
func awaitEgressClientSpan(t *testing.T, method, path string) jaeger.Span {
	t.Helper()

	operationName := fmt.Sprintf("%s %s", strings.ToUpper(method), path)

	var span jaeger.Span

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=httpproxyserver&operation=" + url.QueryEscape(operationName))
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))

		var spans []jaeger.Span
		for i := range tq.Data {
			spans = append(spans,
				tq.Data[i].FindByOperationNameServiceAndKind(operationName, "httpproxyserver", "client")...)
		}
		require.Len(ct, spans, 1, "no client span was produced for the outgoing request")
		span = spans[0]
	}, testTimeout, 100*time.Millisecond)

	full, ok := jaeger.FindIn(span.Tags, "url.full")
	require.True(t, ok, "the client span carries no url.full")
	require.Equal(t, "http://"+strings.Split(echoServerHost, ":")[0]+path, full.Value)

	return span
}
