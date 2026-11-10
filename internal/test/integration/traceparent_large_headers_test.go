// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

// The /large chain is tpclient-a (Node.js) -> tpclient-go (Go). The test sends
// each request with a large cookie ahead of its traceparent, so the traceparent
// is past the first 4 KiB of headers that the HTTP/1 scans used to cover. Only
// incoming requests are scanned that far, so tpclient-a forwards the cookie with
// no traceparent of its own and OBI injects one.
const (
	largeHeadersTraceID       = "abcdef0123456789abcdef0123456789"
	largeHeadersTraceparent   = "00-" + largeHeadersTraceID + "-0000000000000100-01"
	largeHeadersGoTraceID     = "0123456789abcdef0123456789abcdef"
	largeHeadersGoTraceparent = "00-" + largeHeadersGoTraceID + "-0000000000000200-01"
	largeCookieBytes          = 12 * 1024
	largeHeadersMinOffset     = 4 * 1024
)

// largeHeadersHop is what each service of the chain reports about the request it received.
type largeHeadersHop struct {
	Service      string   `json:"service"`
	Traceparents []string `json:"traceparents"`
	// only the Node.js service reports it: Go doesn't keep the header order
	TraceparentOffset int              `json:"traceparentOffset"`
	Downstream        *largeHeadersHop `json:"downstream"`
}

// testLargeHeadersWithTraceparent: the Node.js server must adopt the traceparent
// it receives past the cookie, and OBI must carry its trace to the Go server.
func testLargeHeadersWithTraceparent(t *testing.T) {
	a := doLargeHeadersRequest(t, "http://localhost:6000", largeHeadersTraceparent)
	require.Equal(t, "a", a.Service)
	// The test client wrote Cookie before Traceparent, as net/http sorts headers.
	require.Equal(t, []string{largeHeadersTraceparent}, a.Traceparents)
	require.Greater(t, a.TraceparentOffset, largeHeadersMinOffset)

	goHop := largeHeadersDownstream(t, a)
	require.Len(t, goHop.Traceparents, 1, "the tpinjector must inject exactly one traceparent")
	require.Equal(t, largeHeadersTraceID, traceIDOf(t, goHop.Traceparents[0]))

	requireLargeHeadersChainTrace(t, largeHeadersTraceID)
}

// testLargeHeadersGoServer: the Go server must adopt the traceparent it receives past the cookie.
func testLargeHeadersGoServer(t *testing.T) {
	goHop := doLargeHeadersRequest(t, "http://localhost:6003", largeHeadersGoTraceparent)
	require.Equal(t, "go", goHop.Service)
	require.Equal(t, []string{largeHeadersGoTraceparent}, goHop.Traceparents)

	requireLargeHeadersTrace(t, largeHeadersGoTraceID, "tpclient-go", "server")
}

// testLargeHeadersWithoutTraceparent: the Node.js server finds no traceparent
// past the cookie, so OBI must start a trace and inject exactly one on its client call.
func testLargeHeadersWithoutTraceparent(t *testing.T) {
	a := doLargeHeadersRequest(t, "http://localhost:6000", "")
	require.Equal(t, "a", a.Service)
	require.Empty(t, a.Traceparents)

	goHop := largeHeadersDownstream(t, a)
	require.Len(t, goHop.Traceparents, 1, "the tpinjector must inject exactly one traceparent")

	requireLargeHeadersChainTrace(t, traceIDOf(t, goHop.Traceparents[0]))
}

func doLargeHeadersRequest(t *testing.T, baseURL, traceparent string) largeHeadersHop {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+"/large", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Cookie", "session="+strings.Repeat("a", largeCookieBytes))
	if traceparent != "" {
		req.Header.Set("Traceparent", traceparent)
	}

	resp, err := testHTTPClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var hop largeHeadersHop
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&hop))
	return hop
}

func largeHeadersDownstream(t *testing.T, a largeHeadersHop) largeHeadersHop {
	t.Helper()
	require.NotNil(t, a.Downstream)
	require.Equal(t, "go", a.Downstream.Service)
	return *a.Downstream
}

// requireLargeHeadersChainTrace checks that every span of the chain joined the trace.
func requireLargeHeadersChainTrace(t *testing.T, traceID string) {
	t.Helper()
	requireLargeHeadersTrace(t, traceID, "tpclient-a", "server")
	requireLargeHeadersTrace(t, traceID, "tpclient-a", "client")
	requireLargeHeadersTrace(t, traceID, "tpclient-go", "server")
}

func requireLargeHeadersTrace(t *testing.T, traceID, service, kind string) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := getJaeger(jaegerQueryURL + "?service=" + service + "&traceID=" + traceID)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		require.Len(ct, tq.Data, 1)
		require.NotEmpty(ct, tq.Data[0].FindByOperationNameServiceAndKind("GET /large", service, kind),
			"%s %s span must join trace %s", service, kind, traceID)
	}, testTimeout, 100*time.Millisecond)
}

func traceIDOf(t *testing.T, traceparent string) string {
	t.Helper()
	parts := strings.Split(traceparent, "-")
	require.Len(t, parts, 4, "invalid traceparent %q", traceparent)
	return parts[1]
}
