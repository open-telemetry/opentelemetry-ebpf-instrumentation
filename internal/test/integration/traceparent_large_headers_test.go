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

// The /large-* chain is tpclient-a (Node.js) -> tpclient-go (Go) -> tpclient-c (Node.js).
// Every request on it carries a large cookie ahead of the traceparent, so the
// traceparent is past the first 4 KiB of headers that the HTTP/1 scans used to cover.
const (
	largeHeadersTraceID     = "abcdef0123456789abcdef0123456789"
	largeHeadersTraceparent = "00-" + largeHeadersTraceID + "-0000000000000100-01"
	largeCookieBytes        = 12 * 1024
	largeHeadersMinOffset   = 4 * 1024
)

// largeHeadersHop is what each service of the chain reports about the request it received.
type largeHeadersHop struct {
	Service      string   `json:"service"`
	Traceparents []string `json:"traceparents"`
	// only the Node.js services report it: Go doesn't keep the header order
	TraceparentOffset int              `json:"traceparentOffset"`
	Downstream        *largeHeadersHop `json:"downstream"`
}

// testLargeHeadersWithTraceparent: each hop sends its own traceparent after the
// cookie. Every server must adopt it and no client may add a second one.
func testLargeHeadersWithTraceparent(t *testing.T) {
	a := doLargeHeadersRequest(t, "/large-tp", largeHeadersTraceparent)
	goHop, c := largeHeadersDownstream(t, a)

	// The test client wrote Cookie before Traceparent, as net/http sorts headers.
	require.Equal(t, []string{largeHeadersTraceparent}, a.Traceparents)
	require.Greater(t, a.TraceparentOffset, largeHeadersMinOffset)

	// Node.js client: the tpinjector found the existing traceparent past the cookie.
	require.Len(t, goHop.Traceparents, 1, "the tpinjector must not add a second traceparent")
	require.Equal(t, largeHeadersTraceID, traceIDOf(t, goHop.Traceparents[0]))

	// Go client: the Go probes found the existing traceparent past the cookie.
	require.Len(t, c.Traceparents, 1, "the Go probes must not add a second traceparent")
	require.Equal(t, largeHeadersTraceID, traceIDOf(t, c.Traceparents[0]))
	require.Greater(t, c.TraceparentOffset, largeHeadersMinOffset)

	// Servers: the generic tracer (Node.js) and the Go tracer adopted the
	// traceparent they found past the cookie.
	requireLargeHeadersTrace(t, "GET /large-tp", largeHeadersTraceID)
}

// testLargeHeadersWithoutTraceparent: no hop sends a traceparent, so OBI must
// look past the cookie, find none, and inject exactly one on every client call.
func testLargeHeadersWithoutTraceparent(t *testing.T) {
	a := doLargeHeadersRequest(t, "/large-no-tp", "")
	goHop, c := largeHeadersDownstream(t, a)

	require.Empty(t, a.Traceparents)

	// Node.js client: the tpinjector scanned the whole header block and injected one.
	require.Len(t, goHop.Traceparents, 1, "the tpinjector must inject exactly one traceparent")
	traceID := traceIDOf(t, goHop.Traceparents[0])

	// Go client: the Go probes injected one after the cookie, so the Node.js
	// server found it past the first 4 KiB.
	require.Len(t, c.Traceparents, 1, "the Go probes must inject exactly one traceparent")
	require.Equal(t, traceID, traceIDOf(t, c.Traceparents[0]))
	require.Greater(t, c.TraceparentOffset, largeHeadersMinOffset)

	requireLargeHeadersTrace(t, "GET /large-no-tp", traceID)
}

func doLargeHeadersRequest(t *testing.T, path, traceparent string) largeHeadersHop {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://localhost:6000"+path, http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Cookie", "session="+strings.Repeat("a", largeCookieBytes))
	if traceparent != "" {
		req.Header.Set("Traceparent", traceparent)
	}

	resp, err := testHTTPClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var a largeHeadersHop
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&a))
	require.Equal(t, "a", a.Service)
	return a
}

func largeHeadersDownstream(t *testing.T, a largeHeadersHop) (goHop, c largeHeadersHop) {
	t.Helper()
	require.NotNil(t, a.Downstream)
	require.Equal(t, "go", a.Downstream.Service)
	require.NotNil(t, a.Downstream.Downstream)
	require.Equal(t, "c", a.Downstream.Downstream.Service)
	return *a.Downstream, *a.Downstream.Downstream
}

func requireLargeHeadersTrace(t *testing.T, operation, traceID string) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := getJaeger(jaegerQueryURL + "?service=tpclient-a&traceID=" + traceID)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		require.Len(ct, tq.Data, 1)
		trace := tq.Data[0]
		for _, service := range []string{"tpclient-a", "tpclient-go", "tpclient-c"} {
			require.NotEmpty(ct, trace.FindByOperationNameServiceAndKind(operation, service, "server"),
				"%s server span must join trace %s", service, traceID)
		}
		for _, service := range []string{"tpclient-a", "tpclient-go"} {
			require.NotEmpty(ct, trace.FindByOperationNameServiceAndKind(operation, service, "client"),
				"%s client span must join trace %s", service, traceID)
		}
	}, testTimeout, 100*time.Millisecond)
}

func traceIDOf(t *testing.T, traceparent string) string {
	t.Helper()
	parts := strings.Split(traceparent, "-")
	require.Len(t, parts, 4, "invalid traceparent %q", traceparent)
	return parts[1]
}
