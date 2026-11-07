// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

const (
	dotnetHTTPClientURL     = "http://localhost:18380"
	dotnetHTTPClientService = "dotnet-httpclient"
)

// What the downstream received on the .NET app's outgoing request
type dotnetDownstreamObservation struct {
	Traceparent []string `json:"traceparent"`
	Protocol    int      `json:"protocol"`
}

// The .NET app propagates the context it was called with on an async HTTP/1 call.
// OBI must report that outgoing span as its client span, parented by the server
// span of the same request, whichever thread the call resumed on.
func TestDotNetHTTPClientTraceparent(t *testing.T) {
	// headers: tpinjector reads the application's header; disabled: the kprobe parser does
	for _, mode := range []string{"headers", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			compose, err := docker.ComposeSuite("docker-compose-dotnet-httpclient-traceparent.yml",
				path.Join(pathOutput, "test-suite-dotnet-httpclient-traceparent-"+mode+".log"))
			require.NoError(t, err)
			compose.Env = append(compose.Env, "DOTNET_HTTPCLIENT_PROPAGATION="+mode)
			t.Cleanup(func() { assert.NoError(t, compose.Close()) })
			require.NoError(t, compose.Up())

			waitForDotNetHTTPClientInstrumentation(t)

			t.Run("single", func(t *testing.T) {
				assertDotNetClientParent(t, createTraceID(), createParentID())
			})
			t.Run("concurrent", func(t *testing.T) {
				for i := range 8 {
					t.Run(strconv.Itoa(i), func(t *testing.T) {
						t.Parallel()
						assertDotNetClientParent(t, createTraceID(), createParentID())
					})
				}
			})
			// A retry resends the caller's traceparent: the second request must get its
			// own parent, neither losing it nor inheriting the first request's.
			t.Run("retry-same-traceparent", func(t *testing.T) {
				traceID, parentID := createTraceID(), createParentID()
				first := assertDotNetClientParent(t, traceID, parentID)
				second := assertDotNetClientParent(t, traceID, parentID)
				require.NotEqual(t, first, second, "each request must parent its own client span")
			})
		})
	}
}

// OBI instruments the app asynchronously, and calls produce no spans until it has.
func waitForDotNetHTTPClientInstrumentation(t *testing.T) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(dotnetHTTPClientURL + "/health")
		require.NoError(ct, err)
		require.NoError(ct, resp.Body.Close())
		require.Equal(ct, http.StatusOK, resp.StatusCode)
	}, 2*time.Minute, time.Second)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		callDotNetHTTPClient(ct, createTraceID(), createParentID())
		trace, err := latestTraceMatching(dotnetHTTPClientService, func(trace jaeger.Trace) bool {
			return len(clientSpans(trace)) > 0
		})
		require.NoError(ct, err)
		require.NotEmpty(ct, trace.TraceID, "OBI has not instrumented the .NET app yet")
	}, 2*time.Minute, time.Second)
}

// Calls the app under the given incoming context and returns the span ID of the
// traceparent it put on its outgoing HTTP/1 request.
func callDotNetHTTPClient(t require.TestingT, traceID, parentID string) string {
	req, err := http.NewRequest(http.MethodGet, dotnetHTTPClientURL+"/call?id="+traceID+"-"+parentID, nil)
	require.NoError(t, err)
	req.Header.Set("traceparent", createTraceparent(traceID, parentID))

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))

	var observed dotnetDownstreamObservation
	require.NoError(t, json.Unmarshal(body, &observed))
	require.Equal(t, 1, observed.Protocol, "the outgoing call must be HTTP/1")
	require.Len(t, observed.Traceparent, 1, "the outgoing call must carry only the application's traceparent")
	require.Regexp(t, `^00-`+traceID+`-[0-9a-f]{16}-01$`, observed.Traceparent[0])

	spanID := strings.Split(observed.Traceparent[0], "-")[2]
	require.NotEqual(t, parentID, spanID, "the application must send its own span, not the caller's")
	require.NotEqual(t, "0000000000000000", spanID)

	return spanID
}

// Calls the app and waits for OBI to report the outgoing span as a client span that
// descends from a server span whose parent is the caller. Returns that server span ID.
func assertDotNetClientParent(t *testing.T, traceID, parentID string) string {
	t.Helper()
	outgoingSpanID := callDotNetHTTPClient(t, traceID, parentID)

	var serverSpanID string
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		tq, err := fetchTrace(traceID)
		require.NoError(ct, err)
		require.NotEmpty(ct, tq.Data, "trace %s is not in jaeger yet", traceID)
		trace := tq.Data[0]

		client, ok := dotnetSpanByID(trace, outgoingSpanID)
		require.True(ct, ok, "OBI must report the application's outgoing span %s", outgoingSpanID)
		require.True(ct, isDotNetSpan(trace, client, "client"), "span %s must be a .NET client span", outgoingSpanID)

		server, ok := dotnetServerAncestor(trace, client)
		require.True(ct, ok, "client span %s must descend from a .NET server span", outgoingSpanID)
		require.Contains(ct, server.References,
			jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: parentID},
			"the client span must descend from the server span of its own request")
		serverSpanID = server.SpanID
	}, time.Minute, time.Second)

	return serverSpanID
}

func dotnetSpanByID(trace jaeger.Trace, spanID string) (jaeger.Span, bool) {
	for _, span := range trace.Spans {
		if span.SpanID == spanID {
			return span, true
		}
	}
	return jaeger.Span{}, false
}

// Walks up through any OBI internal spans to the first .NET server span.
func dotnetServerAncestor(trace jaeger.Trace, span jaeger.Span) (jaeger.Span, bool) {
	for range trace.Spans {
		parent, ok := trace.ParentOf(&span)
		if !ok {
			return jaeger.Span{}, false
		}
		if isDotNetSpan(trace, parent, "server") {
			return parent, true
		}
		span = parent
	}
	return jaeger.Span{}, false
}

func isDotNetSpan(trace jaeger.Trace, span jaeger.Span, kind string) bool {
	tag, ok := jaeger.FindIn(span.Tags, "span.kind")
	return ok && tag.Value == kind && trace.Processes[span.ProcessID].ServiceName == dotnetHTTPClientService
}
