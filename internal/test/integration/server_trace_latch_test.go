// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"path"
	"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

const latchRequests = 6

// TestServerTraceNotLatchedOntoLaterClientCalls covers a server trace outliving its
// own request: the app answers on a keep-alive connection and only then calls out to
// three other services, so no inbound request is in flight when it does. Those client
// calls must not join the finished inbound request's trace, whatever framing the
// response used to say where it ends. The one exception is the inflight mode, where
// the calls happen while the response is still open, so they must join it.
func TestServerTraceNotLatchedOntoLaterClientCalls(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-latchsrv.yml", path.Join(pathOutput, "test-suite-latchsrv.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	for _, mode := range []struct {
		name     string
		port     int
		service  string
		status   int
		detached bool
	}{
		{name: "content-length", port: 8080, service: "latchsrv", status: http.StatusOK, detached: true},
		{name: "chunked", port: 8081, service: "latchsrv-chunked", status: http.StatusOK, detached: true},
		{name: "multi-write body", port: 8082, service: "latchsrv-multiwrite", status: http.StatusOK, detached: true},
		{name: "no body status", port: 8083, service: "latchsrv-nobody", status: http.StatusNoContent, detached: true},
		{name: "big headers", port: 8084, service: "latchsrv-bigheaders", status: http.StatusOK, detached: true},
		{name: "calls during the response", port: 8085, service: "latchsrv-inflight", status: http.StatusOK, detached: false},
	} {
		t.Run(mode.name, func(t *testing.T) {
			driveLatchServer(t, mode.port, mode.status)
			if mode.detached {
				assertCallsDetached(t, mode.service)
			} else {
				assertCallsParented(t, mode.service)
			}
		})
	}

	require.NoError(t, compose.Close())
}

// driveLatchServer sends latchRequests requests over one keep-alive connection,
// reading each full response before the next request
func driveLatchServer(t *testing.T, port, wantStatus int) {
	// The app serves one connection at a time, so the handshake that succeeds becomes
	// the keep-alive connection used for the rest of the test: the inbound connection
	// stays open while the app issues its outgoing calls.
	var (
		conn   net.Conn
		reader *bufio.Reader
	)

	require.Eventually(t, func() bool {
		candidate, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), 5*time.Second)
		if err != nil {
			return false
		}

		if err := candidate.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			candidate.Close()
			return false
		}

		candidateReader := bufio.NewReader(candidate)
		if _, err := fmt.Fprintf(candidate, "GET /ready HTTP/1.1\r\nHost: latchsrv\r\n\r\n"); err != nil {
			candidate.Close()
			return false
		}

		resp, err := http.ReadResponse(candidateReader, nil)
		if err != nil {
			candidate.Close()
			return false
		}
		resp.Body.Close()

		conn, reader = candidate, candidateReader
		return true
	}, 2*time.Minute, time.Second)
	defer conn.Close()

	for i := range latchRequests {
		require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))
		_, err := fmt.Fprintf(conn, "GET /trigger HTTP/1.1\r\nHost: latchsrv\r\n\r\n")
		require.NoError(t, err)

		resp, err := http.ReadResponse(reader, nil)
		require.NoErrorf(t, err, "reading response %d", i)
		require.Equal(t, wantStatus, resp.StatusCode)
		require.NoError(t, resp.Body.Close())

		// let the app finish its three outgoing calls before the next request
		time.Sleep(time.Second)
	}
}

func latchTraces(t *testing.T, service string) []jaeger.Trace {
	var traces []jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=" + service + "&limit=200")
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))

		targets := map[string]struct{}{}
		for _, tr := range tq.Data {
			for _, span := range tr.Spans {
				if spanKind(span) == "client" {
					targets[serverAddress(span)] = struct{}{}
				}
			}
		}
		require.Len(ct, targets, 3, "all three targets must have been called")
		traces = tq.Data
	}, testTimeout, 100*time.Millisecond)

	return traces
}

func assertCallsDetached(t *testing.T, service string) {
	detached := 0
	for _, trace := range latchTraces(t, service) {
		serverIDs := map[string]struct{}{}
		targets := map[string]struct{}{}

		for _, span := range trace.Spans {
			if spanKind(span) == "server" {
				serverIDs[span.SpanID] = struct{}{}
			}
		}

		for _, span := range trace.Spans {
			if spanKind(span) != "client" {
				continue
			}
			targets[serverAddress(span)] = struct{}{}
			for _, ref := range span.References {
				if ref.RefType != "CHILD_OF" {
					continue
				}
				_, isServer := serverIDs[ref.SpanID]
				assert.Falsef(t, isServer,
					"client span %s retained finished server %s as its parent in trace %s",
					span.SpanID, ref.SpanID, trace.TraceID)
			}
		}

		if len(serverIDs) > 0 && len(targets) == 3 {
			detached++
		}
	}

	assert.GreaterOrEqualf(t, detached, latchRequests/2,
		"only %d traces retained all three later client calls without parent links to their finished server",
		detached)
}

func assertCallsParented(t *testing.T, service string) {
	// the calls happen while the inbound response is still open, so a trace must
	// hold the server span together with the calls to all three targets
	parented := 0
	for _, trace := range latchTraces(t, service) {
		servers := 0
		targets := map[string]struct{}{}

		for _, span := range trace.Spans {
			switch spanKind(span) {
			case "server":
				servers++
			case "client":
				targets[serverAddress(span)] = struct{}{}
			}
		}

		if servers > 0 && len(targets) == 3 {
			parented++
		}
	}

	assert.GreaterOrEqualf(t, parented, latchRequests/2,
		"only %d traces hold the inbound request together with its three in-flight calls: "+
			"calls made during the response lost their parent", parented)
}

func serverAddress(s jaeger.Span) string {
	if tag, ok := jaeger.FindIn(s.Tags, "server.address"); ok {
		if v, ok := tag.Value.(string); ok {
			return v
		}
	}
	return ""
}
