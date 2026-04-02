// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"fmt"
	"net/http"
	"path"
	"strings"
	"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

const (
	// Parent span ID injected into /relay-multiplex requests.
	multiplexSpanID = "fedcba0987654321"

	// Loop advances ~5s/iter for Jaeger indexing; observed 22–75s, 3 min
	// gives ample headroom.
	grpcRelayTimeout = 3 * time.Minute
)

// expectedRelayServices lists all services in the relay chain:
// Go (HTTP entry) -> Python (gRPC) -> Go (gRPC→HTTP bridge) -> Go (HTTP→gRPC bridge)
// -> Node.js (gRPC) -> Java (gRPC) -> Go (gRPC terminal)
var expectedRelayServices = []string{
	"go-entry",
	"python-relay",
	"go-grpc-to-http",
	"go-http-to-grpc",
	"nodejs-relay",
	"java-relay",
	"go-terminal",
}

// TestSuite_GRPCRelay validates end-to-end gRPC context propagation
// by sending a known traceparent to the first Go hop and verifying it arrives
// at the last hop with the same trace ID.
func TestSuite_GRPCRelay(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-grpc-relay.yml", path.Join(pathOutput, "test-suite-grpc-relay.log"))
	require.NoError(t, err)

	if !KernelLockdownMode() {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, compose.Up())
	t.Cleanup(func() {
		if err := compose.Close(); err != nil {
			t.Logf("compose.Close(): %v", err)
		}
	})

	// Wait for ALL services in the relay chain to be healthy.
	// Each service exposes an HTTP health endpoint on a dedicated port.
	healthURLs := []string{
		"http://localhost:8080/health", // go-entry
		"http://localhost:8090/health", // python-relay
		"http://localhost:8091/health", // go-grpc-to-http
		"http://localhost:8081/health", // go-http-to-grpc
		"http://localhost:8092/health", // nodejs-relay
		"http://localhost:8093/health", // java-relay
		"http://localhost:8094/health", // go-terminal
	}
	for _, url := range healthURLs {
		waitForTestComponentsNoMetrics(t, url)
	}

	t.Run("gRPC relay chain context propagation", testGRPCRelayChainContextPropagation)
	t.Run("gRPC multiplexed context propagation", testGRPCMultiplexedContextPropagation)
}

func testGRPCRelayChainContextPropagation(t *testing.T) {
	// Wait for OBI to instrument go-entry (spans visible in Jaeger).
	t.Log("waiting for instrumentation to be ready")
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		if wr, err := http.Get("http://localhost:8080/smoke"); err == nil && wr != nil {
			wr.Body.Close()
		}
		r, err := http.Get(jaegerQueryURL + "?service=go-entry&limit=1")
		require.NoError(ct, err)
		require.NotNil(ct, r)
		defer r.Body.Close()
		require.Equal(ct, http.StatusOK, r.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(r.Body).Decode(&tq))
		require.NotEmpty(ct, tq.Data)
	}, time.Minute, time.Second)
	t.Log("instrumentation ready")

	// Fresh trace ID per request so each iteration's assertions run against
	// a single-request trace, not accumulated retries. Loop retries with a
	// new ID until one request yields the full chain (services warm up
	// gradually: JVM attach, connection warm-up).
	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		now := uint64(time.Now().UnixNano())
		relayAttemptTraceID := fmt.Sprintf("%016x%016x", now, now+1)
		traceparent := fmt.Sprintf("00-%s-%016x-01", relayAttemptTraceID, now+2)
		req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/relay", nil)
		require.NoError(ct, err)
		req.Header.Set("Traceparent", traceparent)
		if wr, err := http.DefaultClient.Do(req); err == nil && wr != nil {
			wr.Body.Close()
		}

		// Wait for the 7-hop chain to complete and Jaeger to batch-index.
		time.Sleep(5 * time.Second)

		// Query Jaeger for our exact trace ID.
		resp, err := http.Get(jaegerQueryURL + "/" + relayAttemptTraceID)
		if err != nil {
			require.NoError(ct, err)
			return
		}
		defer resp.Body.Close()

		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		require.NotEmpty(ct, tq.Data)

		// Pick the trace and check it spans all expected services.
		trace = tq.Data[0]
		svcs := traceServices(trace)
		for _, svc := range expectedRelayServices {
			require.Contains(ct, svcs, svc, "trace missing service %s", svc)
		}

		// All checks inside the loop so we retry if Jaeger hasn't
		// indexed all spans yet.
		relayServerSpans := trace.FindByOperationName("/relay.Relay/Relay", "server")
		relayClientSpans := trace.FindByOperationName("/relay.Relay/Relay", "client")

		require.GreaterOrEqual(ct, len(relayServerSpans), 5,
			"should have at least 5 gRPC server spans (one per gRPC relay hop)")
		require.GreaterOrEqual(ct, len(relayClientSpans), 5,
			"should have at least 5 gRPC client spans (one per gRPC relay hop)")

		// Verify the parent chain: for each gRPC hop, at least one server
		// span must have a parent client span from the expected service.
		grpcParentChain := []struct{ server, parent string }{
			{"python-relay", "go-entry"},
			{"go-grpc-to-http", "python-relay"},
			{"nodejs-relay", "go-http-to-grpc"},
			{"java-relay", "nodejs-relay"},
			{"go-terminal", "java-relay"},
		}
		for _, hop := range grpcParentChain {
			serverSpans := trace.FindByOperationNameServiceAndKind("/relay.Relay/Relay", hop.server, "server")
			require.NotEmpty(ct, serverSpans, "expected gRPC server span for %s", hop.server)
			found := false
			for _, ss := range serverSpans {
				parent, ok := trace.ParentOf(&ss)
				if !ok {
					continue
				}
				proc, procOK := trace.Processes[parent.ProcessID]
				if procOK && proc.ServiceName == hop.parent {
					found = true
					break
				}
			}
			require.True(ct, found,
				"%s: no server span has a parent from %s", hop.server, hop.parent)
		}

		// Verify the HTTP bridge: go-grpc-to-http gRPC server → HTTP client.
		grpcToHTTPServerSpans := trace.FindByOperationNameServiceAndKind(
			"/relay.Relay/Relay", "go-grpc-to-http", "server")
		require.NotEmpty(ct, grpcToHTTPServerSpans)
		foundBridge := false
		for _, ss := range grpcToHTTPServerSpans {
			for _, child := range trace.ChildrenOf(ss.SpanID) {
				if p, ok := trace.Processes[child.ProcessID]; ok && p.ServiceName == "go-grpc-to-http" {
					foundBridge = true
				}
			}
		}
		require.True(ct, foundBridge,
			"go-grpc-to-http should have an intra-process gRPC server → HTTP client link")

		// Verify the reverse: go-http-to-grpc HTTP server → gRPC client.
		httpToGRPCClientSpans := trace.FindByOperationNameServiceAndKind(
			"/relay.Relay/Relay", "go-http-to-grpc", "client")
		require.NotEmpty(ct, httpToGRPCClientSpans)
		foundReverse := false
		for _, cs := range httpToGRPCClientSpans {
			if parent, ok := trace.ParentOf(&cs); ok {
				if p, pOK := trace.Processes[parent.ProcessID]; pOK && p.ServiceName == "go-http-to-grpc" {
					foundReverse = true
				}
			}
		}
		require.True(ct, foundReverse,
			"go-http-to-grpc should have an intra-process HTTP server → gRPC client link")

		// Double-span detection: walk the single completed chain from
		// go-terminal's server span back to the root and count how many
		// go-entry CLIENT spans appear in that path. Must be exactly 1.
		// Walking the completed chain (rather than comparing total span counts
		// across all accumulated retries) is immune to early iterations where
		// go-entry was instrumented before python-relay.
		terminalSpansCheck := trace.FindByOperationNameServiceAndKind(
			"/relay.Relay/Relay", "go-terminal", "server")
		require.NotEmpty(ct, terminalSpansCheck,
			"need go-terminal server span for double-span check")
		chainCur := terminalSpansCheck[0]
		goEntryClientInChain := 0
		var goEntryClientSpan *jaeger.Span
		for {
			chainParent, chainOK := trace.ParentOf(&chainCur)
			if !chainOK {
				break
			}
			if p, pOK := trace.Processes[chainParent.ProcessID]; pOK && p.ServiceName == "go-entry" {
				if tag, tagOK := jaeger.FindIn(chainParent.Tags, "span.kind"); tagOK && tag.Value == "client" {
					goEntryClientInChain++
					cp := chainParent
					goEntryClientSpan = &cp
				}
			}
			chainCur = chainParent
		}
		if goEntryClientInChain != 1 {
			t.Logf("=== DEBUG chain walk-back from go-terminal (trace %s) ===", trace.TraceID)
			dc := terminalSpansCheck[0]
			depth := 0
			for {
				svcName := "?"
				if p, ok := trace.Processes[dc.ProcessID]; ok {
					svcName = p.ServiceName
				}
				kind := ""
				if tag, ok := jaeger.FindIn(dc.Tags, "span.kind"); ok {
					kind = fmt.Sprintf(" [%v]", tag.Value)
				}
				parentID := ""
				for _, r := range dc.References {
					if r.RefType == "CHILD_OF" {
						parentID = r.SpanID
					}
				}
				t.Logf("  depth=%d svc=%s%s op=%s span_id=%s parent_id=%s", depth, svcName, kind, dc.OperationName, dc.SpanID, parentID)
				p, ok := trace.ParentOf(&dc)
				if !ok {
					break
				}
				dc = p
				depth++
			}
			t.Logf("=== DEBUG all spans in trace (grouped by service) ===")
			for _, sp := range trace.Spans {
				svc := "?"
				if pr, ok := trace.Processes[sp.ProcessID]; ok {
					svc = pr.ServiceName
				}
				kind := ""
				if tag, ok := jaeger.FindIn(sp.Tags, "span.kind"); ok {
					kind = fmt.Sprintf(" [%v]", tag.Value)
				}
				parentID := ""
				for _, r := range sp.References {
					if r.RefType == "CHILD_OF" {
						parentID = r.SpanID
					}
				}
				t.Logf("  svc=%s%s op=%s span_id=%s parent_id=%s", svc, kind, sp.OperationName, sp.SpanID, parentID)
			}
		}
		require.Equal(ct, 1, goEntryClientInChain,
			"double-span bug: found %d go-entry CLIENT spans in completed chain, expected 1",
			goEntryClientInChain)

		// Entry-point parent link: go-entry's gRPC CLIENT span must be a child
		// of go-entry's own HTTP SERVER span, confirming that the incoming
		// Traceparent header was correctly propagated into the outgoing gRPC call.
		require.NotNil(ct, goEntryClientSpan)
		entryParent, entryParentOK := trace.ParentOf(goEntryClientSpan)
		require.True(ct, entryParentOK,
			"go-entry gRPC client span must have a parent span in the trace")
		entryParentProc, entryProcOK := trace.Processes[entryParent.ProcessID]
		require.True(ct, entryProcOK,
			"go-entry gRPC client span parent has no process entry")
		require.Equal(ct, "go-entry", entryParentProc.ServiceName,
			"go-entry gRPC client span parent must be a go-entry span (HTTP server → gRPC client link broken)")
	}, grpcRelayTimeout, time.Second)

	t.Logf("trace %s: %d spans across %d services",
		trace.TraceID, len(trace.Spans), len(traceServices(trace)))

	// Print the complete chain by walking from go-terminal's server span back to
	// the root, then printing root→leaf with indentation.
	terminalSpans := trace.FindByOperationNameServiceAndKind("/relay.Relay/Relay", "go-terminal", "server")
	if len(terminalSpans) > 0 {
		var chain []jaeger.Span
		cur := terminalSpans[0]
		chain = append(chain, cur)
		for {
			parent, ok := trace.ParentOf(&cur)
			if !ok {
				break
			}
			chain = append(chain, parent)
			cur = parent
		}
		// Reverse: chain is currently leaf→root, we want root→leaf.
		for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
			chain[i], chain[j] = chain[j], chain[i]
		}
		t.Logf("complete chain (%d spans):", len(chain))
		for depth, span := range chain {
			svcName := "unknown"
			if proc, ok := trace.Processes[span.ProcessID]; ok {
				svcName = proc.ServiceName
			}
			kind := ""
			if tag, ok := jaeger.FindIn(span.Tags, "span.kind"); ok {
				kind = fmt.Sprintf(" (%v)", tag.Value)
			}
			parentID := ""
			for _, r := range span.References {
				if r.RefType == "CHILD_OF" {
					parentID = r.SpanID
					break
				}
			}
			t.Logf("%s[%s]%s trace_id=[%s] span_id=[%s] parent_span_id=[%s]",
				strings.Repeat("  ", depth), svcName, kind, span.TraceID, span.SpanID, parentID)
		}
	}
}

// testGRPCMultiplexedContextPropagation verifies that concurrent gRPC streams
// on the same HTTP/2 connection don't mix trace context. The /relay-multiplex
// endpoint fires 1 warmup + 3 concurrent RPCs on a shared grpc.ClientConn.
//
// If stream_id isolation works correctly, each go-entry CLIENT span produces
// a distinct python-relay SERVER span whose parent_id points back to that
// specific CLIENT span. If broken (stream_id race), multiple SERVER spans
// would share the same parent_id (last-writer-wins).
//
// A fixed-per-run trace ID is used so spans from successive requests accumulate
// under one trace while Jaeger indexes them. The stream_id isolation assertion
// is still reliable under accumulation: if isolation is broken, all concurrent
// streams from a single request land the same parent_id, and
// require.False(t, parentIDs[pid]) fires on the second span with that parent —
// regardless of how many other requests' spans are also present.
func testGRPCMultiplexedContextPropagation(t *testing.T) {
	muxNow := uint64(time.Now().UnixNano())
	muxAttemptTraceID := fmt.Sprintf("%016x%016x", muxNow, muxNow+1)

	var serverSpans []jaeger.Span
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/relay-multiplex", nil)
		require.NoError(ct, err)
		req.Header.Set("Traceparent", fmt.Sprintf("00-%s-%s-01", muxAttemptTraceID, multiplexSpanID))
		if wr, err := http.DefaultClient.Do(req); err == nil && wr != nil {
			wr.Body.Close()
		}

		resp, err := http.Get(jaegerQueryURL + "/" + muxAttemptTraceID)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		defer resp.Body.Close()

		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		require.NotEmpty(ct, tq.Data)

		serverSpans = tq.Data[0].FindByOperationNameServiceAndKind(
			"/relay.Relay/Relay", "python-relay", "server")
		require.GreaterOrEqual(ct, len(serverSpans), 3,
			"expected at least 3 python-relay server spans in trace %s", muxAttemptTraceID)
	}, grpcRelayTimeout, time.Second)

	// Each server span must have a DISTINCT parent_id. If stream_id
	// isolation is broken, concurrent streams race on a single
	// outgoing_trace_map entry and multiple server spans end up with
	// the same parent (last-writer-wins).
	parentIDs := map[string]bool{}
	for _, s := range serverSpans {
		pid := ""
		for _, ref := range s.References {
			if ref.RefType == "CHILD_OF" {
				pid = ref.SpanID
			}
		}
		require.NotEmpty(t, pid,
			"python-relay server span %s must have a parent", s.SpanID)
		require.False(t, parentIDs[pid],
			"parent_id %s is shared by multiple server spans — stream_id isolation broken", pid)
		parentIDs[pid] = true
	}

	t.Logf("multiplexed: %d server spans, %d distinct parents",
		len(serverSpans), len(parentIDs))
}

// traceServices returns a set of unique service names from a trace's processes.
func traceServices(trace jaeger.Trace) map[string]bool {
	services := make(map[string]bool)
	for _, p := range trace.Processes {
		services[p.ServiceName] = true
	}
	return services
}
