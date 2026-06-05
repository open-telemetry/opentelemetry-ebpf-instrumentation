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

	// Tests rely on active polling instead of long static waits — the warmup
	// step below confirms every service is instrumented before strict checks
	grpcRelayTimeout = 2 * time.Minute
)

// expectedRelayServices lists all services in the relay chain:
// Go (HTTP entry) -> Python (gRPC) -> Go (gRPC→HTTP bridge) -> Go (HTTP→gRPC bridge)
// -> Node.js (gRPC) -> Java (gRPC) -> .NET (gRPC) -> Go (gRPC terminal)
var expectedRelayServices = []string{
	"go-entry",
	"python-relay",
	"go-grpc-to-http",
	"go-http-to-grpc",
	"nodejs-relay",
	"java-relay",
	"dotnet-relay",
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
		"http://localhost:8095/health", // dotnet-relay
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
		r, err := http.Get(jaegerQueryURL + "?service=go-entry&limit=1&lookback=5m")
		require.NoError(ct, err)
		require.NotNil(ct, r)
		defer r.Body.Close()
		require.Equal(ct, http.StatusOK, r.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(r.Body).Decode(&tq))
		require.NotEmpty(ct, tq.Data)
	}, time.Minute, time.Second)
	t.Log("instrumentation ready")

	t.Log("waiting for dotnet-relay instrumentation")
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		if wr, err := http.Get("http://localhost:8080/relay"); err == nil && wr != nil {
			wr.Body.Close()
		}
		r, err := http.Get(jaegerQueryURL + "?service=dotnet-relay&limit=1&lookback=5m")
		require.NoError(ct, err)
		require.NotNil(ct, r)
		defer r.Body.Close()
		require.Equal(ct, http.StatusOK, r.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(r.Body).Decode(&tq))
		require.NotEmpty(ct, tq.Data, "dotnet-relay not yet instrumented")
	}, 2*time.Minute, time.Second)
	t.Log("dotnet-relay instrumented")

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

		// Poll Jaeger for our exact trace ID — gives a slow CI chain
		// (JVM attach + nodejs/python startup) time to land all spans
		// without burning the outer Eventually budget on fresh trace IDs.
		var tq jaeger.TracesQuery
		require.EventuallyWithT(ct, func(ctt *assert.CollectT) {
			resp, err := http.Get(jaegerQueryURL + "/" + relayAttemptTraceID)
			require.NoError(ctt, err)
			defer resp.Body.Close()
			require.NoError(ctt, json.NewDecoder(resp.Body).Decode(&tq))
			require.NotEmpty(ctt, tq.Data)
			svcs := traceServices(tq.Data[0])
			for _, svc := range expectedRelayServices {
				require.Contains(ctt, svcs, svc, "trace missing service %s", svc)
			}
		}, 30*time.Second, time.Second)

		// Pick the completed trace for the structural checks below.
		trace = tq.Data[0]

		// All checks inside the loop so we retry if Jaeger hasn't
		// indexed all spans yet.
		relayServerSpans := trace.FindByOperationName("/relay.Relay/Relay", "server")
		relayClientSpans := trace.FindByOperationName("/relay.Relay/Relay", "client")

		require.GreaterOrEqual(ct, len(relayServerSpans), 6,
			"should have at least 6 gRPC server spans (one per gRPC relay hop)")
		require.GreaterOrEqual(ct, len(relayClientSpans), 6,
			"should have at least 6 gRPC client spans (one per gRPC relay hop)")

		// Verify the parent chain: for each gRPC hop, at least one server
		// span must have a parent client span from the expected service.
		grpcParentChain := []struct{ server, parent string }{
			{"python-relay", "go-entry"},
			{"go-grpc-to-http", "python-relay"},
			{"nodejs-relay", "go-http-to-grpc"},
			{"java-relay", "nodejs-relay"},
			{"dotnet-relay", "java-relay"},
			{"go-terminal", "dotnet-relay"},
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

// serverSpansByService returns every server-kind span in the trace owned by
// the given service, deduped by span_id. Some OBI paths emit a generic op="*"
// HTTP/2 span alongside the gRPC-named span for the same logical request; both
// share the same span_id. Counting them twice would flag a false isolation
// break in the multiplex assertion
func serverSpansByService(trace jaeger.Trace, service string) []jaeger.Span {
	seen := map[string]bool{}
	var matches []jaeger.Span
	for _, s := range trace.Spans {
		if proc, ok := trace.Processes[s.ProcessID]; !ok || proc.ServiceName != service {
			continue
		}
		tag, ok := jaeger.FindIn(s.Tags, "span.kind")
		if !ok || tag.Value != "server" {
			continue
		}
		if seen[s.SpanID] {
			continue
		}
		seen[s.SpanID] = true
		matches = append(matches, s)
	}
	return matches
}

// testGRPCMultiplexedContextPropagation fans out N concurrent gRPC streams
// from go-entry and asserts every gRPC server hop in the chain has distinct
// parent_ids per stream. Each Go relay holds a singleton grpc.NewClient per
// next-hop addr (see callNextHop in main.go), so concurrent fan-outs share
// one HTTP/2 connection and multiplex as separate streams down the line.
// nodejs and java handlers naturally reuse their persistent clients too
func testGRPCMultiplexedContextPropagation(t *testing.T) {
	// Hops asserted: every gRPC server in the chain after the multiplexing
	// origin. go-http-to-grpc receives HTTP/1 (not gRPC server-side), so it
	// has no gRPC server span to assert on
	hops := []string{"go-grpc-to-http", "nodejs-relay", "java-relay", "dotnet-relay"}

	// Wait for OBI to instrument go-entry — suite health checks only prove the
	// service is up, not that OBI has discovered the pid
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		if wr, err := http.Get("http://localhost:8080/smoke"); err == nil && wr != nil {
			wr.Body.Close()
		}
		r, err := http.Get(jaegerQueryURL + "?service=go-entry&limit=1&lookback=5m")
		require.NoError(ct, err)
		require.NotNil(ct, r)
		defer r.Body.Close()
		require.Equal(ct, http.StatusOK, r.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(r.Body).Decode(&tq))
		require.NotEmpty(ct, tq.Data, "go-entry not yet instrumented")
	}, 3*time.Minute, time.Second)

	// Persistent gRPC connections established before OBI discovers the peer
	// pid stay un-tracked for their lifetime — loop until a request with a
	// known traceparent reaches every hop on the same trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		now := uint64(time.Now().UnixNano())
		warmupTraceID := fmt.Sprintf("%016x%016x", now, now+1)
		req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/relay-multiplex", nil)
		require.NoError(ct, err)
		req.Header.Set("Traceparent", fmt.Sprintf("00-%s-%s-01", warmupTraceID, multiplexSpanID))
		if wr, err := http.DefaultClient.Do(req); err == nil && wr != nil {
			wr.Body.Close()
		}

		var tq jaeger.TracesQuery
		require.EventuallyWithT(ct, func(ctt *assert.CollectT) {
			resp, err := http.Get(jaegerQueryURL + "/" + warmupTraceID)
			require.NoError(ctt, err)
			defer resp.Body.Close()
			require.Equal(ctt, http.StatusOK, resp.StatusCode)
			require.NoError(ctt, json.NewDecoder(resp.Body).Decode(&tq))
			require.NotEmpty(ctt, tq.Data, "warmup trace not in jaeger yet")
		}, 30*time.Second, time.Second)

		for _, hop := range hops {
			require.NotEmpty(ct, serverSpansByService(tq.Data[0], hop),
				"warmup: %s missing on trace %s — propagation chain not yet established", hop, warmupTraceID)
		}
	}, 3*time.Minute, time.Second)

	now := uint64(time.Now().UnixNano())
	traceID := fmt.Sprintf("%016x%016x", now, now+1)

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/relay-multiplex", nil)
		require.NoError(ct, err)
		req.Header.Set("Traceparent", fmt.Sprintf("00-%s-%s-01", traceID, multiplexSpanID))
		if wr, err := http.DefaultClient.Do(req); err == nil && wr != nil {
			wr.Body.Close()
		}

		resp, err := http.Get(jaegerQueryURL + "/" + traceID)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		defer resp.Body.Close()

		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		require.NotEmpty(ct, tq.Data)

		trace = tq.Data[0]
		for _, hop := range hops {
			require.GreaterOrEqual(ct,
				len(serverSpansByService(trace, hop)),
				3, "expected at least 3 %s server spans in trace %s", hop, traceID)
		}
	}, grpcRelayTimeout, time.Second)

	t.Logf("trace %s: %d spans across %d services",
		trace.TraceID, len(trace.Spans), len(traceServices(trace)))

	for _, hop := range hops {
		serverSpans := serverSpansByService(trace, hop)
		parents := map[string]bool{}
		for _, s := range serverSpans {
			pid := ""
			for _, ref := range s.References {
				if ref.RefType == "CHILD_OF" {
					pid = ref.SpanID
				}
			}
			require.NotEmpty(t, pid, "%s span %s missing parent", hop, s.SpanID)
			require.False(t, parents[pid],
				"%s: parent_id %s shared by multiple server spans — stream isolation broken", hop, pid)
			parents[pid] = true
		}
		t.Logf("%s: %d server spans, %d distinct parents", hop, len(serverSpans), len(parents))
	}

	// Walk one chain root→leaf so a failure shows which hop dropped a stream
	leafHop := hops[len(hops)-1]
	leafSpans := serverSpansByService(trace, leafHop)
	if len(leafSpans) > 0 {
		var chain []jaeger.Span
		cur := leafSpans[0]
		chain = append(chain, cur)
		for {
			parent, ok := trace.ParentOf(&cur)
			if !ok {
				break
			}
			chain = append(chain, parent)
			cur = parent
		}
		for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
			chain[i], chain[j] = chain[j], chain[i]
		}
		t.Logf("one chain (%d spans):", len(chain))
		for depth, span := range chain {
			svc := "unknown"
			if proc, ok := trace.Processes[span.ProcessID]; ok {
				svc = proc.ServiceName
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
			t.Logf("%s[%s]%s span_id=[%s] parent_span_id=[%s]",
				strings.Repeat("  ", depth), svc, kind, span.SpanID, parentID)
		}
	}
}

// traceServices returns a set of unique service names from a trace's processes.
func traceServices(trace jaeger.Trace) map[string]bool {
	services := make(map[string]bool)
	for _, p := range trace.Processes {
		services[p.ServiceName] = true
	}
	return services
}
