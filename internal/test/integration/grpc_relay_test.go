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

	// Tests rely on active polling instead of long static waits — the suite-level
	// waitForRelayInstrumentation confirms every service is instrumented before
	// any strict check runs
	grpcRelayTimeout = 2 * time.Minute

	// Budget for OBI to discover and instrument all eight relay pids. Generous
	// because it covers JVM agent attach and the Node.js script injection.
	relayInstrumentationTimeout = 3 * time.Minute
)

// relayServices lists all services in the relay chain, in chain order:
// Go (HTTP entry) -> Python (gRPC) -> Go (gRPC→HTTP bridge) -> Go (HTTP→gRPC bridge)
// -> Node.js (gRPC) -> Java (gRPC) -> Rust (gRPC) -> .NET (gRPC) -> Go (gRPC terminal)
//
// Each entry carries the service's dedicated HTTP health endpoint. Health
// requests are plain HTTP/1 and never touch the gRPC chain, so they are the
// traffic used to prove OBI has instrumented a pid without side effects on the
// chain itself (see waitForRelayInstrumentation).
var relayServices = []struct{ name, healthURL string }{
	{"go-entry", "http://localhost:8080/health"},
	{"python-relay", "http://localhost:8090/health"},
	{"go-grpc-to-http", "http://localhost:8091/health"},
	{"go-http-to-grpc", "http://localhost:8081/health"},
	{"nodejs-relay", "http://localhost:8092/health"},
	{"java-relay", "http://localhost:8093/health"},
	{"rust-relay", "http://localhost:8096/health"},
	{"dotnet-relay", "http://localhost:8095/health"},
	{"go-terminal", "http://localhost:8094/health"},
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
	for _, svc := range relayServices {
		waitForTestComponentsNoMetrics(t, svc.healthURL)
	}

	waitForRelayInstrumentation(t)

	t.Run("gRPC relay chain context propagation", testGRPCRelayChainContextPropagation)
	t.Run("gRPC multiplexed context propagation", testGRPCMultiplexedContextPropagation)
	t.Run("gRPC persistent dyn-table context propagation", testGRPCPersistentDynTable)
	t.Run("gRPC app traceparent not duplicated", func(t *testing.T) {
		testGRPCAppTraceparentNotDuplicated(t, compose)
	})
}

// App sends its own traceparent: OBI must not append a second, receivers discard multi-value.
// Repeated on one channel, nghttp2 puts the whole field in its dynamic table and sends it as a
// single index byte from the second call on, so nothing is left on the wire to detect.
func testGRPCAppTraceparentNotDuplicated(t *testing.T, compose *docker.Compose) {
	now := uint64(time.Now().UnixNano())
	appTraceID := fmt.Sprintf("%016x%016x", now, now+1)
	appSpanID := fmt.Sprintf("%016x", now+2)
	traceparent := fmt.Sprintf("00-%s-%s-01", appTraceID, appSpanID)

	resp, err := http.Get("http://localhost:8092/self-prop?tp=" + traceparent + "&n=4")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		lines := relayTraceparentLogs(ct, compose, appTraceID)
		// past the first request the field is a single dyn-table index, which is the case
		// worth asserting, so keep polling until more than one call has landed
		require.Greater(ct, len(lines), 1, "need a request past the first")
		for _, line := range lines {
			require.Contains(ct, line, "count=1", "duplicate traceparent: %s", line)
			require.Contains(ct, line, appSpanID, "app span id was rewritten: %s", line)
		}
	}, 30*time.Second, 2*time.Second)

	// /self-prop has its own channel, so the ordinary chain runs on a socket where nobody
	// propagates. Injection there must be unaffected by the burst.
	plainTraceID := sendRelayRequest(t)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for _, line := range relayTraceparentLogs(ct, compose, plainTraceID) {
			require.Contains(ct, line, "count=1", "duplicate traceparent: %s", line)
		}
	}, 30*time.Second, 2*time.Second)
}

// java-relay's per-RPC traceparent log lines that carry traceID. Fails the attempt when none
// have arrived yet, so an absent injection can never read as a pass.
func relayTraceparentLogs(ct *assert.CollectT, compose *docker.Compose, traceID string) []string {
	logs, err := compose.LogsTail(2000, "java-relay")
	require.NoError(ct, err)

	var seen []string
	for line := range strings.SplitSeq(logs, "\n") {
		if strings.Contains(line, "traceparent count=") && strings.Contains(line, traceID) {
			seen = append(seen, strings.TrimSpace(line))
		}
	}
	require.NotEmpty(ct, seen, "java-relay logged no traceparent for %s", traceID)

	return seen
}

// hasSpansInJaeger reports whether Jaeger holds any recent trace for the given
// service, which is the observable proof that OBI has instrumented its pid.
func hasSpansInJaeger(service string) bool {
	r, err := http.Get(jaegerQueryURL + "?service=" + service + "&limit=1&lookback=5m")
	if err != nil {
		return false
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return false
	}
	var tq jaeger.TracesQuery
	if err := json.NewDecoder(r.Body).Decode(&tq); err != nil {
		return false
	}
	return len(tq.Data) > 0
}

// waitForRelayInstrumentation blocks until OBI has instrumented every service in
// the chain, generating traffic with health requests only.
//
// This must complete before the first /relay request. Every relay holds a
// singleton gRPC channel to its next hop, created on that first request, and the
// HTTP/2 client preface is sent exactly once, at connection setup. OBI only
// classifies a connection as HTTP/2 when it observes that preface, so a channel
// opened before OBI instrumented the process is never eligible for traceparent
// injection for the lifetime of the run — the chain would break at that hop
// permanently, and no amount of retrying with fresh trace IDs recovers it.
//
// Health endpoints are plain HTTP/1 and unrelated to the gRPC chain, so they
// drive discovery without pinning any hop to an uninstrumented connection.
func waitForRelayInstrumentation(t *testing.T) {
	t.Helper()

	instrumented := make(map[string]bool, len(relayServices))
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var pending []string
		for _, svc := range relayServices {
			if instrumented[svc.name] {
				continue
			}
			if r, err := http.Get(svc.healthURL); err == nil && r != nil {
				r.Body.Close()
			}
			if hasSpansInJaeger(svc.name) {
				instrumented[svc.name] = true
				t.Logf("%s instrumented", svc.name)
				continue
			}
			pending = append(pending, svc.name)
		}
		require.Empty(ct, pending, "waiting for OBI to instrument: %v", pending)
	}, relayInstrumentationTimeout, time.Second)
}

// sendRelayRequest hits /relay with a fresh trace ID and returns it
func sendRelayRequest(t require.TestingT) string {
	now := uint64(time.Now().UnixNano())
	traceID := fmt.Sprintf("%016x%016x", now, now+1)

	req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/relay", nil)
	require.NoError(t, err)
	req.Header.Set("Traceparent", fmt.Sprintf("00-%s-%016x-01", traceID, now+2))

	if resp, err := http.DefaultClient.Do(req); err == nil && resp != nil {
		resp.Body.Close()
	}

	return traceID
}

func testGRPCRelayChainContextPropagation(t *testing.T) {
	// Fresh trace ID per request so each iteration's assertions run against
	// a single-request trace, not accumulated retries. Loop retries with a
	// new ID until one request yields the full chain (services warm up
	// gradually: JVM attach, connection warm-up).
	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		relayAttemptTraceID := sendRelayRequest(ct)

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
			for _, svc := range relayServices {
				require.Contains(ctt, svcs, svc.name, "trace missing service %s", svc.name)
			}
		}, 30*time.Second, time.Second)

		// Pick the completed trace for the structural checks below.
		trace = tq.Data[0]

		// all checks inside the loop so partial Jaeger indexing retries
		relayServerSpans := trace.FindByOperationName("/relay.Relay/Relay", "server")
		relayClientSpans := trace.FindByOperationName("/relay.Relay/Relay", "client")

		require.GreaterOrEqual(ct, len(relayServerSpans), 6,
			"should have at least 6 gRPC server spans (one per gRPC relay hop)")
		require.GreaterOrEqual(ct, len(relayClientSpans), 6,
			"should have at least 6 gRPC client spans (one per gRPC relay hop)")

		// per hop, at least one server span must have a parent client span from the expected service
		grpcParentChain := []struct{ server, parent string }{
			{"python-relay", "go-entry"},
			{"go-grpc-to-http", "python-relay"},
			{"nodejs-relay", "go-http-to-grpc"},
			{"java-relay", "nodejs-relay"},
			{"rust-relay", "java-relay"},
			{"dotnet-relay", "rust-relay"},
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

		// double-span check: go-terminal's chain to root must hold exactly 1 go-entry client span
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
			logChain(t, trace, terminalSpansCheck[0],
				fmt.Sprintf("DEBUG chain from go-terminal (trace %s)", trace.TraceID))
			t.Logf("=== DEBUG all spans in trace ===")
			logAllSpans(t, trace)
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

	terminalSpans := trace.FindByOperationNameServiceAndKind("/relay.Relay/Relay", "go-terminal", "server")
	if len(terminalSpans) > 0 {
		logChain(t, trace, terminalSpans[0], "complete chain")
	}
}

// serverSpansByService dedupes by span_id — OBI can emit a generic op="*" twin with the same id
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

// Fans out N concurrent streams over shared HTTP/2 conns and asserts distinct parent_ids per hop
func testGRPCMultiplexedContextPropagation(t *testing.T) {
	// go-http-to-grpc receives HTTP/1 (no gRPC server span), so it isn't asserted
	hops := []string{"go-grpc-to-http", "nodejs-relay", "java-relay", "rust-relay", "dotnet-relay"}

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

	// one chain root→leaf so a failure shows which hop dropped a stream
	leafSpans := serverSpansByService(trace, hops[len(hops)-1])
	if len(leafSpans) > 0 {
		logChain(t, trace, leafSpans[0], "one chain")
	}
}

// Requests 2+ on a persistent conn carry traceparent as a dyn-table indexed name
func testGRPCPersistentDynTable(t *testing.T) {
	// Warm the chain end-to-end so a first-request miss on any hop doesn't skew the loop
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		now := uint64(time.Now().UnixNano())
		warmupTraceID := fmt.Sprintf("%016x%016x", now, now+1)
		req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/relay", nil)
		require.NoError(ct, err)
		req.Header.Set("Traceparent", fmt.Sprintf("00-%s-%016x-01", warmupTraceID, now+2))
		if wr, err := http.DefaultClient.Do(req); err == nil && wr != nil {
			wr.Body.Close()
		}
		var tq jaeger.TracesQuery
		require.EventuallyWithT(ct, func(ctt *assert.CollectT) {
			resp, err := http.Get(jaegerQueryURL + "/" + warmupTraceID)
			require.NoError(ctt, err)
			defer resp.Body.Close()
			require.NoError(ctt, json.NewDecoder(resp.Body).Decode(&tq))
			require.NotEmpty(ctt, tq.Data)
			svcs := traceServices(tq.Data[0])
			for _, svc := range relayServices {
				require.Contains(ctt, svcs, svc.name, "warmup trace missing %s", svc.name)
			}
		}, 30*time.Second, time.Second)
	}, grpcRelayTimeout, time.Second)

	const numRequests = 8
	// Retry whole batches: stream_ids advance monotonically, so retries exercise fresh dyn-table indices
	var lastFailed []struct {
		iter int
		id   string
		tq   jaeger.TracesQuery
	}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		lastFailed = lastFailed[:0]
		traceIDs := make([]string, numRequests)
		base := uint64(time.Now().UnixNano())
		for i := 0; i < numRequests; i++ {
			nowI := base + uint64(i)*1000
			traceIDs[i] = fmt.Sprintf("%016x%016x", nowI, nowI+1)
			req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/relay", nil)
			require.NoError(ct, err)
			req.Header.Set("Traceparent", fmt.Sprintf("00-%s-%016x-01", traceIDs[i], nowI+2))
			resp, err := http.DefaultClient.Do(req)
			require.NoError(ct, err)
			resp.Body.Close()
		}
		for i, id := range traceIDs {
			var tq jaeger.TracesQuery
			ok := assert.EventuallyWithT(ct, func(ctt *assert.CollectT) {
				resp, err := http.Get(jaegerQueryURL + "/" + id)
				require.NoError(ctt, err)
				defer resp.Body.Close()
				require.NoError(ctt, json.NewDecoder(resp.Body).Decode(&tq))
				require.NotEmpty(ctt, tq.Data, "trace %s not in jaeger", id)
				svcs := traceServices(tq.Data[0])
				for _, svc := range relayServices {
					if !svcs[svc.name] {
						require.Fail(ctt, "missing service", "iter=%d trace=%s missing %s", i, id, svc.name)
					}
				}
			}, 20*time.Second, time.Second)
			if !ok {
				lastFailed = append(lastFailed, struct {
					iter int
					id   string
					tq   jaeger.TracesQuery
				}{i, id, tq})
			}
		}
		for _, f := range lastFailed {
			dumpTrace(t, f.iter, f.id, f.tq)
		}
		require.Empty(ct, lastFailed, "iterations missing services after retries")
	}, 4*time.Minute, 5*time.Second)
}

func dumpTrace(t *testing.T, iter int, id string, tq jaeger.TracesQuery) {
	if len(tq.Data) == 0 {
		t.Logf("iter=%d trace=%s: no data in jaeger", iter, id)
		return
	}
	tr := tq.Data[0]
	t.Logf("iter=%d trace=%s spans=%d processes=%d", iter, id, len(tr.Spans), len(tr.Processes))
	logAllSpans(t, tr)
}

// spanMeta returns the service name, " (kind)" suffix and parent span id of a span, for logging
func spanMeta(trace jaeger.Trace, s *jaeger.Span) (svc, kind, parentID string) {
	svc = "?"
	if p, ok := trace.Processes[s.ProcessID]; ok {
		svc = p.ServiceName
	}
	if tag, ok := jaeger.FindIn(s.Tags, "span.kind"); ok {
		kind = fmt.Sprintf(" (%v)", tag.Value)
	}
	for _, r := range s.References {
		if r.RefType == "CHILD_OF" {
			parentID = r.SpanID
			break
		}
	}
	return svc, kind, parentID
}

// logChain prints leaf's ancestry root→leaf with indentation
func logChain(t *testing.T, trace jaeger.Trace, leaf jaeger.Span, label string) {
	chain := []jaeger.Span{leaf}
	for cur := leaf; ; {
		parent, ok := trace.ParentOf(&cur)
		if !ok {
			break
		}
		chain = append(chain, parent)
		cur = parent
	}
	t.Logf("%s (%d spans):", label, len(chain))
	for i := len(chain) - 1; i >= 0; i-- {
		svc, kind, parentID := spanMeta(trace, &chain[i])
		t.Logf("%s[%s]%s op=%s span_id=[%s] parent_span_id=[%s]",
			strings.Repeat("  ", len(chain)-1-i), svc, kind, chain[i].OperationName, chain[i].SpanID, parentID)
	}
}

func logAllSpans(t *testing.T, trace jaeger.Trace) {
	for i := range trace.Spans {
		svc, kind, parentID := spanMeta(trace, &trace.Spans[i])
		t.Logf("  svc=%s%s op=%s span_id=%s parent_id=%s",
			svc, kind, trace.Spans[i].OperationName, trace.Spans[i].SpanID, parentID)
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
