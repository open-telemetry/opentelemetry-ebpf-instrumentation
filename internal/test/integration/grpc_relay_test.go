// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"path"
	"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

const (
	// Known trace ID sent via the traceparent HTTP header to the first hop.
	// We query Jaeger for this exact ID and expect it on the last hop.
	relayTraceID = "abcdef1234567890abcdef1234567890"
	relaySpanID  = "1234567890abcdef"
)

// expectedRelayServices lists all services in the gRPC relay chain:
// Go (HTTP entry) -> Python -> Rust -> Node.js -> Java -> Go (gRPC terminal)
var expectedRelayServices = []string{
	"go-entry",
	"python-relay",
	"rust-relay",
	"nodejs-relay",
	"java-relay",
	"go-terminal",
}

// TestSuite_GRPCRelayChainHeaders validates end-to-end gRPC context propagation
// by sending a known traceparent to the first Go hop and verifying it arrives
// at the last hop with the same trace ID.
func TestSuite_GRPCRelayChainHeaders(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-grpc-relay.yml", path.Join(pathOutput, "test-suite-grpc-relay-chain-headers.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `OTEL_EBPF_BPF_CONTEXT_PROPAGATION=headers`)
	require.NoError(t, compose.Up())

	waitForTestComponentsNoMetrics(t, "http://localhost:8080/smoke")

	t.Run("gRPC relay chain context propagation (headers)", testGRPCRelayChainContextPropagation)

	require.NoError(t, compose.Close())
}

func TestSuite_GRPCRelayChainTCP(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-grpc-relay.yml", path.Join(pathOutput, "test-suite-grpc-relay-chain-tcp.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `OTEL_EBPF_BPF_CONTEXT_PROPAGATION=tcp`)
	require.NoError(t, compose.Up())

	waitForTestComponentsNoMetrics(t, "http://localhost:8080/smoke")

	t.Run("gRPC relay chain context propagation (tcp)", testGRPCRelayChainContextPropagation)

	require.NoError(t, compose.Close())
}

func testGRPCRelayChainContextPropagation(t *testing.T) {
	// Wait for OBI to instrument go-entry (spans visible in Jaeger).
	t.Log("waiting for instrumentation to be ready")
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, "http://localhost:8080/smoke", 200)

		resp, err := http.Get(jaegerQueryURL + "?service=go-entry&limit=1")
		if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
			return
		}
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		require.NotEmpty(ct, tq.Data)
	}, time.Minute, time.Second)
	t.Log("instrumentation ready")

	// Send a single request with a known traceparent to go-entry, then
	// poll Jaeger until the trace has propagated through all services.
	// Sending once (rather than inside EventuallyWithT) avoids duplicate
	// spans accumulating under the same trace ID on each retry.
	traceparent := "00-" + relayTraceID + "-" + relaySpanID + "-01"

	req, err := http.NewRequest("GET", "http://localhost:8080/relay", nil)
	require.NoError(t, err)
	req.Header.Set("Traceparent", traceparent)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Query Jaeger for our exact trace ID.
		resp, err := http.Get(jaegerQueryURL + "/" + relayTraceID)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		require.NotEmpty(ct, tq.Data)

		// Pick the trace and check it spans all expected services.
		trace = tq.Data[0]
		svcs := traceServices(trace)
		for _, svc := range expectedRelayServices {
			require.Contains(ct, svcs, svc, "trace missing service %s", svc)
		}
	}, testTimeout, time.Second)

	// All spans must carry the trace ID we injected.
	for _, span := range trace.Spans {
		require.Equal(t, relayTraceID, span.TraceID,
			"all spans in the relay chain must carry the injected trace ID")
	}

	// Verify gRPC server/client span counts.
	relayServerSpans := trace.FindByOperationName("/relay.Relay/Relay", "server")
	relayClientSpans := trace.FindByOperationName("/relay.Relay/Relay", "client")
	assert.GreaterOrEqual(t, len(relayServerSpans), 5,
		"should have at least 5 gRPC server spans (one per relay hop)")
	assert.GreaterOrEqual(t, len(relayClientSpans), 5,
		"should have at least 5 gRPC client spans (one per relay hop)")

	// Each gRPC server span's parent should be a client span.
	for _, serverSpan := range relayServerSpans {
		parent, ok := trace.ParentOf(&serverSpan)
		if ok {
			sd := parent.Diff(jaeger.Tag{Key: "span.kind", Type: "string", Value: "client"})
			assert.Empty(t, sd, "gRPC server span's parent should be a client span: %s", sd.String())
		}
	}

	// Verify the parent chain: service[i]'s client span_id == service[i+1]'s
	// server span's parent_id, for every consecutive pair in the relay chain.
	// The chain is: go-entry(client) -> python(server/client) -> ... -> go-terminal(server)
	relayHops := expectedRelayServices[1:] // python-relay through go-terminal have server spans
	for i, svc := range relayHops {
		serverSpans := trace.FindByOperationNameServiceAndKind("/relay.Relay/Relay", svc, "server")
		require.NotEmpty(t, serverSpans, "expected server span for %s", svc)

		serverSpan := serverSpans[0]
		parent, ok := trace.ParentOf(&serverSpan)
		require.True(t, ok, "%s server span should have a parent", svc)

		// The parent must be a client span from the previous service in the chain.
		prevSvc := expectedRelayServices[i] // i is offset by 1 due to relayHops = [1:]
		proc, procOK := trace.Processes[parent.ProcessID]
		require.True(t, procOK)
		assert.Equal(t, prevSvc, proc.ServiceName,
			"%s's server span parent should be a client span from %s", svc, prevSvc)
	}

	t.Logf("trace %s: %d spans across %d services",
		trace.TraceID, len(trace.Spans), len(traceServices(trace)))

	// Print per-span summary: [serviceName] -> trace_id=[traceID] span_id=[spanID]
	for _, span := range trace.Spans {
		svcName := "unknown"
		if proc, ok := trace.Processes[span.ProcessID]; ok {
			svcName = proc.ServiceName
		}
		kind := ""
		for _, tag := range span.Tags {
			if tag.Key == "span.kind" {
				kind = fmt.Sprintf(" (%v)", tag.Value)
			}
		}
		parentID := ""
		for _, ref := range span.References {
			if ref.RefType == "CHILD_OF" {
				parentID = ref.SpanID
			}
		}
		t.Logf("[%s]%s -> trace_id=[%s] span_id=[%s] parent_id=[%s]", svcName, kind, span.TraceID, span.SpanID, parentID)
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
