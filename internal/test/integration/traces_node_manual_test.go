// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

// testHTTPTracesNodeManualSpans exercises the Node.js manual span bridge
// (OTEL_EBPF_NODEJS_MANUAL_SPANS): the /manual route creates spans through
// @opentelemetry/api with no SDK registered, so they only exist because OBI
// injected the span bridge. It asserts the spans are captured, carry their
// attributes/status, nest correctly among themselves, and are re-anchored
// onto the same trace as OBI's own automatic HTTP server span (parented
// under OBI's "processing" sub-span, which carries the in-flight request
// context that the bridge spans inherit).
func testHTTPTracesNodeManualSpans(t *testing.T) {
	for i := 0; i < 6; i++ {
		ti.DoHTTPGet(t, "http://localhost:3031/manual", 200)
	}

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=GET%20%2Fmanual")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/manual"})
		require.NotEmpty(ct, traces)
		// Pick a trace that actually carries the manual spans (a batch may
		// briefly surface the server span before the manual ones land).
		for i := range traces {
			if len(traces[i].FindByOperationName("checkout", "internal")) > 0 {
				trace = traces[i]
				return
			}
		}
		require.Fail(ct, "no trace with manual spans yet")
	}, testTimeout, 100*time.Millisecond)

	// OBI's automatic HTTP server span (from kprobes).
	res := trace.FindByOperationName("GET /manual", "server")
	require.Len(t, res, 1)
	server := res[0]
	require.NotEmpty(t, server.TraceID)
	traceID := server.TraceID

	// OBI's automatic "processing" sub-span: a child of the server span whose
	// span id is the in-flight request context. Manual spans re-anchor here.
	res = trace.FindByOperationName("processing", "internal")
	require.Len(t, res, 1)
	processing := res[0]
	require.Equal(t, traceID, processing.TraceID)

	// "checkout" is the root manual span. It must share the automatic trace
	// and be re-anchored as a child of the "processing" sub-span — this is
	// the eBPF correlation via traces_ctx_v1, the whole point of the feature.
	res = trace.FindByOperationName("checkout", "internal")
	require.Len(t, res, 1)
	checkout := res[0]
	assert.Equal(t, traceID, checkout.TraceID, "manual span must join the automatic trace")
	p, ok := trace.ParentOf(&checkout)
	require.True(t, ok, "checkout must have a parent")
	assert.Equal(t, processing.SpanID, p.SpanID,
		"checkout must be re-anchored under OBI's automatic processing sub-span")
	sd := checkout.Diff(
		jaeger.Tag{Key: "cart.items", Type: "int64", Value: float64(3)},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "internal"},
	)
	assert.Empty(t, sd, sd.String())

	// "validate-cart": a plain (non-active) child of checkout.
	res = trace.FindByOperationName("validate-cart", "internal")
	require.Len(t, res, 1)
	validate := res[0]
	p, ok = trace.ParentOf(&validate)
	require.True(t, ok)
	assert.Equal(t, checkout.SpanID, p.SpanID, "validate-cart must be a child of checkout")
	sd = validate.Diff(
		jaeger.Tag{Key: "valid", Type: "bool", Value: bool(true)},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "internal"},
	)
	assert.Empty(t, sd, sd.String())

	// "charge-card": a nested active manual span, child of checkout, carrying
	// an integer attribute and an ERROR status.
	res = trace.FindByOperationName("charge-card", "internal")
	require.Len(t, res, 1)
	charge := res[0]
	p, ok = trace.ParentOf(&charge)
	require.True(t, ok)
	assert.Equal(t, checkout.SpanID, p.SpanID, "charge-card must be a child of checkout")
	sd = charge.Diff(
		jaeger.Tag{Key: "amount.cents", Type: "int64", Value: float64(4999)},
		jaeger.Tag{Key: "otel.status_code", Type: "string", Value: "ERROR"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "internal"},
	)
	assert.Empty(t, sd, sd.String())

	// "ledger-commit": renamed via updateName(); a child of charge-card.
	res = trace.FindByOperationName("ledger-commit", "internal")
	require.Len(t, res, 1)
	ledger := res[0]
	p, ok = trace.ParentOf(&ledger)
	require.True(t, ok)
	assert.Equal(t, charge.SpanID, p.SpanID, "ledger-commit must be a child of charge-card")
	sd = ledger.Diff(
		jaeger.Tag{Key: "account", Type: "string", Value: "acct-1"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "internal"},
	)
	assert.Empty(t, sd, sd.String())

	// The outgoing HTTP call made INSIDE "checkout" must produce an OBI
	// automatic (eBPF) client span that nests as a CHILD of "checkout" — not as
	// a sibling under the server span. This is the -mspan/ override feature:
	// while the manual span is active, OBI parents its automatic client spans
	// (and downstream traceparent propagation) under the manual span. Everything
	// stays in the one automatic trace with the correct server root.
	var clientChildren []jaeger.Span
	for _, c := range trace.ChildrenOf(checkout.SpanID) {
		if tag, ok := jaeger.FindIn(c.Tags, "span.kind"); ok && tag.Value == "client" {
			clientChildren = append(clientChildren, c)
		}
	}
	require.Len(t, clientChildren, 1,
		"the outgoing call inside checkout must nest as a client child of the manual span")
	client := clientChildren[0]
	assert.Equal(t, traceID, client.TraceID, "client span must join the automatic trace")
	if m, ok := jaeger.FindIn(client.Tags, "http.request.method"); ok {
		assert.Equal(t, "GET", m.Value, "the nested client span is the outgoing GET")
	}
}

// testHTTPTracesNodeManualBackgroundSpan covers the stale-context clear: the
// app runs a background timer that creates manual spans OUTSIDE any request
// context ("bg-tick"), overlapping a slow request (/manual-slow). Without the
// explicit no-request clear emitted by fdextractor's async hook, the kernel
// context map would still hold the in-flight request's trace context when a
// background span ends, mis-parenting it into that trace. The request's own
// manual span ("slow-op") must still re-anchor correctly afterwards.
func testHTTPTracesNodeManualBackgroundSpan(t *testing.T) {
	for i := 0; i < 3; i++ {
		ti.DoHTTPGet(t, "http://localhost:3031/manual-slow", 200)
	}

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=GET%20%2Fmanual-slow")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/manual-slow"})
		require.NotEmpty(ct, traces)
		for i := range traces {
			if len(traces[i].FindByOperationName("slow-op", "internal")) > 0 {
				trace = traces[i]
				return
			}
		}
		require.Fail(ct, "no trace with the slow-op manual span yet")
	}, testTimeout, 100*time.Millisecond)

	// The in-request manual span re-anchors onto the request trace even after
	// background callbacks cleared the kernel context in between.
	res := trace.FindByOperationName("slow-op", "internal")
	require.Len(t, res, 1)

	// Background spans that fired while this request was in flight must NOT be
	// pulled into its trace: the no-request clear removes the stale context
	// before they end.
	assert.Empty(t, trace.FindByOperationName("bg-tick", "internal"),
		"background span must not be parented into the request trace")

	// The background spans are still captured, on their own traces.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=bg-tick")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		require.NotEmpty(ct, tq.Data, "standalone background spans must still be exported")
		for i := range tq.Data {
			assert.Empty(ct, tq.Data[i].FindByOperationName("GET /manual-slow", "server"),
				"a bg-tick trace must not contain the slow request's server span")
		}
	}, testTimeout, 100*time.Millisecond)
}
