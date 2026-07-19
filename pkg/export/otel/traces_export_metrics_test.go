// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/ptrace"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

// countingTracesReporter records how many trace exports the instrumentation
// wrapper observed as successful vs failed. Embedding NoopReporter satisfies the
// rest of the imetrics.Reporter interface while keeping the type distinct from
// the builtin noop (so instrumentTracesExporter actually wraps it).
type countingTracesReporter struct {
	imetrics.NoopReporter
	exports    atomic.Int64
	exportErrs atomic.Int64
}

func (c *countingTracesReporter) OTELTraceExport(int)        { c.exports.Add(1) }
func (c *countingTracesReporter) OTELTraceExportError(error) { c.exportErrs.Add(1) }

func oneSpan() ptrace.Traces {
	traces := ptrace.NewTraces()
	traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty().SetName("test")
	return traces
}

// TestTracesExportInternalMetrics verifies that obi.otel.trace.export(.errors)
// reflect the real OTLP send outcome rather than the exporter sending-queue's
// enqueue result. The instrumentation wraps a synchronous exporter beneath the
// queue/retry, so a reachable collector records a success and an unreachable one
// records an error.
func TestTracesExportInternalMetrics(t *testing.T) {
	t.Run("successful export is counted", func(t *testing.T) {
		coll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer coll.Close()

		rep := &countingTracesReporter{}
		cfg := otelcfg.TracesConfig{
			CommonEndpoint:   coll.URL,
			Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
		}
		exp, host, err := getTracesExporter(context.Background(), cfg, rep)
		require.NoError(t, err)
		require.NoError(t, exp.Start(context.Background(), host))
		t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })

		require.NoError(t, exp.ConsumeTraces(context.Background(), oneSpan()))

		require.Eventually(t, func() bool { return rep.exports.Load() > 0 }, 5*time.Second, 20*time.Millisecond,
			"a successful export must increment obi.otel.trace.exports")
		assert.Zero(t, rep.exportErrs.Load(), "a successful export must not increment obi.otel.trace.export.errors")
	})

	t.Run("failed export is counted", func(t *testing.T) {
		// Start then immediately stop a server so its address refuses connections.
		coll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		deadEndpoint := coll.URL
		coll.Close()

		rep := &countingTracesReporter{}
		cfg := otelcfg.TracesConfig{
			CommonEndpoint:   deadEndpoint,
			Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
			// Bound the retry so ConsumeTraces gives up quickly instead of
			// blocking on the default 5-minute backoff budget.
			BackOffInitialInterval: 10 * time.Millisecond,
			BackOffMaxInterval:     10 * time.Millisecond,
			BackOffMaxElapsedTime:  100 * time.Millisecond,
		}
		exp, host, err := getTracesExporter(context.Background(), cfg, rep)
		require.NoError(t, err)
		require.NoError(t, exp.Start(context.Background(), host))
		t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })

		// The send fails; ConsumeTraces surfaces the error after the bounded retry.
		_ = exp.ConsumeTraces(context.Background(), oneSpan())

		require.Eventually(t, func() bool { return rep.exportErrs.Load() > 0 }, 5*time.Second, 20*time.Millisecond,
			"a failed export must increment obi.otel.trace.export.errors")
		assert.Zero(t, rep.exports.Load(), "a failed export must not increment obi.otel.trace.exports")
	})
}
