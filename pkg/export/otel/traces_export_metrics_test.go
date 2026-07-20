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

type countingTracesReporter struct {
	imetrics.NoopReporter
	exports    atomic.Int64
	exportErrs atomic.Int64
}

func (c *countingTracesReporter) OTELTraceExport(spans int)  { c.exports.Add(int64(spans)) }
func (c *countingTracesReporter) OTELTraceExportError(error) { c.exportErrs.Add(1) }

func oneSpan() ptrace.Traces {
	traces := ptrace.NewTraces()
	traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty().SetName("test")
	return traces
}

func TestTracesExportInternalMetrics(t *testing.T) {
	t.Run("successful export is counted", func(t *testing.T) {
		coll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer coll.Close()

		rep := &countingTracesReporter{}
		// queue/batcher enabled so the export exercises the async send path
		cfg := otelcfg.TracesConfig{
			CommonEndpoint:   coll.URL,
			Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
			BatchMaxSize:     1,
			QueueSize:        2,
			BatchTimeout:     10 * time.Millisecond,
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
		coll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		deadEndpoint := coll.URL
		coll.Close()

		rep := &countingTracesReporter{}
		// queue/batcher enabled so the export exercises the async send path
		cfg := otelcfg.TracesConfig{
			CommonEndpoint:         deadEndpoint,
			Instrumentations:       []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
			BatchMaxSize:           1,
			QueueSize:              2,
			BatchTimeout:           10 * time.Millisecond,
			BackOffInitialInterval: 10 * time.Millisecond,
			BackOffMaxInterval:     10 * time.Millisecond,
			BackOffMaxElapsedTime:  100 * time.Millisecond,
		}
		exp, host, err := getTracesExporter(context.Background(), cfg, rep)
		require.NoError(t, err)
		require.NoError(t, exp.Start(context.Background(), host))
		t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })

		_ = exp.ConsumeTraces(context.Background(), oneSpan())

		require.Eventually(t, func() bool { return rep.exportErrs.Load() > 0 }, 5*time.Second, 20*time.Millisecond,
			"a failed export must increment obi.otel.trace.export.errors")
		assert.Zero(t, rep.exports.Load(), "a failed export must not increment obi.otel.trace.exports")
	})
}
