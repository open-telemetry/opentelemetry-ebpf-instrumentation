// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"

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

type otlpTraceGRPCServer struct {
	ptraceotlp.UnimplementedGRPCServer
}

func (*otlpTraceGRPCServer) Export(context.Context, ptraceotlp.ExportRequest) (ptraceotlp.ExportResponse, error) {
	return ptraceotlp.NewExportResponse(), nil
}

// startOTLPTraceGRPCServer starts an in-process OTLP/gRPC trace receiver that
// accepts every export, returning its "http://host:port" endpoint.
func startOTLPTraceGRPCServer(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	ptraceotlp.RegisterGRPCServer(srv, &otlpTraceGRPCServer{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return "http://" + lis.Addr().String()
}

func TestTracesExportInternalMetrics(t *testing.T) {
	t.Run("HTTP successful export is counted", func(t *testing.T) {
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

	t.Run("HTTP failed export is counted", func(t *testing.T) {
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

	t.Run("gRPC successful export is counted", func(t *testing.T) {
		rep := &countingTracesReporter{}
		// queue/batcher enabled so the export exercises the async send path
		cfg := otelcfg.TracesConfig{
			CommonEndpoint:   startOTLPTraceGRPCServer(t),
			Protocol:         otelcfg.ProtocolGRPC,
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
			"a successful gRPC export must increment obi.otel.trace.exports")
		assert.Zero(t, rep.exportErrs.Load(), "a successful gRPC export must not increment obi.otel.trace.export.errors")
	})

	t.Run("gRPC failed export is counted", func(t *testing.T) {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		deadEndpoint := "http://" + lis.Addr().String()
		require.NoError(t, lis.Close())

		rep := &countingTracesReporter{}
		// queue/batcher enabled so the export exercises the async send path
		cfg := otelcfg.TracesConfig{
			CommonEndpoint:         deadEndpoint,
			Protocol:               otelcfg.ProtocolGRPC,
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
			"a failed gRPC export must increment obi.otel.trace.export.errors")
		assert.Zero(t, rep.exports.Load(), "a failed gRPC export must not increment obi.otel.trace.exports")
	})
}
