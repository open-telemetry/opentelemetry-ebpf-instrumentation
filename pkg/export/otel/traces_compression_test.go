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
	"google.golang.org/grpc/stats"

	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

func collectorRecordingEncoding(t *testing.T, got *atomic.Pointer[string]) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enc := r.Header.Get("Content-Encoding")
		got.CompareAndSwap(nil, &enc)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func exportOneSpan(t *testing.T, cfg otelcfg.TracesConfig) {
	t.Helper()
	exp, host, err := getTracesExporter(context.Background(), cfg, imetrics.NoopReporter{})
	require.NoError(t, err)
	require.NoError(t, exp.Start(context.Background(), host))
	t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })
	require.NoError(t, exp.ConsumeTraces(context.Background(), oneSpan()))
}

func baseTracesConfig(endpoint string) otelcfg.TracesConfig {
	return otelcfg.TracesConfig{
		CommonEndpoint:   endpoint,
		Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
		BatchMaxSize:     1,
		QueueSize:        2,
		BatchTimeout:     10 * time.Millisecond,
	}
}

func TestTracesExportCompressionHTTP(t *testing.T) {
	for _, tc := range []struct {
		name        string
		compression string
		wantHeader  string
	}{
		{name: "default is the exporter's own gzip", compression: "", wantHeader: "gzip"},
		{name: "explicit gzip", compression: "gzip", wantHeader: "gzip"},
		{name: "none disables it", compression: "none", wantHeader: ""},
		{name: "zstd is passed through", compression: "zstd", wantHeader: "zstd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got atomic.Pointer[string]
			coll := collectorRecordingEncoding(t, &got)

			cfg := baseTracesConfig(coll.URL)
			cfg.TracesCompression = tc.compression
			exportOneSpan(t, cfg)

			require.Eventually(t, func() bool { return got.Load() != nil }, 5*time.Second, 20*time.Millisecond,
				"the collector never received an export")
			assert.Equal(t, tc.wantHeader, *got.Load())
		})
	}
}

func TestTracesExportCompressionRejectsUnknownValue(t *testing.T) {
	for _, protocol := range []otelcfg.Protocol{otelcfg.ProtocolHTTPProtobuf, otelcfg.ProtocolGRPC} {
		t.Run(string(protocol), func(t *testing.T) {
			cfg := baseTracesConfig("http://127.0.0.1:1")
			cfg.Protocol = protocol
			cfg.TracesCompression = "not-a-codec"
			_, _, err := getTracesExporter(context.Background(), cfg, imetrics.NoopReporter{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not-a-codec")
		})
	}
}

func TestTracesCompressionTracesKeyWinsOverCommon(t *testing.T) {
	var got atomic.Pointer[string]
	coll := collectorRecordingEncoding(t, &got)

	cfg := baseTracesConfig(coll.URL)
	cfg.CommonCompression = "gzip"
	cfg.TracesCompression = "none"
	exportOneSpan(t, cfg)

	require.Eventually(t, func() bool { return got.Load() != nil }, 5*time.Second, 20*time.Millisecond,
		"the collector never received an export")
	assert.Empty(t, *got.Load(), "the traces-specific setting must win")
}

// grpc-encoding is consumed by the transport, so it is absent from the handler's
// metadata. stats.InHeader.Compression carries it.
type encodingStatsHandler struct {
	got atomic.Pointer[string]
}

func (h *encodingStatsHandler) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}

func (h *encodingStatsHandler) HandleRPC(_ context.Context, s stats.RPCStats) {
	inHeader, ok := s.(*stats.InHeader)
	if !ok {
		return
	}
	enc := inHeader.Compression
	h.got.CompareAndSwap(nil, &enc)
}

func (h *encodingStatsHandler) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}

func (h *encodingStatsHandler) HandleConn(context.Context, stats.ConnStats) {}

func TestTracesExportCompressionGRPC(t *testing.T) {
	for _, tc := range []struct {
		name         string
		compression  string
		wantEncoding string
	}{
		{name: "default is the exporter's own gzip", compression: "", wantEncoding: "gzip"},
		{name: "none disables it", compression: "none", wantEncoding: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			handler := &encodingStatsHandler{}
			srv := grpc.NewServer(grpc.StatsHandler(handler))
			ptraceotlp.RegisterGRPCServer(srv, &otlpTraceGRPCServer{})
			go func() { _ = srv.Serve(lis) }()
			t.Cleanup(srv.Stop)

			cfg := baseTracesConfig("http://" + lis.Addr().String())
			cfg.Protocol = otelcfg.ProtocolGRPC
			cfg.TracesCompression = tc.compression
			exportOneSpan(t, cfg)

			require.Eventually(t, func() bool { return handler.got.Load() != nil }, 5*time.Second, 20*time.Millisecond,
				"the collector never received an export")
			assert.Equal(t, tc.wantEncoding, *handler.got.Load())
		})
	}
}
