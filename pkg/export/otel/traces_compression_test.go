// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/stats"

	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"go.opentelemetry.io/otel"

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
	exp, err := getTracesExporter(context.Background(), cfg, imetrics.NoopReporter{})
	require.NoError(t, err)
	require.NoError(t, exp.Start(context.Background()))
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
		name              string
		compression       string
		commonCompression string
		wantHeader        string
	}{
		{name: "unset sends uncompressed", compression: "", wantHeader: ""},
		{name: "gzip compresses", compression: "gzip", wantHeader: "gzip"},
		{name: "none is explicit off", compression: "none", wantHeader: ""},
		{name: "none overrides common gzip", compression: "none", commonCompression: "gzip", wantHeader: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_COMPRESSION", tc.commonCompression)
			var got atomic.Pointer[string]
			coll := collectorRecordingEncoding(t, &got)

			cfg := baseTracesConfig(coll.URL)
			cfg.CommonCompression = tc.commonCompression
			cfg.TracesCompression = tc.compression
			exportOneSpan(t, cfg)

			require.Eventually(t, func() bool { return got.Load() != nil }, 5*time.Second, 20*time.Millisecond,
				"the collector never received an export")
			assert.Equal(t, tc.wantHeader, *got.Load())
		})
	}
}

func TestTracesCompressionTracesKeyWinsOverCommon(t *testing.T) {
	var got atomic.Pointer[string]
	coll := collectorRecordingEncoding(t, &got)

	cfg := baseTracesConfig(coll.URL)
	cfg.CommonCompression = "none"
	cfg.TracesCompression = "gzip"
	exportOneSpan(t, cfg)

	require.Eventually(t, func() bool { return got.Load() != nil }, 5*time.Second, 20*time.Millisecond,
		"the collector never received an export")
	assert.Equal(t, "gzip", *got.Load(), "the traces-specific setting must win")
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
		name              string
		compression       string
		commonCompression string
		wantEncoding      string
	}{
		{name: "unset sends uncompressed", compression: "", wantEncoding: ""},
		{name: "gzip compresses", compression: "gzip", wantEncoding: "gzip"},
		{name: "none is explicit off", compression: "none", wantEncoding: encoding.Identity},
		{name: "none overrides common gzip", compression: "none", commonCompression: "gzip", wantEncoding: encoding.Identity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_COMPRESSION", tc.commonCompression)
			previousHandler := otel.GetErrorHandler()
			var errorCalls atomic.Int64
			otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
				if strings.Contains(err.Error(), "invalid compression type:") {
					errorCalls.Add(1)
				}
			}))
			t.Cleanup(func() {
				otel.SetErrorHandler(previousHandler)
				require.Zero(t, errorCalls.Load(), "the client must not report an invalid compression option")
			})

			lis, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			handler := &encodingStatsHandler{}
			srv := grpc.NewServer(grpc.StatsHandler(handler))
			ptraceotlp.RegisterGRPCServer(srv, &otlpTraceGRPCServer{})
			go func() { _ = srv.Serve(lis) }()
			t.Cleanup(srv.Stop)

			cfg := baseTracesConfig("http://" + lis.Addr().String())
			cfg.Protocol = otelcfg.ProtocolGRPC
			cfg.CommonCompression = tc.commonCompression
			cfg.TracesCompression = tc.compression
			exportOneSpan(t, cfg)

			require.Eventually(t, func() bool { return handler.got.Load() != nil }, 5*time.Second, 20*time.Millisecond,
				"the collector never received an export")
			assert.Equal(t, tc.wantEncoding, *handler.got.Load())
		})
	}
}
