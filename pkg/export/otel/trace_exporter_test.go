// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"

	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

func TestOTLPTraceClientReportsPartialSuccess(t *testing.T) {
	received := make(chan ptrace.Traces, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		request := ptraceotlp.NewExportRequest()
		if err := request.UnmarshalProto(data); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		received <- request.Traces()

		response := ptraceotlp.NewExportResponse()
		response.PartialSuccess().SetRejectedSpans(1)
		data, err = response.MarshalProto()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(data)
	}))
	defer server.Close()

	cfg := otelcfg.TracesConfig{CommonEndpoint: server.URL}
	exp, err := getTracesExporter(context.Background(), cfg, nil)
	require.NoError(t, err)
	require.NoError(t, exp.Start(context.Background()))
	defer func() { require.NoError(t, exp.Shutdown(context.Background())) }()

	require.ErrorContains(t, exp.ConsumeTraces(context.Background(), oneSpan()), "1 spans rejected")
	require.Equal(t, "test", (<-received).ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Name())
}

func TestHTTPTraceClientRetriesStalledRequest(t *testing.T) {
	var attempts atomic.Int32
	releaseFirst := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			<-releaseFirst
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer func() {
		close(releaseFirst)
		server.Close()
	}()

	cfg := otelcfg.TracesConfig{
		CommonEndpoint:         server.URL,
		BackOffInitialInterval: 10 * time.Millisecond,
		BackOffMaxInterval:     10 * time.Millisecond,
		BackOffMaxElapsedTime:  12 * time.Second,
	}
	exp, err := getTracesExporter(context.Background(), cfg, nil)
	require.NoError(t, err)
	require.NoError(t, exp.Start(context.Background()))
	defer func() { require.NoError(t, exp.Shutdown(context.Background())) }()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	require.NoError(t, exp.ConsumeTraces(ctx, oneSpan()))
	require.EqualValues(t, 2, attempts.Load())
}

type stalledTraceGRPCServer struct {
	ptraceotlp.UnimplementedGRPCServer
	attempts atomic.Int32
}

func (s *stalledTraceGRPCServer) Export(ctx context.Context, _ ptraceotlp.ExportRequest) (ptraceotlp.ExportResponse, error) {
	if s.attempts.Add(1) == 1 {
		<-ctx.Done()
		return ptraceotlp.NewExportResponse(), ctx.Err()
	}
	return ptraceotlp.NewExportResponse(), nil
}

func TestGRPCTraceClientRetriesStalledRequest(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	receiver := &stalledTraceGRPCServer{}
	ptraceotlp.RegisterGRPCServer(server, receiver)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()

	cfg := otelcfg.TracesConfig{
		CommonEndpoint:         "http://" + listener.Addr().String(),
		Protocol:               otelcfg.ProtocolGRPC,
		BackOffInitialInterval: 10 * time.Millisecond,
		BackOffMaxInterval:     10 * time.Millisecond,
		BackOffMaxElapsedTime:  12 * time.Second,
	}
	exp, err := getTracesExporter(context.Background(), cfg, nil)
	require.NoError(t, err)
	require.NoError(t, exp.Start(context.Background()))
	defer func() { require.NoError(t, exp.Shutdown(context.Background())) }()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	require.NoError(t, exp.ConsumeTraces(ctx, oneSpan()))
	require.EqualValues(t, 2, receiver.attempts.Load())
}

func TestTraceQueueCountsSpansAndUnblocksOnShutdown(t *testing.T) {
	cfg := otelcfg.TracesConfig{QueueSize: 2}
	exp := newOBITracesExporter(cfg, nil, func(context.Context, ptrace.Traces) error {
		return nil
	}, nil)

	traces := ptrace.NewTraces()
	spans := traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans()
	spans.AppendEmpty()
	spans.AppendEmpty()
	require.NoError(t, exp.ConsumeTraces(context.Background(), traces))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, exp.ConsumeTraces(ctx, oneSpan()), context.DeadlineExceeded)

	done := make(chan error, 1)
	go func() { done <- exp.ConsumeTraces(context.Background(), oneSpan()) }()
	require.NoError(t, exp.Shutdown(context.Background()))
	select {
	case err := <-done:
		require.True(t, errors.Is(err, context.Canceled) || err.Error() == "trace exporter is shut down")
	case <-time.After(time.Second):
		t.Fatal("producer remained blocked after shutdown")
	}
}

func TestTraceQueueFlushesAfterPipelineCancellation(t *testing.T) {
	cfg := otelcfg.TracesConfig{
		QueueSize:    2,
		BatchMaxSize: 2,
		BatchTimeout: time.Hour,
	}
	var sentSpans int
	var sendErr error
	exp := newOBITracesExporter(cfg, nil, func(ctx context.Context, traces ptrace.Traces) error {
		sentSpans = traces.SpanCount()
		sendErr = ctx.Err()
		return sendErr
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, exp.Start(ctx))
	require.NoError(t, exp.ConsumeTraces(ctx, oneSpan()))
	cancel()
	shutdownCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	require.NoError(t, exp.Shutdown(shutdownCtx))

	require.Equal(t, 1, sentSpans)
	require.NoError(t, sendErr)
}

func TestTraceCallbackDoesNotBatch(t *testing.T) {
	called := false
	cfg := otelcfg.TracesConfig{
		TracesExport: func(context.Context, []byte) error {
			called = true
			return nil
		},
		BatchMaxSize: 4096,
		BatchTimeout: 15 * time.Second,
		QueueSize:    16384,
	}
	exp, err := getTracesExporter(context.Background(), cfg, nil)
	require.NoError(t, err)
	require.NoError(t, exp.Start(context.Background()))
	defer func() { require.NoError(t, exp.Shutdown(context.Background())) }()

	require.NoError(t, exp.ConsumeTraces(context.Background(), oneSpan()))
	require.True(t, called)
}

func TestTraceQueueSplitsAtBatchLimit(t *testing.T) {
	cfg := otelcfg.TracesConfig{QueueSize: 8, BatchMaxSize: 4, BatchTimeout: time.Hour}
	var batches []ptrace.Traces
	exp := newOBITracesExporter(cfg, nil, func(_ context.Context, traces ptrace.Traces) error {
		batches = append(batches, traces)
		return nil
	}, nil)
	require.NoError(t, exp.Start(context.Background()))

	traces := ptrace.NewTraces()
	resource := traces.ResourceSpans().AppendEmpty()
	resource.SetSchemaUrl("resource-schema")
	resource.Resource().Attributes().PutStr("service.name", "test")
	scope := resource.ScopeSpans().AppendEmpty()
	scope.SetSchemaUrl("scope-schema")
	scope.Scope().SetName("instrument")
	spans := scope.Spans()
	for range 3 {
		spans.AppendEmpty()
	}
	require.NoError(t, exp.ConsumeTraces(context.Background(), traces))
	require.NoError(t, exp.ConsumeTraces(context.Background(), traces))
	require.NoError(t, exp.Shutdown(context.Background()))
	require.Len(t, batches, 2)
	require.Equal(t, 4, batches[0].SpanCount())
	require.Equal(t, 2, batches[1].SpanCount())
	for _, batch := range batches {
		for _, gotResource := range batch.ResourceSpans().All() {
			require.Equal(t, "resource-schema", gotResource.SchemaUrl())
			name, ok := gotResource.Resource().Attributes().Get("service.name")
			require.True(t, ok)
			require.Equal(t, "test", name.Str())
			for _, gotScope := range gotResource.ScopeSpans().All() {
				require.Equal(t, "scope-schema", gotScope.SchemaUrl())
				require.Equal(t, "instrument", gotScope.Scope().Name())
			}
		}
	}
}

func TestTraceQueueShutdownHonorsDeadline(t *testing.T) {
	cfg := otelcfg.TracesConfig{QueueSize: 2, BatchMaxSize: 1}
	exp := newOBITracesExporter(cfg, nil, func(ctx context.Context, _ ptrace.Traces) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil)
	require.NoError(t, exp.Start(context.Background()))
	require.NoError(t, exp.ConsumeTraces(context.Background(), oneSpan()))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, exp.Shutdown(ctx), context.DeadlineExceeded)
}
