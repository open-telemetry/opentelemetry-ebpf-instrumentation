// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

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
	reporter := &countingTracesReporter{}
	exp, err := getTracesExporter(context.Background(), cfg, reporter)
	require.NoError(t, err)
	require.NoError(t, exp.Start(context.Background()))
	defer func() { require.NoError(t, exp.Shutdown(context.Background())) }()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	require.NoError(t, exp.ConsumeTraces(ctx, oneSpan()))
	require.EqualValues(t, 2, attempts.Load())
	require.EqualValues(t, 1, reporter.exportErrs.Load())
	require.EqualValues(t, 1, reporter.exports.Load())
}

func TestHTTPTraceClientRetainsCertificateWithAttemptMetrics(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	certPath := filepath.Join(t.TempDir(), "collector.pem")
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	require.NoError(t, os.WriteFile(certPath, cert, 0o600))
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE", certPath)

	reporter := &countingTracesReporter{}
	exp, err := getTracesExporter(t.Context(), otelcfg.TracesConfig{CommonEndpoint: server.URL}, reporter)
	require.NoError(t, err)
	require.NoError(t, exp.Start(t.Context()))
	defer func() { require.NoError(t, exp.Shutdown(context.Background())) }()
	require.NoError(t, exp.ConsumeTraces(t.Context(), oneSpan()))
	require.EqualValues(t, 1, reporter.exports.Load())
	require.Zero(t, reporter.exportErrs.Load())
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
	reporter := &countingTracesReporter{}
	exp, err := getTracesExporter(context.Background(), cfg, reporter)
	require.NoError(t, err)
	require.NoError(t, exp.Start(context.Background()))
	defer func() { require.NoError(t, exp.Shutdown(context.Background())) }()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	require.NoError(t, exp.ConsumeTraces(ctx, oneSpan()))
	require.EqualValues(t, 2, receiver.attempts.Load())
	require.EqualValues(t, 1, reporter.exportErrs.Load())
	require.EqualValues(t, 1, reporter.exports.Load())
}

func fastRetryTracesConfig(endpoint string) otelcfg.TracesConfig {
	return otelcfg.TracesConfig{
		CommonEndpoint:         endpoint,
		BackOffInitialInterval: 10 * time.Millisecond,
		BackOffMaxInterval:     10 * time.Millisecond,
		BackOffMaxElapsedTime:  5 * time.Second,
		InjectHeaders:          func(dst map[string]string) { dst["X-Test"] = "obi" },
	}
}

func TestHTTPTraceClientRetriesByStatus(t *testing.T) {
	for _, tc := range []struct {
		name         string
		firstStatus  int
		wantAttempts int32
		wantErr      string
	}{
		{name: "unavailable is retried", firstStatus: http.StatusServiceUnavailable, wantAttempts: 2},
		{name: "too many requests is retried", firstStatus: http.StatusTooManyRequests, wantAttempts: 2},
		{name: "bad request is permanent", firstStatus: http.StatusBadRequest, wantAttempts: 1, wantErr: "400 Bad Request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts atomic.Int32
			var headers atomic.Pointer[http.Header]
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				headers.Store(&r.Header)
				if attempts.Add(1) == 1 {
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(tc.firstStatus)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			exp, err := getTracesExporter(t.Context(), fastRetryTracesConfig(server.URL), nil)
			require.NoError(t, err)
			require.NoError(t, exp.Start(t.Context()))
			defer func() { require.NoError(t, exp.Shutdown(context.Background())) }()

			err = exp.ConsumeTraces(t.Context(), oneSpan())
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}
			require.Equal(t, tc.wantAttempts, attempts.Load())
			require.Equal(t, "obi", headers.Load().Get("X-Test"))
			require.Equal(t, traceContentTypeProto, headers.Load().Get("Content-Type"))
			require.Equal(t, traceUserAgent, headers.Load().Get("User-Agent"))
		})
	}
}

type failingTraceGRPCServer struct {
	ptraceotlp.UnimplementedGRPCServer
	firstErr error
	attempts atomic.Int32
	header   atomic.Pointer[[]string]
}

func (s *failingTraceGRPCServer) Export(ctx context.Context, _ ptraceotlp.ExportRequest) (ptraceotlp.ExportResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("x-test")
	s.header.Store(&values)
	if s.attempts.Add(1) == 1 {
		return ptraceotlp.NewExportResponse(), s.firstErr
	}
	return ptraceotlp.NewExportResponse(), nil
}

func TestGRPCTraceClientRetriesByCode(t *testing.T) {
	throttled, err := status.New(codes.ResourceExhausted, "busy").
		WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(10 * time.Millisecond)})
	require.NoError(t, err)

	for _, tc := range []struct {
		name         string
		firstErr     error
		wantAttempts int32
		wantErr      string
	}{
		{name: "unavailable is retried", firstErr: status.Error(codes.Unavailable, "down"), wantAttempts: 2},
		{name: "throttled exhaustion is retried", firstErr: throttled.Err(), wantAttempts: 2},
		{name: "exhaustion without retry info is permanent", firstErr: status.Error(codes.ResourceExhausted, "full"), wantAttempts: 1, wantErr: "full"},
		{name: "invalid argument is permanent", firstErr: status.Error(codes.InvalidArgument, "bad"), wantAttempts: 1, wantErr: "bad"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			server := grpc.NewServer()
			receiver := &failingTraceGRPCServer{firstErr: tc.firstErr}
			ptraceotlp.RegisterGRPCServer(server, receiver)
			go func() { _ = server.Serve(listener) }()
			defer server.Stop()

			cfg := fastRetryTracesConfig("http://" + listener.Addr().String())
			cfg.Protocol = otelcfg.ProtocolGRPC
			exp, err := getTracesExporter(t.Context(), cfg, nil)
			require.NoError(t, err)
			require.NoError(t, exp.Start(t.Context()))
			defer func() { require.NoError(t, exp.Shutdown(context.Background())) }()

			err = exp.ConsumeTraces(t.Context(), oneSpan())
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}
			require.Equal(t, tc.wantAttempts, receiver.attempts.Load())
			require.Equal(t, []string{"obi"}, *receiver.header.Load())
		})
	}
}

func retryAfterOneFailure(throttle time.Duration) (func(context.Context) error, *atomic.Int32) {
	var attempts atomic.Int32
	return func(context.Context) error {
		if attempts.Add(1) == 1 {
			return retryableTraceError{err: errors.New("busy"), throttle: throttle}
		}
		return nil
	}, &attempts
}

func TestTraceRetryThrottleIsAMinimumDelay(t *testing.T) {
	const backoffInterval = 200 * time.Millisecond
	// The backoff is randomized by up to half its interval in either direction.
	const shortestBackoff = backoffInterval / 2
	const longThrottle = 400 * time.Millisecond

	for _, tc := range []struct {
		name        string
		throttle    time.Duration
		wantAtLeast time.Duration
	}{
		{name: "shorter throttle keeps the backoff", throttle: time.Millisecond, wantAtLeast: shortestBackoff},
		{name: "longer throttle extends the wait", throttle: longThrottle, wantAtLeast: longThrottle},
	} {
		t.Run(tc.name, func(t *testing.T) {
			retry := traceRetry{initialInterval: backoffInterval, maxInterval: backoffInterval, maxElapsedTime: 5 * time.Second}
			attempt, attempts := retryAfterOneFailure(tc.throttle)

			start := time.Now()
			require.NoError(t, retry.do(t.Context(), attempt))
			require.EqualValues(t, 2, attempts.Load())
			require.GreaterOrEqual(t, time.Since(start), tc.wantAtLeast)
		})
	}
}

func TestTraceRetryKeepsLastErrorWhenContextEnds(t *testing.T) {
	retry := traceRetry{initialInterval: time.Second, maxInterval: time.Second, maxElapsedTime: time.Minute}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	err := retry.do(ctx, func(context.Context) error {
		return retryableTraceError{err: errors.New("collector unavailable")}
	})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorContains(t, err, "collector unavailable")
}

func TestTraceClientsRejectUnreadableCertificate(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE", filepath.Join(t.TempDir(), "missing.pem"))

	for _, protocol := range []otelcfg.Protocol{otelcfg.ProtocolHTTPProtobuf, otelcfg.ProtocolGRPC} {
		t.Run(string(protocol), func(t *testing.T) {
			cfg := otelcfg.TracesConfig{CommonEndpoint: "https://collector.example:4318", Protocol: protocol}
			_, err := getTracesExporter(t.Context(), cfg, nil)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
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
		TracesExport: func(context.Context, ptrace.Traces) error {
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
	var batchesMu sync.Mutex
	var batches []ptrace.Traces
	exp := newOBITracesExporter(cfg, nil, func(_ context.Context, traces ptrace.Traces) error {
		batchesMu.Lock()
		defer batchesMu.Unlock()
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
	counts := []int{batches[0].SpanCount(), batches[1].SpanCount()}
	require.ElementsMatch(t, []int{4, 2}, counts)
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

func TestTraceQueueExportsBatchesConcurrently(t *testing.T) {
	cfg := otelcfg.TracesConfig{QueueSize: 20, BatchMaxSize: 1}
	started := make(chan struct{}, defaultTraceWorkers+1)
	release := make(chan struct{})
	exp := newOBITracesExporter(cfg, nil, func(ctx context.Context, _ ptrace.Traces) error {
		started <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, nil)
	require.NoError(t, exp.Start(t.Context()))
	defer func() {
		close(release)
		require.NoError(t, exp.Shutdown(context.Background()))
	}()

	for range defaultTraceWorkers + 1 {
		require.NoError(t, exp.ConsumeTraces(t.Context(), oneSpan()))
	}
	for range defaultTraceWorkers {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("trace batches were not exported concurrently")
		}
	}
	select {
	case <-started:
		t.Fatal("trace exporter exceeded its worker limit")
	default:
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
