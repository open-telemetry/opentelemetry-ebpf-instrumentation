// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	grpcgzip "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

const (
	defaultTraceQueueSize      = 1000
	defaultTraceFlushDelay     = 200 * time.Millisecond
	defaultTraceRetryStart     = 5 * time.Second
	defaultTraceRetryMax       = 30 * time.Second
	defaultTraceRetryTotal     = 5 * time.Minute
	defaultTraceRequestTimeout = 5 * time.Second
)

type traceSender func(context.Context, ptrace.Traces) error

type queuedTraces struct {
	traces ptrace.Traces
	spans  int64
}

type tracesExporter interface {
	Start(context.Context) error
	Shutdown(context.Context) error
	ConsumeTraces(context.Context, ptrace.Traces) error
}

type obiTracesExporter struct {
	send          traceSender
	close         func() error
	reporter      imetrics.Reporter
	retry         bool
	retryStart    time.Duration
	retryMax      time.Duration
	retryTotal    time.Duration
	queue         chan queuedTraces
	queueSize     int64
	queueSlots    *semaphore.Weighted
	queueContext  context.Context
	queueCancel   context.CancelFunc
	queueMu       sync.RWMutex
	queueClosed   bool
	workerStarted bool
	batchMaxSize  int
	batchTimeout  time.Duration
	workerDone    chan struct{}
	shutdownOnce  sync.Once
}

func (e *obiTracesExporter) Start(ctx context.Context) error {
	e.queueMu.Lock()
	defer e.queueMu.Unlock()
	if e.queueClosed {
		return errors.New("trace exporter is shut down")
	}
	if e.queue != nil && !e.workerStarted {
		e.workerStarted = true
		go e.runQueue(ctx)
	}
	return nil
}

func (e *obiTracesExporter) Shutdown(context.Context) error {
	e.shutdownOnce.Do(func() {
		if e.queue != nil {
			e.queueCancel()
			e.queueMu.Lock()
			e.queueClosed = true
			close(e.queue)
			started := e.workerStarted
			e.queueMu.Unlock()
			if started {
				<-e.workerDone
			}
		} else {
			e.queueMu.Lock()
			e.queueClosed = true
			e.queueMu.Unlock()
		}
	})
	if e.close != nil {
		return e.close()
	}
	return nil
}

func (e *obiTracesExporter) ConsumeTraces(ctx context.Context, traces ptrace.Traces) error {
	if e.queue != nil {
		return e.enqueue(ctx, traces)
	}
	e.queueMu.RLock()
	defer e.queueMu.RUnlock()
	if e.queueClosed {
		return errors.New("trace exporter is shut down")
	}
	return e.export(ctx, traces)
}

func (e *obiTracesExporter) enqueue(ctx context.Context, traces ptrace.Traces) error {
	spans := int64(max(1, traces.SpanCount()))
	if spans > e.queueSize {
		return errors.New("sending queue is full")
	}
	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(e.queueContext, cancel)
	defer stop()
	if err := e.queueSlots.Acquire(waitCtx, spans); err != nil {
		return err
	}

	e.queueMu.RLock()
	defer e.queueMu.RUnlock()
	if e.queueClosed {
		e.queueSlots.Release(spans)
		return errors.New("trace exporter is shut down")
	}
	e.queue <- queuedTraces{traces: traces, spans: spans}
	return nil
}

func (e *obiTracesExporter) export(ctx context.Context, traces ptrace.Traces) error {
	spanCount := traces.SpanCount()
	var err error
	if e.retry {
		strategy := backoff.NewExponentialBackOff()
		strategy.InitialInterval = e.retryStart
		strategy.MaxInterval = e.retryMax
		_, err = backoff.Retry(ctx, func() (struct{}, error) {
			return struct{}{}, e.send(ctx, traces)
		}, backoff.WithBackOff(strategy), backoff.WithMaxElapsedTime(e.retryTotal))
	} else {
		err = e.send(ctx, traces)
	}
	if e.reporter != nil && !imetrics.IsBuiltinNoopReporter(e.reporter) {
		if err != nil {
			e.reporter.OTELTraceExportError(err)
		} else {
			e.reporter.OTELTraceExport(spanCount)
		}
	}
	return err
}

func (e *obiTracesExporter) runQueue(ctx context.Context) {
	defer close(e.workerDone)
	batch := ptrace.NewTraces()
	var timer *time.Timer
	var timeout <-chan time.Time
	flush := func() {
		if batch.SpanCount() == 0 {
			return
		}
		if err := e.export(ctx, batch); err != nil {
			slog.Warn("error sending trace to consumer", "error", err)
		}
		batch = ptrace.NewTraces()
		if timer != nil {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		timeout = nil
	}
	for {
		select {
		case queued, ok := <-e.queue:
			if !ok {
				flush()
				return
			}
			e.queueSlots.Release(queued.spans)
			for _, resource := range queued.traces.ResourceSpans().All() {
				resource.CopyTo(batch.ResourceSpans().AppendEmpty())
			}
			if e.batchMaxSize == 0 || batch.SpanCount() >= e.batchMaxSize {
				flush()
				continue
			}
			if timeout == nil {
				if timer == nil {
					timer = time.NewTimer(e.batchTimeout)
				} else {
					timer.Reset(e.batchTimeout)
				}
				timeout = timer.C
			}
		case <-timeout:
			flush()
		}
	}
}

func newOBITracesExporter(cfg otelcfg.TracesConfig, reporter imetrics.Reporter, send traceSender, closeFn func() error, retry bool) tracesExporter {
	exporter := &obiTracesExporter{
		send:       send,
		close:      closeFn,
		reporter:   reporter,
		retry:      retry,
		retryStart: defaultTraceRetryStart,
		retryMax:   defaultTraceRetryMax,
		retryTotal: defaultTraceRetryTotal,
	}
	if cfg.BackOffInitialInterval > 0 {
		exporter.retryStart = cfg.BackOffInitialInterval
	}
	if cfg.BackOffMaxInterval > 0 {
		exporter.retryMax = cfg.BackOffMaxInterval
	}
	if cfg.BackOffMaxElapsedTime > 0 {
		exporter.retryTotal = cfg.BackOffMaxElapsedTime
	}
	if cfg.QueueSize > 0 || cfg.BatchMaxSize > 0 || cfg.BatchTimeout > 0 {
		queueSize := cfg.QueueSize
		if queueSize == 0 {
			queueSize = defaultTraceQueueSize
		}
		exporter.queue = make(chan queuedTraces, queueSize)
		exporter.queueSize = int64(queueSize)
		exporter.queueSlots = semaphore.NewWeighted(int64(queueSize))
		exporter.queueContext, exporter.queueCancel = context.WithCancel(context.Background())
		exporter.workerDone = make(chan struct{})
		exporter.batchMaxSize = cfg.BatchMaxSize
		exporter.batchTimeout = cfg.BatchTimeout
		if exporter.batchTimeout == 0 {
			exporter.batchTimeout = defaultTraceFlushDelay
		}
	}
	return exporter
}

func getTracesExporter(_ context.Context, cfg otelcfg.TracesConfig, reporter imetrics.Reporter) (tracesExporter, error) {
	if cfg.TracesExport != nil {
		send := func(ctx context.Context, traces ptrace.Traces) error {
			data, err := ptraceotlp.NewExportRequestFromTraces(traces).MarshalProto()
			if err != nil {
				return err
			}
			return cfg.TracesExport(ctx, data)
		}
		return newOBITracesExporter(cfg, reporter, send, nil, false), nil
	}

	switch cfg.GetProtocol() {
	case otelcfg.ProtocolHTTPJSON, otelcfg.ProtocolHTTPProtobuf, "":
		send, closeFn, err := newHTTPTraceSender(cfg)
		if err != nil {
			return nil, err
		}
		return newOBITracesExporter(cfg, reporter, send, closeFn, true), nil
	case otelcfg.ProtocolGRPC:
		send, closeFn, err := newGRPCTraceSender(cfg)
		if err != nil {
			return nil, err
		}
		return newOBITracesExporter(cfg, reporter, send, closeFn, true), nil
	case otelcfg.ProtocolDebug:
		send := func(_ context.Context, traces ptrace.Traces) error {
			data, err := (&ptrace.JSONMarshaler{}).MarshalTraces(traces)
			if err != nil {
				return err
			}
			slog.Info("traces", "data", string(data))
			return nil
		}
		return newOBITracesExporter(cfg, reporter, send, nil, false), nil
	default:
		return nil, fmt.Errorf("invalid protocol value: %q", cfg.GetProtocol())
	}
}

func newHTTPTraceSender(cfg otelcfg.TracesConfig) (traceSender, func() error, error) {
	opts, err := otelcfg.HTTPTracesEndpointOptions(&cfg)
	if err != nil {
		return nil, nil, err
	}
	path := opts.URLPath
	if path == "" {
		path = "/v1/traces"
	}
	endpoint := opts.Scheme + "://" + opts.Endpoint + path
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.SkipTLSVerify}}
	if opts.UnixSocketAddr != "" {
		transport = otelcfg.UnixTransport(opts.UnixSocketAddr)
	}
	client := &http.Client{Transport: transport, Timeout: defaultTraceRequestTimeout}
	send := func(ctx context.Context, traces ptrace.Traces) error {
		data, err := ptraceotlp.NewExportRequestFromTraces(traces).MarshalProto()
		if err != nil {
			return err
		}
		var body io.Reader = bytes.NewReader(data)
		compressed := cfg.GetCompression() == "gzip"
		if compressed {
			var buf bytes.Buffer
			writer := gzip.NewWriter(&buf)
			if _, err := writer.Write(data); err != nil {
				return err
			}
			if err := writer.Close(); err != nil {
				return err
			}
			body = &buf
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/x-protobuf")
		if compressed {
			request.Header.Set("Content-Encoding", "gzip")
		}
		for key, value := range opts.Headers {
			request.Header.Set(key, value)
		}
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
			err := fmt.Errorf("OTLP HTTP export returned %s", response.Status)
			if response.StatusCode < http.StatusInternalServerError && response.StatusCode != http.StatusTooManyRequests {
				return backoff.Permanent(err)
			}
			return err
		}
		return nil
	}
	return send, func() error { transport.CloseIdleConnections(); return nil }, nil
}

func newGRPCTraceSender(cfg otelcfg.TracesConfig) (traceSender, func() error, error) {
	opts, err := otelcfg.GRPCTracesEndpointOptions(&cfg)
	if err != nil {
		return nil, nil, err
	}
	transport := credentials.NewTLS(&tls.Config{InsecureSkipVerify: opts.SkipTLSVerify})
	dialOption := grpc.WithTransportCredentials(transport)
	if opts.Insecure {
		dialOption = grpc.WithTransportCredentials(insecure.NewCredentials())
	}
	conn, err := grpc.NewClient(opts.Endpoint, dialOption)
	if err != nil {
		return nil, nil, err
	}
	client := ptraceotlp.NewGRPCClient(conn)
	send := func(ctx context.Context, traces ptrace.Traces) error {
		request := ptraceotlp.NewExportRequestFromTraces(traces)
		if len(opts.Headers) > 0 {
			headers := metadata.MD{}
			for key, value := range opts.Headers {
				headers.Set(strings.ToLower(key), value)
			}
			ctx = metadata.NewOutgoingContext(ctx, headers)
		}
		var callOptions []grpc.CallOption
		if cfg.GetCompression() == "gzip" {
			callOptions = append(callOptions, grpc.UseCompressor(grpcgzip.Name))
		}
		requestCtx, cancel := context.WithTimeout(ctx, defaultTraceRequestTimeout)
		defer cancel()
		_, err = client.Export(requestCtx, request, callOptions...)
		switch status.Code(err) {
		case codes.InvalidArgument, codes.NotFound, codes.AlreadyExists,
			codes.PermissionDenied, codes.Unauthenticated, codes.FailedPrecondition,
			codes.OutOfRange, codes.Unimplemented, codes.DataLoss:
			return backoff.Permanent(err)
		}
		return err
	}
	return send, conn.Close, nil
}

var _ tracesExporter = (*obiTracesExporter)(nil)
