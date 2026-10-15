// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
	"google.golang.org/protobuf/proto"

	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

const (
	defaultTraceQueueSize  = 1000
	defaultTraceFlushDelay = 200 * time.Millisecond
	defaultTraceRetryStart = 5 * time.Second
	defaultTraceRetryMax   = 30 * time.Second
	defaultTraceRetryTotal = 5 * time.Minute
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
	client        otlptrace.Client
	reporter      imetrics.Reporter
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
	if e.client != nil {
		if err := e.client.Start(ctx); err != nil {
			return err
		}
	}
	if e.queue != nil && !e.workerStarted {
		e.workerStarted = true
		// The queue must flush after the pipeline context is canceled.
		go e.runQueue(context.WithoutCancel(ctx))
	}
	return nil
}

func (e *obiTracesExporter) Shutdown(ctx context.Context) error {
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
	if e.client != nil {
		return e.client.Stop(ctx)
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
	err := e.send(ctx, traces)
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

func newOBITracesExporter(cfg otelcfg.TracesConfig, reporter imetrics.Reporter, send traceSender, client otlptrace.Client) tracesExporter {
	exporter := &obiTracesExporter{
		send:     send,
		client:   client,
		reporter: reporter,
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
		return newOBITracesExporter(cfg, reporter, send, nil), nil
	}

	switch cfg.GetProtocol() {
	case otelcfg.ProtocolHTTPJSON, otelcfg.ProtocolHTTPProtobuf, "":
		client, err := newHTTPTraceClient(cfg)
		if err != nil {
			return nil, err
		}
		return newOTLPTracesExporter(cfg, reporter, client), nil
	case otelcfg.ProtocolGRPC:
		client, err := newGRPCTraceClient(cfg)
		if err != nil {
			return nil, err
		}
		return newOTLPTracesExporter(cfg, reporter, client), nil
	case otelcfg.ProtocolDebug:
		send := func(_ context.Context, traces ptrace.Traces) error {
			data, err := (&ptrace.JSONMarshaler{}).MarshalTraces(traces)
			if err != nil {
				return err
			}
			slog.Info("traces", "data", string(data))
			return nil
		}
		return newOBITracesExporter(cfg, reporter, send, nil), nil
	default:
		return nil, fmt.Errorf("invalid protocol value: %q", cfg.GetProtocol())
	}
}

func newOTLPTracesExporter(cfg otelcfg.TracesConfig, reporter imetrics.Reporter, client otlptrace.Client) tracesExporter {
	send := func(ctx context.Context, traces ptrace.Traces) error {
		data, err := (&ptrace.ProtoMarshaler{}).MarshalTraces(traces)
		if err != nil {
			return err
		}
		var payload tracepb.TracesData
		if err := proto.Unmarshal(data, &payload); err != nil {
			return err
		}
		return client.UploadTraces(ctx, payload.ResourceSpans)
	}
	return newOBITracesExporter(cfg, reporter, send, client)
}

func traceRetrySettings(cfg otelcfg.TracesConfig) (time.Duration, time.Duration, time.Duration) {
	initial, maxInterval, maxElapsed := defaultTraceRetryStart, defaultTraceRetryMax, defaultTraceRetryTotal
	if cfg.BackOffInitialInterval > 0 {
		initial = cfg.BackOffInitialInterval
	}
	if cfg.BackOffMaxInterval > 0 {
		maxInterval = cfg.BackOffMaxInterval
	}
	if cfg.BackOffMaxElapsedTime > 0 {
		maxElapsed = cfg.BackOffMaxElapsedTime
	}
	return initial, maxInterval, maxElapsed
}

func newHTTPTraceClient(cfg otelcfg.TracesConfig) (otlptrace.Client, error) {
	opts, err := otelcfg.HTTPTracesEndpointOptions(&cfg)
	if err != nil {
		return nil, err
	}
	initial, maxInterval, maxElapsed := traceRetrySettings(cfg)
	options := opts.AsTraceHTTP()
	options = append(options,
		otlptracehttp.WithTimeout(maxElapsed),
		otlptracehttp.WithRetry(otlptracehttp.RetryConfig{
			Enabled: true, InitialInterval: initial, MaxInterval: maxInterval, MaxElapsedTime: maxElapsed,
		}),
	)
	if cfg.GetCompression() == "gzip" {
		options = append(options, otlptracehttp.WithCompression(otlptracehttp.GzipCompression))
	}
	if cfg.GetProtocol() == otelcfg.ProtocolHTTPJSON {
		options = append(options, otlptracehttp.WithEncoding(otlptracehttp.EncodingJSON))
	}
	if opts.UnixSocketAddr != "" {
		options = append(options, otlptracehttp.WithHTTPClient(&http.Client{
			Transport: otelcfg.UnixTransport(opts.UnixSocketAddr),
			Timeout:   maxElapsed,
		}))
	}
	return otlptracehttp.NewClient(options...), nil
}

func newGRPCTraceClient(cfg otelcfg.TracesConfig) (otlptrace.Client, error) {
	opts, err := otelcfg.GRPCTracesEndpointOptions(&cfg)
	if err != nil {
		return nil, err
	}
	initial, maxInterval, maxElapsed := traceRetrySettings(cfg)
	options := opts.AsTraceGRPC()
	options = append(options,
		otlptracegrpc.WithTimeout(maxElapsed),
		otlptracegrpc.WithRetry(otlptracegrpc.RetryConfig{
			Enabled: true, InitialInterval: initial, MaxInterval: maxInterval, MaxElapsedTime: maxElapsed,
		}),
	)
	if cfg.GetCompression() == "gzip" {
		options = append(options, otlptracegrpc.WithCompressor("gzip"))
	}
	return otlptracegrpc.NewClient(options...), nil
}

var _ tracesExporter = (*obiTracesExporter)(nil)
