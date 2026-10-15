// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/ptrace"

	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

func TestTraceQueueCountsSpansAndUnblocksOnShutdown(t *testing.T) {
	cfg := otelcfg.TracesConfig{QueueSize: 2}
	exp := newOBITracesExporter(cfg, nil, func(context.Context, ptrace.Traces) error {
		return nil
	}, nil, false)

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
	}, nil, false)

	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, exp.Start(ctx))
	require.NoError(t, exp.ConsumeTraces(ctx, oneSpan()))
	cancel()
	require.NoError(t, exp.Shutdown(ctx))

	require.Equal(t, 1, sentSpans)
	require.NoError(t, sendErr)
}
