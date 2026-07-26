// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestGetLogsExporter_Debug(t *testing.T) {
	cfg := otelcfg.LogsConfig{LogsProtocol: otelcfg.ProtocolDebug}
	exp, host, err := getLogsExporter(t.Context(), cfg)
	require.NoError(t, err)
	require.NotNil(t, exp)
	require.NotNil(t, host)

	require.NoError(t, exp.Start(context.Background(), host))
	defer func() { assert.NoError(t, exp.Shutdown(context.Background())) }()
}

func TestGetLogsExporter_InvalidProtocol(t *testing.T) {
	cfg := otelcfg.LogsConfig{LogsEndpoint: "http://localhost:4318", LogsProtocol: otelcfg.Protocol("bogus")}
	_, _, err := getLogsExporter(t.Context(), cfg)
	require.Error(t, err)
}

// TestLogsReceiver_QueueProcessingLogsDisabled is a regression test for the
// LogsReceiver enable-gate: a user with a common OTEL_EXPORTER_OTLP_ENDPOINT
// set (so cfg.Enabled() is true) but the queue_processing_logs toggle left
// off (QueueProcessingLogs is false) must not get a running logs receiver —
// mirroring Config.QueueProcessingAsLogsEnabled(), which checks both halves
// of the gate together.
func TestLogsReceiver_QueueProcessingLogsDisabled(t *testing.T) {
	cfg := otelcfg.LogsConfig{LogsEndpoint: "http://localhost:4318"}
	require.True(t, cfg.Enabled(), "test setup: endpoint must make Enabled() true")
	require.False(t, cfg.QueueProcessingLogs, "test setup: toggle must be left off")

	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(1))
	instanceFn := LogsReceiver(&global.ContextInfo{}, cfg, otelcfg.TracesConfig{}, &attributes.SelectorConfig{}, input)

	runFunc, err := instanceFn(t.Context())
	require.NoError(t, err)
	require.NotNil(t, runFunc)

	// A real provideLoop would block reading from the (unclosed, empty)
	// subscribed input channel. The expected no-op RunFunc (from
	// swarm.EmptyRunFunc) returns immediately regardless of context.
	done := make(chan struct{})
	go func() {
		runFunc(t.Context())
		close(done)
	}()

	select {
	case <-done:
		// OK: no-op RunFunc, as expected when the toggle is off.
	case <-time.After(500 * time.Millisecond):
		t.Fatal("LogsReceiver started a live receiver even though QueueProcessingLogs was disabled")
	}
}
