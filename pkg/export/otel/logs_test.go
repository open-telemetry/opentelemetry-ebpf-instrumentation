// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/exporter/otlphttpexporter"

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

// TestBuildHTTPLogsExporterConfig_SingleBufferingLayer is a regression test for the
// HTTP logs exporter double-buffering bug: buildHTTPLogsExporterConfig must disable the
// inner otlphttpexporter's own queue/retry, and hand back the real queue/retry settings
// separately for the caller to apply exactly once via the outer exporterhelper.NewLogs
// wrap — matching getTracesExporter's HTTP branch.
func TestBuildHTTPLogsExporterConfig_SingleBufferingLayer(t *testing.T) {
	cfg := otelcfg.LogsConfig{
		LogsEndpoint:           "http://localhost:4318",
		QueueSize:              7,
		BatchMaxSize:           10,
		BackOffInitialInterval: 2 * time.Second,
	}

	factory := otlphttpexporter.NewFactory()
	config, host, queueCfg, retryCfg, err := buildHTTPLogsExporterConfig(cfg, factory)
	require.NoError(t, err)
	require.NotNil(t, host)

	assert.False(t, config.QueueConfig.HasValue(), "the inner otlphttpexporter must not buffer on its own")
	assert.False(t, config.RetryConfig.Enabled, "the inner otlphttpexporter must not retry on its own")

	require.True(t, queueCfg.HasValue(), "the outer wrap must receive the real queue settings")
	assert.EqualValues(t, 7, queueCfg.Get().QueueSize)

	assert.True(t, retryCfg.Enabled, "the outer wrap must receive the real, enabled retry settings")
	assert.Equal(t, 2*time.Second, retryCfg.InitialInterval)
}

// TestGetLogsExporter_HTTP exercises getLogsExporter's HTTP branch end to end with a
// real queue/batch/retry configuration, which previously had no test coverage at all.
func TestGetLogsExporter_HTTP(t *testing.T) {
	cfg := otelcfg.LogsConfig{
		LogsEndpoint:           "http://localhost:4318",
		QueueSize:              5,
		BatchMaxSize:           5,
		BackOffInitialInterval: time.Second,
	}
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
