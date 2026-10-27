// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/obi"
)

func exceptionDocument(t *testing.T, yaml string) *obi.Config {
	t.Helper()
	doc, _, err := schema.ParseStandaloneYAML([]byte(yaml))
	require.NoError(t, err)
	cfg, err := DocumentToRuntime(doc)
	require.NoError(t, err)
	return cfg
}

func TestExceptionV2LoggerProvider(t *testing.T) {
	for _, tc := range []struct {
		name     string
		exporter string
		endpoint string
		protocol otelcfg.Protocol
	}{
		{name: "grpc", exporter: "otlp_grpc:\n            endpoint: http://collector:4317", endpoint: "http://collector:4317", protocol: otelcfg.ProtocolGRPC},
		{name: "http protobuf", exporter: "otlp_http:\n            endpoint: http://collector:4318/custom/logs", endpoint: "http://collector:4318/custom/logs", protocol: otelcfg.ProtocolHTTPProtobuf},
		{name: "http json", exporter: "otlp_http:\n            endpoint: http://collector:4318/v1/logs\n            encoding: json", endpoint: "http://collector:4318/v1/logs", protocol: otelcfg.ProtocolHTTPJSON},
		{name: "console", exporter: "console: {}", protocol: otelcfg.ProtocolDebug},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := exceptionDocument(t, `file_format: "1.0"
logger_provider:
  processors:
    - batch:
        max_queue_size: 100
        max_export_batch_size: 10
        schedule_delay: 250
        exporter:
          `+tc.exporter+`
extensions:
  obi:
    version: "2.0"
    capture:
      exceptions:
        enabled: true
`)
			require.True(t, cfg.Exceptions.Enabled)
			require.True(t, cfg.Logs.Enabled())
			require.Equal(t, tc.protocol, cfg.Logs.Protocol)
			require.Equal(t, tc.endpoint, cfg.Logs.Endpoint)
			require.Equal(t, 100, cfg.Logs.QueueSize)
			require.Equal(t, 10, cfg.Logs.BatchMaxSize)
			require.Equal(t, 250*time.Millisecond, cfg.Logs.BatchTimeout)
			require.NoError(t, cfg.ValidateStatic())
		})
	}
}

func TestExceptionV2RuleRefinement(t *testing.T) {
	cfg := exceptionDocument(t, `file_format: "1.0"
logger_provider:
  processors:
    - batch:
        exporter:
          otlp_http:
            endpoint: http://localhost:4318/v1/logs
extensions:
  obi:
    version: "2.0"
    capture:
      exceptions:
        enabled: true
      rules:
        - action: include
          match:
            process:
              language_glob: [python]
          refine:
            exceptions:
              enabled: false
            exports:
              logs: true
              traces: false
              metrics: false
        - action: include
          match:
            process:
              language_glob: [go]
`)
	require.True(t, cfg.Exceptions.Enabled)
	python := 0
	for _, s := range cfg.Discovery.Instrument {
		if s.Languages.IsSet() && s.Languages.MatchString("python") {
			python++
			require.False(t, s.Exceptions.Resolve(cfg.Exceptions).Enabled)
			require.True(t, s.ExportModes.CanExportLogs())
			require.False(t, s.ExportModes.CanExportTraces())
		} else {
			require.True(t, s.Exceptions.Resolve(cfg.Exceptions).Enabled)
		}
	}
	require.Equal(t, 1, python)
	require.NoError(t, cfg.ValidateStatic())
}

func TestExceptionV2SelectiveCapture(t *testing.T) {
	cfg := exceptionDocument(t, `file_format: "1.0"
logger_provider:
  processors:
    - batch:
        exporter:
          otlp_http:
            endpoint: http://localhost:4318/v1/logs
extensions:
  obi:
    version: "2.0"
    capture:
      exceptions:
        enabled: false
      rules:
        - action: include
          match:
            process:
              language_glob: [go, python]
          refine:
            exceptions:
              enabled: true
            exports:
              logs: true
              traces: false
              metrics: false
`)
	require.False(t, cfg.Exceptions.Enabled)
	require.True(t, cfg.ExceptionsEnabled())
	require.True(t, cfg.Discovery.Instrument[0].Exceptions.Resolve(cfg.Exceptions).Enabled)
	require.NoError(t, cfg.ValidateStatic())
}

func TestExceptionV2RequiresLoggerProvider(t *testing.T) {
	cfg := exceptionDocument(t, `file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      exceptions:
        enabled: true
`)
	require.ErrorContains(t, cfg.ValidateStatic(), "exception capture requires a logger_provider exporter")
}
