// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obi

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

func TestExceptionConfigValidation(t *testing.T) {
	disabled := false
	cfg := DefaultConfig
	cfg.Exceptions.Enabled = true
	cfg.Logs.Endpoint = "http://localhost:4318/v1/logs"
	cfg.Logs.Protocol = otelcfg.ProtocolHTTPProtobuf
	cfg.Discovery.Instrument = services.GlobDefinitionCriteria{
		{Languages: services.NewGlob("{go,python}"), Exceptions: &services.ExceptionsOverride{Enabled: &disabled}},
		{Languages: services.NewGlob("java")},
	}
	require.False(t, cfg.Discovery.Instrument[0].Exceptions.Resolve(cfg.Exceptions).Enabled)
	require.True(t, cfg.Discovery.Instrument[1].Exceptions.Resolve(cfg.Exceptions).Enabled)
	require.NoError(t, cfg.ValidateStatic())

	cfg.Logs.Endpoint = ""
	require.ErrorContains(t, cfg.ValidateStatic(), "exception capture requires")
	cfg.Logs.Protocol = otelcfg.ProtocolDebug
	require.NoError(t, cfg.ValidateStatic())
}

func TestExceptionConfigNotInV1(t *testing.T) {
	t.Setenv("OTEL_EBPF_EXCEPTIONS_ENABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "http://localhost:4318/v1/logs")
	cfg, err := LoadConfig(strings.NewReader(`
exceptions:
  enabled: true
otel_logs_export:
  endpoint: http://localhost:4318/v1/logs
`))
	require.NoError(t, err)
	require.False(t, cfg.ExceptionsEnabled())
	require.False(t, cfg.Logs.Enabled())

	_, err = LoadConfig(strings.NewReader(`
discovery:
  instrument:
    - languages: python
      exceptions:
        enabled: true
`))
	require.Error(t, err)
}
