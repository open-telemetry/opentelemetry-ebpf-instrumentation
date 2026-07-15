// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestLoadConfigV2Standalone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config-v2.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
file_format: "1.0"
log_level: debug
extensions:
  obi:
    version: "2.0"
    capture:
      rules:
        - action: include
          match:
            process:
              exe_path_glob: ["/usr/bin/checkout"]
      channels:
        buffer_len: 123
    enrich:
      enrichers:
        kubernetes:
          mode: disabled
    correlation:
      log_trace_annotation:
        enabled: true
    daemon:
      logging:
        format: json
        debug_trace_output: text
      shutdown:
        timeout: 12s
`), 0o600))

	cfg, version := loadConfig(&path)

	require.Equal(t, configVersionV2, version)
	require.NoError(t, cfg.Validate())
	require.Equal(t, 123, cfg.ChannelBufferLen)
	require.Len(t, cfg.Discovery.Instrument, 1)
	require.Equal(t, obi.LogLevelDebug, cfg.LogLevel)
	require.Equal(t, obi.LogFormatJSON, cfg.LogFormat)
	require.Equal(t, 12*time.Second, cfg.ShutdownTimeout)
	require.Equal(t, "false", string(cfg.Attributes.Kubernetes.Enable))
	require.True(t, cfg.EBPF.LogEnricher.Enabled())
}

func TestLoadConfigV2ReplacesEnvironmentVariables(t *testing.T) {
	t.Setenv("OBI_V2_BUFFER_LEN", "321")

	cfg, version, err := loadConfigReader(bytes.NewBufferString(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      channels:
        buffer_len: ${OBI_V2_BUFFER_LEN}
`))

	require.NoError(t, err)
	require.Equal(t, configVersionV2, version)
	require.Equal(t, 321, cfg.ChannelBufferLen)
}

func TestLoadConfigV1PreservesLegacyEnvironmentPrecedence(t *testing.T) {
	t.Setenv("OTEL_EBPF_CHANNEL_BUFFER_LEN", "222")
	t.Setenv("OBI_ESCAPED_SERVICE_NAME", "expanded-twice")

	cfg, version, err := loadConfigReader(bytes.NewBufferString(`
channel_buffer_len: 111
log_format: json
service_name: "$${OBI_ESCAPED_SERVICE_NAME}"
`))

	require.NoError(t, err)
	require.Equal(t, configVersionV1, version)
	require.Equal(t, 222, cfg.ChannelBufferLen)
	require.Equal(t, obi.LogFormatJSON, cfg.LogFormat)
	require.Equal(t, "${OBI_ESCAPED_SERVICE_NAME}", cfg.ServiceName)
}

func TestLoadConfigFallsBackOnExplicitNotV2(t *testing.T) {
	data := []byte("{}\n")
	_, _, detectionErr := schema.ParseStandaloneYAML(data)
	var notV2 *schema.NotV2Error
	require.ErrorAs(t, detectionErr, &notV2)

	cfg, version, err := loadConfigReader(bytes.NewReader(data))

	require.NoError(t, err)
	require.Equal(t, configVersionV1, version)
	require.Equal(t, obi.DefaultConfig.ChannelBufferLen, cfg.ChannelBufferLen)
}

func TestLoadConfigDoesNotFallbackForMalformedV2(t *testing.T) {
	_, version, err := loadConfigReader(bytes.NewBufferString(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    daemon:
      logging:
        format: binary
`))

	require.Error(t, err)
	require.Empty(t, version)
	require.ErrorContains(t, err, "loading config v2")
	require.ErrorContains(t, err, "format")
	require.ErrorContains(t, err, "binary")
}

func TestLoadConfigDoesNotFallbackForUnsupportedV2(t *testing.T) {
	_, version, err := loadConfigReader(bytes.NewBufferString(`
file_format: "1.0"
extensions:
  obi:
    version: "3.0"
`))

	var unsupported *schema.UnsupportedVersionError
	require.ErrorAs(t, err, &unsupported)
	require.Empty(t, version)
	require.Equal(t, "3.0", unsupported.Version)
	require.ErrorContains(t, err, `unsupported OBI config version "3.0"`)
}

func TestLoadConfigV2PreservesOmittedDefaults(t *testing.T) {
	overridden, version, err := loadConfigReader(bytes.NewBufferString(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      channels:
        buffer_len: 123
`))
	require.NoError(t, err)
	require.Equal(t, configVersionV2, version)
	require.Equal(t, 123, overridden.ChannelBufferLen)
	require.Equal(t, obi.DefaultConfig.ChannelSendTimeout, overridden.ChannelSendTimeout)

	defaults, version, err := loadConfigReader(bytes.NewBufferString(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
`))
	require.NoError(t, err)
	require.Equal(t, configVersionV2, version)
	require.Equal(t, obi.DefaultConfig.ChannelBufferLen, defaults.ChannelBufferLen)
	require.Equal(t, obi.DefaultConfig.ShutdownTimeout, defaults.ShutdownTimeout)
	require.Equal(t, obi.DefaultConfig.InternalMetrics, defaults.InternalMetrics)
	require.Equal(t, obi.DefaultConfig.Prometheus.SpanMetricsServiceCacheSize, defaults.Prometheus.SpanMetricsServiceCacheSize)
}

func TestLoadConfigReaderError(t *testing.T) {
	wantErr := errors.New("read failed")

	_, version, err := loadConfigReader(errorReader{err: wantErr})

	require.ErrorIs(t, err, wantErr)
	require.Empty(t, version)
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}
