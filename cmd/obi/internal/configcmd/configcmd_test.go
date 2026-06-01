// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configcmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateStandaloneConfigSupportsV2(t *testing.T) {
	require.NoError(t, validateStandaloneConfig([]byte(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: include
    daemon:
      logging:
        debug_trace_output: text
`)))
}

func TestValidateStandaloneConfigSupportsV2EnvSubstitution(t *testing.T) {
	t.Setenv("OBI_DEFAULT_ACTION", "include")

	require.NoError(t, validateStandaloneConfig([]byte(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: ${OBI_DEFAULT_ACTION}
    daemon:
      logging:
        debug_trace_output: text
`)))
}

func TestValidateStandaloneConfigSupportsTopLevelTracesPipelineFields(t *testing.T) {
	require.NoError(t, validateStandaloneConfig([]byte(`
file_format: "1.0"
tracer_provider:
  processors:
    - batch:
        max_export_batch_size: 512
        max_queue_size: 4096
        schedule_delay: 7000
        exporter:
          otlp_grpc:
            endpoint: https://collector:4317
            retry:
              initial_interval: 2s
              max_interval: 9s
              max_elapsed_time: 45s
            tls:
              insecure: true
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: include
`)))
}

func TestValidateReceiverConfigSupportsV2(t *testing.T) {
	require.NoError(t, validateReceiverConfig([]byte(`
version: "2.0"
policy:
  default_action: include
`)))
}

func TestValidateReceiverConfigRejectsStandaloneSections(t *testing.T) {
	err := validateReceiverConfig([]byte(`
version: "2.0"
policy:
  default_action: include
daemon:
  logging:
    level: INFO
`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "not allowed in receiver mode")
}

func TestMigrateConfigDataCanonicalizesV2(t *testing.T) {
	encoded, report, err := migrateConfigData([]byte(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: include
`))
	require.NoError(t, err)
	require.Empty(t, report)
	require.Contains(t, encoded, "version: \"2.0\"")
}

func TestMigrateConfigDataSupportsV2EnvSubstitution(t *testing.T) {
	t.Setenv("OBI_VERSION", "2.0")

	encoded, report, err := migrateConfigData([]byte(`
file_format: "1.0"
extensions:
  obi:
    version: "${OBI_VERSION}"
    capture:
      policy:
        default_action: include
`))
	require.NoError(t, err)
	require.Empty(t, report)
	require.Contains(t, encoded, "version: \"2.0\"")
}

func TestMigrateConfigDataCanonicalizesReceiverShapedV2(t *testing.T) {
	encoded, report, err := migrateConfigData([]byte(`
version: "2.0"
policy:
  default_action: include
`))
	require.NoError(t, err)
	require.Empty(t, report)
	require.Contains(t, encoded, "file_format: \"1.0\"")
	require.Contains(t, encoded, "extensions:")
	require.Contains(t, encoded, "version: \"2.0\"")
	require.NotEqual(t, "null\n", encoded)
}

func TestMigrateConfigDataMigratesLegacy(t *testing.T) {
	encoded, report, err := migrateConfigData([]byte(`{}`))
	require.NoError(t, err)
	require.Contains(t, report, "mapping report:")
	require.Contains(t, encoded, "extensions:")
	require.Contains(t, encoded, "version: \"2.0\"")
}
