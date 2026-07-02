// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const validStandaloneV2 = `
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture: {}
`

const validReceiverV2 = `
version: "2.0"
`

func TestValidateConfigData(t *testing.T) {
	t.Parallel()

	require.NoError(t, validateConfigData([]byte(validStandaloneV2), configValidationModeStandalone))
	require.NoError(t, validateConfigData([]byte(validReceiverV2), configValidationModeReceiver))

	err := validateConfigData([]byte(validReceiverV2+"daemon: {}\n"), configValidationModeReceiver)
	require.ErrorContains(t, err, `section "daemon" is not allowed in receiver config`)

	err = validateConfigData([]byte(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: drop
`), configValidationModeStandalone)
	require.ErrorContains(t, err, "invalid action")

	err = validateConfigData([]byte(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    daemon:
      profiling:
        port: 99999
`), configValidationModeStandalone)
	require.ErrorContains(t, err, "ProfilePort")
}

func TestRunConfigCommandExitCodes(t *testing.T) {
	t.Parallel()

	validV2 := writeConfigFile(t, validStandaloneV2)
	invalidV2 := writeConfigFile(t, `
file_format: "1.0"
extensions:
  obi:
    version: "3.0"
`)
	validV1 := writeConfigFile(t, `
open_port: 8080
otel_traces_export:
  endpoint: http://localhost:4317
  protocol: grpc
`)
	invalidV1 := writeConfigFile(t, "unknown_setting: true\n")

	tests := []struct {
		name string
		args []string
		code int
	}{
		{name: "usage", args: []string{"config"}, code: configCommandExitUsage},
		{name: "valid", args: []string{"config", "validate", validV2}, code: configCommandExitSuccess},
		{name: "invalid", args: []string{"config", "validate", invalidV2}, code: configCommandExitFailure},
		{name: "migrate", args: []string{"config", "migrate", validV1}, code: configCommandExitSuccess},
		{name: "migration failure", args: []string{"config", "migrate", invalidV1}, code: configCommandExitFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			handled, code := runConfigCommand(test.args, &stdout, &stderr)

			require.True(t, handled)
			require.Equal(t, test.code, code)
		})
	}
}

func TestMigrateConfigDataReport(t *testing.T) {
	t.Parallel()

	encoded, report, err := migrateConfigData([]byte(`
discovery:
  instrument:
    - open_ports: 8080
ebpf:
  track_request_headers: true
filter:
  application:
    http.request.method:
      match: GET
network:
  enable: true
  source: socket_filter
otel_metrics_export:
  endpoint: http://localhost:4317
  protocol: grpc
otel_traces_export:
  endpoint: http://localhost:4317
  protocol: grpc
attributes:
  rename_unresolved_hosts: unknown
log_level: DEBUG
`))

	require.NoError(t, err)
	require.Contains(t, encoded, `version: "2.0"`)
	require.NotContains(t, encoded, "additionalproperties")
	require.Contains(t, encoded, "meter_provider:")
	require.Contains(t, encoded, "track_request_headers: true")
	require.Contains(t, encoded, "source: socket_filter")
	require.Contains(t, encoded, "default: unknown")
	require.Contains(t, encoded, "level: DEBUG")
	require.Contains(t, report, "filter.application: fanned out to protocol and signal filters")
	require.NoError(t, validateConfigData([]byte(encoded), configValidationModeStandalone))
}

func writeConfigFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yml")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}
