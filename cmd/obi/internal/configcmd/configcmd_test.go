// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configcmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const validStandaloneV2 = `
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: include
      rules:
        - action: include
          match:
            process:
              exe_path_glob: ["/srv/*"]
    daemon:
      logging:
        debug_trace_output: text
`

const representativeV1 = `
discovery:
  instrument:
    - exe_path: "/srv/*"
  skip_go_specific_tracers: true
ebpf:
  wakeup_len: 64
network:
  source: socket_filter
  print_flows: true
metrics:
  features: [application, network]
filter:
  application:
    http.request.method:
      match: GET
  network:
    src.address:
      not_match: "127.*"
prometheus_export:
  port: 9090
attributes:
  rename_unresolved_hosts: missing
log_level: DEBUG
trace_printer: text
profile_port: 6060
`

func TestMaybeRunIgnoresRuntimeArguments(t *testing.T) {
	handled, exitCode := MaybeRun([]string{"-config", "obi.yml"}, &bytes.Buffer{}, &bytes.Buffer{})
	require.False(t, handled)
	require.Equal(t, ExitSuccess, exitCode)
}

func TestRunValidateStandalone(t *testing.T) {
	t.Setenv("OBI_CONFIG_VERSION", "2.0")
	contents := strings.Replace(validStandaloneV2, `version: "2.0"`, `version: "${OBI_CONFIG_VERSION}"`, 1)
	path := writeConfig(t, "v2.yaml", contents)
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"validate", path}, &stdout, &stderr)

	require.Equal(t, ExitSuccess, exitCode, stderr.String())
	require.Equal(t, "configuration is valid\n", stdout.String())
	require.Empty(t, stderr.String())
}

func TestRunValidateReceiver(t *testing.T) {
	path := writeConfig(t, "receiver.yaml", `
version: "2.0"
policy:
  default_action: include
rules:
  - action: include
    match:
      process:
        exe_path_glob: ["/srv/*"]
`)
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"validate", "--mode=receiver", path}, &stdout, &stderr)

	require.Equal(t, ExitSuccess, exitCode, stderr.String())
	require.Equal(t, "configuration is valid\n", stdout.String())
}

func TestRunValidateRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		args []string
		want string
	}{
		{
			name: "malformed YAML",
			yaml: "file_format: [\n",
			want: "parsing config v2 YAML",
		},
		{
			name: "unsupported version",
			yaml: strings.Replace(validStandaloneV2, `version: "2.0"`, `version: "3.0"`, 1),
			want: "unsupported OBI config version",
		},
		{
			name: "unknown v2 field",
			yaml: strings.Replace(validStandaloneV2, "      policy:\n", "      unknown_field: true\n      policy:\n", 1),
			want: "field unknown_field not found",
		},
		{
			name: "v1 is not reinterpreted",
			yaml: "trace_printer: text\n",
			want: "missing extensions.obi.version",
		},
		{
			name: "receiver standalone section",
			yaml: "version: \"2.0\"\ndaemon: {}\n",
			args: []string{"--mode=receiver"},
			want: "not allowed in receiver config",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeConfig(t, "invalid.yaml", test.yaml)
			args := append([]string{"validate"}, test.args...)
			args = append(args, path)
			var stdout, stderr bytes.Buffer

			exitCode := run(args, &stdout, &stderr)

			require.Equal(t, ExitError, exitCode)
			require.Empty(t, stdout.String())
			require.Contains(t, stderr.String(), test.want)
		})
	}
}

func TestRunMigrateRepresentativeV1(t *testing.T) {
	t.Setenv("OTEL_EBPF_BPF_WAKEUP_LEN", "999")
	t.Setenv("MIGRATION_WAKEUP_LEN", "64")
	contents := strings.Replace(representativeV1, "wakeup_len: 64", "wakeup_len: ${MIGRATION_WAKEUP_LEN}", 1)
	path := writeConfig(t, "v1.yaml", contents)
	var first, second, firstReport, secondReport bytes.Buffer

	firstExit := run([]string{"migrate", path}, &first, &firstReport)
	secondExit := run([]string{"migrate", path}, &second, &secondReport)

	require.Equal(t, ExitSuccess, firstExit, firstReport.String())
	require.Equal(t, ExitSuccess, secondExit, secondReport.String())
	require.Equal(t, first.String(), second.String())
	require.Equal(t, firstReport.String(), secondReport.String())
	require.Contains(t, first.String(), "file_format: \"1.0\"")
	require.Contains(t, first.String(), "version: \"2.0\"")
	require.Contains(t, first.String(), "wakeup_len: 64")
	require.NotContains(t, first.String(), "additionalproperties")
	require.Contains(t, firstReport.String(), "fanned out")
	require.Contains(t, firstReport.String(), "capture.rules")
	require.Contains(t, firstReport.String(), "inverted")
	require.Contains(t, firstReport.String(), "OpenTelemetry providers")
	require.NoError(t, validateConfig(first.Bytes(), validationModeStandalone))
}

func TestRunMigrateRejectsUnsupportedInput(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "unknown v1 field",
			yaml: representativeV1 + "unknown_field: true\n",
			want: "field unknown_field not found",
		},
		{
			name: "known but unmapped v1 field",
			yaml: strings.Replace(representativeV1, "  port: 9090\n", "  port: 9090\n  path: /custom\n", 1),
			want: "prometheus_export.path",
		},
		{
			name: "already v2",
			yaml: validStandaloneV2,
			want: "already a standalone OBI config v2",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeConfig(t, "unsupported.yaml", test.yaml)
			var stdout, stderr bytes.Buffer

			exitCode := run([]string{"migrate", path}, &stdout, &stderr)

			require.Equal(t, ExitError, exitCode)
			require.Empty(t, stdout.String())
			require.Contains(t, stderr.String(), test.want)
		})
	}
}

func TestRunExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{name: "missing subcommand", want: ExitUsage},
		{name: "unknown subcommand", args: []string{"unknown"}, want: ExitUsage},
		{name: "invalid mode", args: []string{"validate", "--mode=other", "missing"}, want: ExitUsage},
		{name: "unsupported migrate flag", args: []string{"migrate", "--from=v1", "missing"}, want: ExitUsage},
		{name: "validate read error", args: []string{"validate", "missing"}, want: ExitError},
		{name: "migrate read error", args: []string{"migrate", "missing"}, want: ExitError},
		{name: "validate help", args: []string{"validate", "--help"}, want: ExitSuccess},
		{name: "migrate help", args: []string{"migrate", "--help"}, want: ExitSuccess},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exitCode := run(test.args, &bytes.Buffer{}, &bytes.Buffer{})
			require.Equal(t, test.want, exitCode)
		})
	}
}

func writeConfig(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}
