// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configcmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/internal/config/convert"
	"go.opentelemetry.io/obi/internal/config/schema"
	obiconfig "go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/obi"
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

func TestRunValidateReceiverStatsOnly(t *testing.T) {
	path := writeConfig(t, "receiver.yaml", `
version: "2.0"
network:
  stats:
    enabled: true
`)
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"validate", "--mode=receiver", path}, &stdout, &stderr)

	require.Equal(t, ExitSuccess, exitCode, stderr.String())
	require.Equal(t, "configuration is valid\n", stdout.String())
}

func TestValidateConfigDefaultIncludeWithoutSelector(t *testing.T) {
	tests := []struct {
		name string
		mode validationMode
		yaml string
	}{
		{
			name: "standalone",
			mode: validationModeStandalone,
			yaml: `
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: include
      rules:
        - action: exclude
          match:
            process:
              exe_path_glob: ["*/obi"]
    daemon:
      logging:
        debug_trace_output: text
`,
		},
		{
			name: "receiver",
			mode: validationModeReceiver,
			yaml: `
version: "2.0"
policy:
  default_action: include
rules:
  - action: exclude
    match:
      process:
        exe_path_glob: ["*/obi"]
`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.NoError(t, validateConfig([]byte(test.yaml), test.mode))
		})
	}
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

func TestMigrateConfigPreservesEscapedEnvironmentVariable(t *testing.T) {
	t.Setenv("MIGRATION_LITERAL", "expanded")
	contents := strings.Replace(
		representativeV1,
		"attributes:\n",
		"attributes:\n  kubernetes:\n    cluster_name: \"$${MIGRATION_LITERAL}\"\n",
		1,
	)

	output, _, err := migrateConfig([]byte(contents))
	require.NoError(t, err)
	require.Contains(t, string(output), "cluster_name: $${MIGRATION_LITERAL}")

	doc, _, err := schema.ParseStandaloneYAML(obiconfig.ReplaceEnv(output))
	require.NoError(t, err)
	runtimeConfig, err := convert.DocumentToRuntime(doc)
	require.NoError(t, err)
	require.Equal(t, "${MIGRATION_LITERAL}", runtimeConfig.Attributes.Kubernetes.ClusterName)
}

func TestMigrateConfigPreservesDisabledApplicationCapture(t *testing.T) {
	output, _, err := migrateConfig([]byte(`
network:
  enable: true
  print_flows: true
metrics:
  features: [network]
`))
	require.NoError(t, err)

	doc, ext, err := schema.ParseStandaloneYAML(output)
	require.NoError(t, err)
	require.Equal(t, schema.CaptureActionExclude, ext.Capture.Policy.DefaultAction)

	runtimeConfig, err := convert.DocumentToRuntime(doc)
	require.NoError(t, err)
	require.False(t, runtimeConfig.Enabled(obi.FeatureAppO11y))
	require.True(t, runtimeConfig.Enabled(obi.FeatureNetO11y))
}

func TestMigrateConfigSupportsDeprecatedServiceSelectors(t *testing.T) {
	originalLogger := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() {
		slog.SetDefault(originalLogger)
	})

	output, report, err := migrateConfig([]byte(`
discovery:
  services:
    - exe_path: "^/srv/api$"
  excluded_linux_system_paths: ["/opt/system+services/"]
otel_traces_export:
  endpoint: http://collector:4318
`))
	require.NoError(t, err)
	require.Empty(t, logs.String())
	require.Contains(t, report, "capture.rules")

	doc, _, err := schema.ParseStandaloneYAML(output)
	require.NoError(t, err)
	runtimeConfig, err := convert.DocumentToRuntime(doc)
	require.NoError(t, err)
	require.Len(t, runtimeConfig.Discovery.Services, 1)
	require.True(t, runtimeConfig.Discovery.Services[0].Path.MatchString("/srv/api"))

	var excludesSystemPath bool
	for _, selector := range runtimeConfig.Discovery.ExcludeServices {
		if selector.Path.MatchString("/opt/system+services/daemon") {
			excludesSystemPath = true
			break
		}
	}
	require.True(t, excludesSystemPath)
}

func TestMigrateIntegrationConfigurations(t *testing.T) {
	// Docker suites select their target through OTEL_EBPF_OPEN_PORT. Materialize
	// that setting in the input because config migrate operates on YAML files.
	tests := []struct {
		name   string
		input  func(t *testing.T) []byte
		verify func(t *testing.T, cfg *obi.Config)
	}{
		{
			name: "Docker Go OTEL gRPC",
			input: func(t *testing.T) []byte {
				return withV1OpenPort(
					integrationConfig(t, "internal/test/integration/configs/obi-config-go-otel-grpc.yml"),
					8080,
				)
			},
			verify: func(t *testing.T, cfg *obi.Config) {
				require.True(t, cfg.Enabled(obi.FeatureAppO11y))
				require.Len(t, cfg.Discovery.Instrument, 1)
				require.True(t, cfg.Discovery.Instrument[0].OpenPorts.Matches(8080))
				require.Equal(t, 8999, cfg.Prometheus.Port)
				require.Equal(t, "http://jaeger:4318", cfg.Traces.TracesEndpoint)
				require.NotNil(t, cfg.Routes)
				require.Equal(t, "path", string(cfg.Routes.Unmatch))
			},
		},
		{
			name: "Docker Java",
			input: func(t *testing.T) []byte {
				return withV1OpenPort(
					integrationConfig(t, "internal/test/integration/configs/obi-config-java.yml"),
					8085,
				)
			},
			verify: func(t *testing.T, cfg *obi.Config) {
				require.True(t, cfg.Enabled(obi.FeatureAppO11y))
				require.Len(t, cfg.Discovery.Instrument, 1)
				require.True(t, cfg.Discovery.Instrument[0].OpenPorts.Matches(8085))
				require.Equal(t, "http://otelcol:4318", cfg.OTELMetrics.MetricsEndpoint)
				require.NotNil(t, cfg.Routes)
				require.Equal(t, []string{"/greeting"}, cfg.Routes.Patterns)
			},
		},
		{
			name: "Kubernetes daemonset",
			input: func(t *testing.T) []byte {
				return kubernetesConfig(t, "internal/test/integration/k8s/manifests/06-obi-daemonset.yml")
			},
			verify: func(t *testing.T, cfg *obi.Config) {
				require.True(t, cfg.Enabled(obi.FeatureAppO11y))
				require.Equal(t, obi.LogLevelDebug, cfg.LogLevel)
				require.Equal(t, "true", string(cfg.Attributes.Kubernetes.Enable))
				require.Len(t, cfg.Discovery.Instrument, 5)
				require.GreaterOrEqual(t, len(cfg.Discovery.ExcludeInstrument), 1)
				require.True(t, cfg.Discovery.Instrument[0].Metadata["k8s_deployment_name"].MatchString("testserver"))
				require.True(t, cfg.Discovery.ExcludeInstrument[0].Metadata["k8s_deployment_name"].MatchString("testserver"))
				require.NotNil(t, cfg.Routes)
				require.Equal(t, []string{"/metrics"}, cfg.Routes.IgnorePatterns)
			},
		},
		{
			name: "Kubernetes shared PID namespace daemonset",
			input: func(t *testing.T) []byte {
				return kubernetesConfig(t, "internal/test/integration/k8s/manifests/06-obi-daemonset-sharedpidns.yml")
			},
			verify: func(t *testing.T, cfg *obi.Config) {
				require.True(t, cfg.Enabled(obi.FeatureAppO11y))
				require.Equal(t, obi.LogLevelDebug, cfg.LogLevel)
				require.Equal(t, "true", string(cfg.Attributes.Kubernetes.Enable))
				require.Len(t, cfg.Discovery.Instrument, 2)
				require.True(t, cfg.Discovery.Instrument[0].Metadata["k8s_deployment_name"].MatchString("testserver"))
				require.True(t, cfg.Discovery.Instrument[1].Metadata["k8s_daemonset_name"].MatchString("hostpid-httpserver"))
				require.NotNil(t, cfg.Routes)
				require.Equal(t, []string{"/pingpong"}, cfg.Routes.Patterns)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, _, err := migrateConfig(test.input(t))
			require.NoError(t, err)

			doc, _, err := schema.ParseStandaloneYAML(output)
			require.NoError(t, err)
			cfg, err := convert.DocumentToRuntime(doc)
			require.NoError(t, err)

			test.verify(t, cfg)
		})
	}
}

func integrationConfig(t *testing.T, relativePath string) []byte {
	t.Helper()

	contents, err := os.ReadFile(filepath.Join(repositoryRoot(t), relativePath))
	require.NoError(t, err)
	return contents
}

func withV1OpenPort(config []byte, port int) []byte {
	return append(config, fmt.Sprintf("\nopen_port: %d\n", port)...)
}

func kubernetesConfig(t *testing.T, relativePath string) []byte {
	t.Helper()

	contents := integrationConfig(t, relativePath)
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	for {
		var resource struct {
			Kind string            `yaml:"kind"`
			Data map[string]string `yaml:"data"`
		}
		err := decoder.Decode(&resource)
		if errors.Is(err, io.EOF) {
			t.Fatal("ConfigMap with obi-config.yml was not found")
		}
		require.NoError(t, err)
		if resource.Kind != "ConfigMap" {
			continue
		}
		if config, ok := resource.Data["obi-config.yml"]; ok {
			return []byte(config)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()

	directory, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		require.NotEqual(t, directory, parent, "repository root was not found")
		directory = parent
	}
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
