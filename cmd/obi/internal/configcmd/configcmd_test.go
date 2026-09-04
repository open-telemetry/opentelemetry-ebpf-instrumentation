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
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
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

func TestRunConfigHelp(t *testing.T) {
	for _, helpFlag := range []string{"-h", "--help"} {
		t.Run(helpFlag, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			exitCode := run([]string{helpFlag}, &stdout, &stderr)

			require.Equal(t, ExitSuccess, exitCode)
			require.Empty(t, stdout.String())
			require.Equal(t, "usage: obi config <validate|migrate> ...\n", stderr.String())
		})
	}
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

func TestValidateConfigAcceptsLastMatchWins(t *testing.T) {
	require.NoError(t, validateConfig([]byte(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: exclude
        match_order: last_match_wins
      rules:
        - action: include
          match:
            process:
              exe_path_glob: ["/srv/*"]
        - action: exclude
          match:
            process:
              exe_path_glob: ["/srv/private/*"]
    daemon:
      logging:
        debug_trace_output: text
`), validationModeStandalone))
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

func TestValidateConfigRejectsDivergentFlowLimitAliases(t *testing.T) {
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
      limits:
        network_packets: 74
      network:
        capture:
          flow_lifecycle:
            max_tracked_flows: 75
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
limits:
  network_packets: 74
network:
  capture:
    flow_lifecycle:
      max_tracked_flows: 75
`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateConfig([]byte(test.yaml), test.mode)
			require.EqualError(
				t,
				err,
				"capture.limits.network_packets (74) must equal "+
					"capture.network.capture.flow_lifecycle.max_tracked_flows (75): "+
					"both configure network.cache_max_flows",
			)
		})
	}
}

func TestValidateConfigAcceptsSingleFlowLimitAlias(t *testing.T) {
	tests := []struct {
		name string
		mode validationMode
		yaml string
	}{
		{
			name: "standalone limits",
			mode: validationModeStandalone,
			yaml: `
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      limits:
        network_packets: 74
    daemon:
      logging:
        debug_trace_output: text
`,
		},
		{
			name: "standalone lifecycle",
			mode: validationModeStandalone,
			yaml: `
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      network:
        capture:
          flow_lifecycle:
            max_tracked_flows: 75
    daemon:
      logging:
        debug_trace_output: text
`,
		},
		{
			name: "receiver limits",
			mode: validationModeReceiver,
			yaml: `
version: "2.0"
limits:
  network_packets: 74
`,
		},
		{
			name: "receiver lifecycle",
			mode: validationModeReceiver,
			yaml: `
version: "2.0"
network:
  capture:
    flow_lifecycle:
      max_tracked_flows: 75
`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.NoError(t, validateConfig([]byte(test.yaml), test.mode))
		})
	}
}

func TestValidateConfigRejectsZeroFlowLimitAlias(t *testing.T) {
	tests := []struct {
		name string
		mode validationMode
		yaml string
		want string
	}{
		{
			name: "standalone limits",
			mode: validationModeStandalone,
			yaml: `
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      limits:
        network_packets: 0
    daemon:
      logging:
        debug_trace_output: text
`,
			want: "capture.limits.network_packets must be greater than zero",
		},
		{
			name: "standalone lifecycle",
			mode: validationModeStandalone,
			yaml: `
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      network:
        capture:
          flow_lifecycle:
            max_tracked_flows: 0
    daemon:
      logging:
        debug_trace_output: text
`,
			want: "capture.network.capture.flow_lifecycle.max_tracked_flows must be greater than zero",
		},
		{
			name: "receiver limits",
			mode: validationModeReceiver,
			yaml: `
version: "2.0"
limits:
  network_packets: 0
`,
			want: "capture.limits.network_packets must be greater than zero",
		},
		{
			name: "receiver lifecycle",
			mode: validationModeReceiver,
			yaml: `
version: "2.0"
network:
  capture:
    flow_lifecycle:
      max_tracked_flows: 0
`,
			want: "capture.network.capture.flow_lifecycle.max_tracked_flows must be greater than zero",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.EqualError(t, validateConfig([]byte(test.yaml), test.mode), test.want)
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
			name: "unsupported attribute limits",
			yaml: strings.Replace(
				validStandaloneV2,
				"file_format: \"1.0\"\n",
				"file_format: \"1.0\"\nattribute_limits: {}\n",
				1,
			),
			want: "attribute_limits is not supported by the OBI runtime converter",
		},
		{
			name: "unsupported disabled document",
			yaml: strings.Replace(
				validStandaloneV2,
				"file_format: \"1.0\"\n",
				"file_format: \"1.0\"\ndisabled: true\n",
				1,
			),
			want: "disabled is not supported by the OBI runtime converter",
		},
		{
			name: "capture rule missing action",
			yaml: strings.Replace(
				validStandaloneV2,
				"        - action: include\n",
				"        - name: missing-action\n",
				1,
			),
			want: "capture.rules[0].action",
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

func TestMigrationGoldenFiles(t *testing.T) {
	t.Setenv("CART_ROOT", "/srv")
	t.Setenv("OTLP_HOST", "collector")
	t.Setenv("OTEL_EBPF_BPF_WAKEUP_LEN", "999")

	defaultConfig := integrationConfig(
		t,
		"devdocs/config/version-2.0/examples/default-configuration.yaml",
	)
	require.NoError(t, validateConfig(defaultConfig, validationModeStandalone))

	input := integrationConfig(
		t,
		"cmd/obi/internal/configcmd/testdata/migration-v1.yaml",
	)
	wantStandalone := integrationConfig(
		t,
		"cmd/obi/internal/configcmd/testdata/migration-v2.yaml",
	)
	output, report, err := migrateConfig(input)
	require.NoError(t, err)
	require.Equal(t, wantStandalone, output)
	require.Contains(t, string(output), "wakeup_len: 500")
	require.Equal(t, `migrated v1 config to OBI config v2
- fanned out v1 attribute filters to signal-scoped v2 filters
- reshaped effective discovery selectors into capture.rules
- expanded v1 route settings into incoming and outgoing HTTP route policies
- moved exporter configuration into top-level OpenTelemetry providers
`, report)

	_, standalone, err := schema.ParseStandaloneYAML(output)
	require.NoError(t, err)

	receiverData := integrationConfig(
		t,
		"cmd/obi/internal/configcmd/testdata/migration-receiver-v2.yaml",
	)
	receiverInput := integrationConfig(
		t,
		"cmd/obi/internal/configcmd/testdata/migration-receiver-v1.yaml",
	)
	receiverOutput, receiverReport, err := migrateConfigForMode(
		receiverInput,
		validationModeReceiver,
	)
	require.NoError(t, err)
	require.Equal(t, receiverData, receiverOutput)
	require.Contains(t, receiverReport, "capture.rules")
	receiverOutputAgain, receiverReportAgain, err := migrateConfigForMode(
		receiverInput,
		validationModeReceiver,
	)
	require.NoError(t, err)
	require.Equal(t, receiverOutput, receiverOutputAgain)
	require.Equal(t, receiverReport, receiverReportAgain)

	receiver, err := schema.ParseReceiverYAML(receiverData)
	require.NoError(t, err)
	require.Equal(t, standalone.Version, receiver.Version)
	require.Equal(t, standalone.Capture, receiver.Capture)
	require.NoError(t, validateConfig(receiverData, validationModeReceiver))

	rewired := bytes.Replace(
		output,
		[]byte("wakeup_len: 500"),
		[]byte("wakeup_len: ${OTEL_EBPF_BPF_WAKEUP_LEN:-500}"),
		1,
	)
	require.NotEqual(t, output, rewired)
	require.NoError(t, validateConfig(rewired, validationModeStandalone))

	rewiredDoc, _, err := schema.ParseStandaloneYAML(obiconfig.ReplaceEnv(rewired))
	require.NoError(t, err)
	rewiredRuntime, err := convert.DocumentToRuntime(rewiredDoc)
	require.NoError(t, err)
	require.Equal(t, 999, rewiredRuntime.EBPF.WakeupLen)
}

func TestRunMigrateReceiver(t *testing.T) {
	path := writeConfig(t, "receiver-v1.yaml", `open_port: "8080"`)
	var stdout, stderr bytes.Buffer

	exitCode := run(
		[]string{"migrate", "--mode=receiver", path},
		&stdout,
		&stderr,
	)

	require.Equal(t, ExitSuccess, exitCode, stderr.String())
	require.Contains(t, stdout.String(), `version: "2.0"`)
	require.NotContains(t, stdout.String(), "file_format:")
	require.NotContains(t, stdout.String(), "extensions:")
	require.Contains(t, stderr.String(), "capture.rules")
	receiver, err := schema.ParseReceiverYAML(stdout.Bytes())
	require.NoError(t, err)
	require.NoError(t, validateConfig(stdout.Bytes(), validationModeReceiver))
	require.Equal(
		t,
		[]int{8080},
		receiver.Capture.Rules[len(receiver.Capture.Rules)-1].
			Match.Process.OpenPorts.AllValues(),
	)
}

func TestMigrateConfigReceiverRejectsWrongInputShape(t *testing.T) {
	_, _, err := migrateConfigForMode(
		[]byte("version: \"2.0\"\npolicy: {}\n"),
		validationModeReceiver,
	)
	require.ErrorContains(t, err, "already a receiver OBI config v2 document")

	_, _, err = migrateConfigForMode([]byte(`
open_port: "8080"
otel_traces_export:
  endpoint: http://collector:4317
`), validationModeReceiver)
	require.ErrorContains(t, err, "otel_traces_export.endpoint")
}

func TestMigrateConfigReceiverRejectsStandaloneOnlyV1Fields(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "Kubernetes enrichment",
			yaml: `
attributes:
  kubernetes:
    cluster_name: production
`,
			want: "attributes.kubernetes.cluster_name",
		},
		{
			name: "name resolution",
			yaml: `
name_resolver:
  sources: [dns]
`,
			want: "name_resolver.sources",
		},
		{
			name: "log correlation",
			yaml: `
ebpf:
  log_enricher:
    cache_size: 256
`,
			want: "ebpf.log_enricher.cache_size",
		},
		{
			name: "daemon telemetry",
			yaml: `
internal_metrics:
  exporter: prometheus
  prometheus:
    port: 9090
`,
			want: "internal_metrics.exporter",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := migrateConfigForMode(
				[]byte("open_port: \"8080\"\n"+test.yaml),
				validationModeReceiver,
			)

			require.ErrorContains(t, err, test.want)
		})
	}
}

func TestMigrationEnvironmentSelectorExample(t *testing.T) {
	example := []byte(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: exclude
        match_order: first_match_wins
      rules:
        - action: include
          match:
            process:
              exe_path_glob: ["/srv/*"]
              language_glob: [go, java]
    daemon:
      logging:
        debug_trace_output: text
`)

	require.NoError(t, validateConfig(example, validationModeStandalone))
	doc, ext, err := schema.ParseStandaloneYAML(example)
	require.NoError(t, err)
	require.Equal(
		t,
		[]string{"/srv/*"},
		ext.Capture.Rules[0].Match.Process.ExePathGlob,
	)
	require.Equal(
		t,
		[]string{"go", "java"},
		ext.Capture.Rules[0].Match.Process.LanguageGlob,
	)

	cfg, err := convert.DocumentToRuntime(doc)
	require.NoError(t, err)
	require.Len(t, cfg.Discovery.Instrument, 1)
	require.True(t, cfg.Discovery.Instrument[0].Path.MatchString("/srv/api"))
	require.True(t, cfg.Discovery.Instrument[0].Languages.MatchString("go"))
	require.True(t, cfg.Discovery.Instrument[0].Languages.MatchString("java"))
	require.False(t, cfg.Discovery.Instrument[0].Languages.MatchString("python"))
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

func TestMigrateConfigAcceptsSemanticNormalization(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "trace ID ratio sampler",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
otel_traces_export:
  endpoint: http://collector:4317
  sampler:
    name: traceidratio
    arg: "0.10"
`,
			want: "ratio: 0.1",
		},
		{
			name: "parent-based trace ID ratio sampler",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
otel_traces_export:
  endpoint: http://collector:4317
  sampler:
    name: parentbased_traceidratio
    arg: "0.10"
`,
			want: "ratio: 0.1",
		},
		{
			name: "effective metric interval",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
otel_metrics_export:
  endpoint: http://collector:4317
  interval: 0s
`,
			want: "interval: 60000",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, _, err := migrateConfig([]byte(test.yaml))
			require.NoError(t, err)
			require.Contains(t, string(output), test.want)
		})
	}
}

func TestConfigCommandsSuppressRuntimeValidationLogs(t *testing.T) {
	originalLogger := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() {
		slog.SetDefault(originalLogger)
	})

	path := writeConfig(t, "v1.yaml", `
discovery:
  instrument:
    - exe_path: "/srv/*"
otel_traces_export:
  endpoint: http://collector:4317
  batch_max_size: 10
  queue_size: 0
`)
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"migrate", path}, &stdout, &stderr)

	require.Equal(t, ExitSuccess, exitCode, stderr.String())
	require.Empty(t, logs.String())
	require.Equal(t, `migrated v1 config to OBI config v2
- reshaped effective discovery selectors into capture.rules
- moved exporter configuration into top-level OpenTelemetry providers
`, stderr.String())
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

func TestMigrateConfigExpandsGlobalRoutes(t *testing.T) {
	output, report, err := migrateConfig([]byte(`
routes:
  unmatched: path
  patterns: ["/users/{id}"]
  ignored_patterns: ["/health"]
  ignore_mode: metrics
  wildcard_char: "#"
  max_path_segment_cardinality: 25
discovery:
  instrument:
    - exe_path: "/srv/*"
metrics:
  features: [application]
prometheus_export:
  port: 9090
`))
	require.NoError(t, err)
	require.Contains(t, report, "incoming and outgoing HTTP route policies")

	_, ext, err := schema.ParseStandaloneYAML(output)
	require.NoError(t, err)

	for _, policy := range []*schema.HTTPRoutePolicy{
		ext.Capture.Instrumentation.HTTP.Routes.Incoming,
		ext.Capture.Instrumentation.HTTP.Routes.Outgoing,
	} {
		require.NotNil(t, policy)
		require.Equal(t, "path", string(*policy.Unmatched))
		require.Equal(t, []string{"/users/{id}"}, *policy.Patterns)
		require.Equal(t, []string{"/health"}, *policy.IgnoredPatterns)
		require.Equal(t, "metrics", string(*policy.IgnoreMode))
		require.Equal(t, "#", *policy.WildcardChar)
		require.Equal(t, 25, *policy.MaxPathSegmentCardinality)
	}
}

func TestMigrateConfigPreservesPerServiceRoutes(t *testing.T) {
	output, report, err := migrateConfig([]byte(`
discovery:
  instrument:
    - exe_path: "/srv/*"
      routes:
        incoming: ["/users/{id}"]
        outgoing: ["/inventory/{id}"]
metrics:
  features: [application]
prometheus_export:
  port: 9090
`))
	require.NoError(t, err)
	require.Contains(t, report, "incoming and outgoing HTTP route policies")

	_, ext, err := schema.ParseStandaloneYAML(output)
	require.NoError(t, err)
	require.NotEmpty(t, ext.Capture.Rules)

	rule := ext.Capture.Rules[len(ext.Capture.Rules)-1]
	require.NotNil(t, rule.Refine.HTTP)
	require.Equal(t, []string{"/users/{id}"}, *rule.Refine.HTTP.Routes.Incoming.Patterns)
	require.Equal(t, []string{"/inventory/{id}"}, *rule.Refine.HTTP.Routes.Outgoing.Patterns)
}

func TestMigrateConfigDeterministicSelectorExports(t *testing.T) {
	input := []byte(`
discovery:
  instrument:
    - exe_path: "/srv/*"
      exports: [metrics, traces]
metrics:
  features: [application]
prometheus_export:
  port: 9090
`)
	wantOutput, wantReport, err := migrateConfig(input)
	require.NoError(t, err)

	for range 100 {
		output, report, err := migrateConfig(input)
		require.NoError(t, err)
		require.Equal(t, wantOutput, output)
		require.Equal(t, wantReport, report)
	}
}

func TestMigrateConfigOrdersOverlappingRefinementsForFirstMatch(t *testing.T) {
	output, _, err := migrateConfig([]byte(`
discovery:
  instrument:
    - exe_path: "/srv/*"
      exports: [metrics]
    - exe_path: "/srv/payments/*"
      exports: [traces]
metrics:
  features: [application]
otel_traces_export:
  endpoint: http://collector:4317
prometheus_export:
  port: 9090
`))
	require.NoError(t, err)

	_, ext, err := schema.ParseStandaloneYAML(output)
	require.NoError(t, err)
	var includes []schema.Rule
	for _, rule := range ext.Capture.Rules {
		if rule.Action == schema.CaptureActionInclude {
			includes = append(includes, rule)
		}
	}
	require.Len(t, includes, 2)
	require.Equal(
		t,
		[]string{"/srv/payments/*"},
		includes[0].Match.Process.ExePathGlob,
	)
	require.Equal(t, []string{"/srv/*"}, includes[1].Match.Process.ExePathGlob)
}

func TestMigrateConfigRejectsMixedSelectorRefinementInheritance(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "exports",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
      exports: [metrics]
    - exe_path: "/srv/payments/*"
metrics:
  features: [application]
otel_traces_export:
  endpoint: http://collector:4317
prometheus_export:
  port: 9090
`,
			want: "mix explicit and omitted fields: exports",
		},
		{
			name: "routes",
			yaml: `
discovery:
  services:
    - exe_path: "^/srv/.*"
      routes:
        incoming: ["/api/{id}"]
    - exe_path: "^/srv/payments/.*"
trace_printer: text
`,
			want: "mix explicit and omitted fields: routes",
		},
		{
			name: "exports and routes",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
      exports: [metrics]
      routes:
        incoming: ["/api/{id}"]
    - exe_path: "/srv/payments/*"
metrics:
  features: [application]
prometheus_export:
  port: 9090
`,
			want: "mix explicit and omitted fields: exports, routes",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := migrateConfig([]byte(test.yaml))
			require.ErrorContains(t, err, test.want)
		})
	}
}

func TestMigrateConfigRejectsMixedSelectorRefinementsInReceiverMode(t *testing.T) {
	_, _, err := migrateConfigForMode([]byte(`
discovery:
  instrument:
    - exe_path: "/srv/*"
      exports: [metrics]
    - exe_path: "/srv/payments/*"
metrics:
  features: [application]
`), validationModeReceiver)

	require.ErrorContains(t, err, "mix explicit and omitted fields: exports")
}

func TestMigrateConfigRejectsMixedRefinementWithSyntheticSelector(t *testing.T) {
	_, _, err := migrateConfig([]byte(`
open_port: "8080"
discovery:
  instrument:
    - exe_path: "/srv/*"
      exports: [metrics]
metrics:
  features: [application]
prometheus_export:
  port: 9090
`))

	require.ErrorContains(t, err, "mix explicit and omitted fields: exports")
}

func TestMigrateConfigAllowsExplicitRoutesOnEverySelector(t *testing.T) {
	output, _, err := migrateConfig([]byte(`
discovery:
  instrument:
    - exe_path: "/srv/*"
      routes:
        incoming: ["/api/{id}"]
    - exe_path: "/srv/payments/*"
      routes: {}
trace_printer: text
`))
	require.NoError(t, err)

	_, ext, err := schema.ParseStandaloneYAML(output)
	require.NoError(t, err)
	var includes []schema.Rule
	for _, rule := range ext.Capture.Rules {
		if rule.Action == schema.CaptureActionInclude {
			includes = append(includes, rule)
		}
	}
	require.Len(t, includes, 2)
	require.Equal(
		t,
		[]string{"/srv/payments/*"},
		includes[0].Match.Process.ExePathGlob,
	)
	require.Nil(t, includes[0].Refine.HTTP)
	require.NotNil(t, includes[1].Refine.HTTP)
}

func TestMigrateConfigPreservesReorderedInstrumentations(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "traces",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
otel_traces_export:
  endpoint: http://collector:4317
  instrumentations: [grpc, http, sql, redis, kafka, mqtt, nats, amqp, mongo, couchbase, memcached, sunrpc, aerospike]
`,
		},
		{
			name: "OTLP metrics",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
metrics:
  features: [application]
otel_metrics_export:
  endpoint: http://collector:4317
  instrumentations: [http, nats, mqtt, amqp, genai, memcached, sunrpc, aerospike]
`,
		},
		{
			name: "Prometheus metrics",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
metrics:
  features: [application]
prometheus_export:
  port: 9090
  instrumentations: [http, nats, mqtt, amqp, genai, memcached, sunrpc, aerospike]
`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := migrateConfig([]byte(test.yaml))
			require.NoError(t, err)
		})
	}
}

func TestMigrateConfigRejectsNetworkEnablementChange(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "omitted enable",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
network:
  print_flows: true
metrics:
  features: [application, network]
otel_traces_export:
  endpoint: http://collector:4317
`,
			want: "metrics.features",
		},
		{
			name: "explicit false",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
network:
  enable: false
  print_flows: true
metrics:
  features: [application, network]
otel_traces_export:
  endpoint: http://collector:4317
`,
			want: "network.enable",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := migrateConfig([]byte(test.yaml))
			require.ErrorContains(t, err, test.want)
		})
	}
}

func TestMigrateConfigRejectsLayeredRoutePatterns(t *testing.T) {
	_, _, err := migrateConfig([]byte(`
routes:
  patterns: ["/global/{id}"]
discovery:
  instrument:
    - exe_path: "/srv/*"
      routes:
        incoming: ["/users/{id}"]
metrics:
  features: [application]
prometheus_export:
  port: 9090
`))
	require.ErrorContains(t, err, "discovery.instrument[0].routes.incoming")
}

func TestMigrateConfigPreservesExplicitGRPCProtocol(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "traces",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
otel_traces_export:
  endpoint: http://collector:4318
  protocol: grpc
`,
		},
		{
			name: "metrics",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
metrics:
  features: [application]
otel_metrics_export:
  endpoint: http://collector:4318
  protocol: grpc
`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, _, err := migrateConfig([]byte(test.yaml))
			require.NoError(t, err)
			require.Contains(t, string(output), "otlp_grpc:")
		})
	}
}

func TestMigrateConfigPreservesDefaultDNSMetrics(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "OTLP",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
metrics:
  features: [application]
otel_metrics_export:
  endpoint: http://collector:4317
`,
		},
		{
			name: "Prometheus",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
metrics:
  features: [application]
prometheus_export:
  port: 9090
`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, _, err := migrateConfig([]byte(test.yaml))
			require.NoError(t, err)

			_, ext, err := schema.ParseStandaloneYAML(output)
			require.NoError(t, err)
			require.True(t, ext.Capture.Instrumentation.DNS.Enabled.Metrics)
		})
	}
}

func TestMigrateConfigAllowsDisabledEmptyExporterEndpoints(t *testing.T) {
	for _, exporter := range []string{"otel_traces_export", "otel_metrics_export"} {
		t.Run(exporter, func(t *testing.T) {
			_, _, err := migrateConfig([]byte(fmt.Sprintf(`
discovery:
  instrument:
    - exe_path: "/srv/*"
prometheus_export:
  port: 9090
%s:
  endpoint: ""
  protocol: ""
`, exporter)))
			require.NoError(t, err)
		})
	}
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
    - open_ports: 5000
otel_traces_export:
  endpoint: http://collector:4317
`))
	require.NoError(t, err)
	require.Empty(t, logs.String())
	require.Contains(t, report, "capture.rules")

	doc, _, err := schema.ParseStandaloneYAML(output)
	require.NoError(t, err)
	runtimeConfig, err := convert.DocumentToRuntime(doc)
	require.NoError(t, err)
	require.Len(t, runtimeConfig.Discovery.Services, 2)
	require.True(t, runtimeConfig.Discovery.Services[0].Path.MatchString("/srv/api"))
	require.True(t, runtimeConfig.Discovery.Services[1].Path.MatchString("/any/executable"))
	require.True(t, runtimeConfig.Discovery.Services[1].OpenPorts.Matches(5000))
	require.Equal(
		t,
		obi.DefaultConfig.Discovery.ExcludedLinuxSystemPaths,
		runtimeConfig.Discovery.ExcludedLinuxSystemPaths,
	)
}

func TestMigrateConfigSupportsDeprecatedExecutablePath(t *testing.T) {
	output, report, err := migrateConfig([]byte(`
executable_path: "^/srv/api$"
discovery:
  exclude_instrument:
    - exe_path: "/custom/{one,two}/service-??"
    - exe_path: "{[a,b],c}"
  default_exclude_instrument: []
otel_traces_export:
  endpoint: http://collector:4317
`))
	require.NoError(t, err)
	require.Contains(t, report, "capture.rules")

	doc, _, err := schema.ParseStandaloneYAML(output)
	require.NoError(t, err)
	runtimeConfig, err := convert.DocumentToRuntime(doc)
	require.NoError(t, err)
	require.Len(t, runtimeConfig.Discovery.Services, 1)
	require.True(t, runtimeConfig.Discovery.Services[0].Path.MatchString("/srv/api"))
	require.Len(t, runtimeConfig.Discovery.ExcludeServices, 2)
	require.True(t, runtimeConfig.Discovery.ExcludeServices[0].Path.MatchString("/custom/one/service-ab"))
	require.False(t, runtimeConfig.Discovery.ExcludeServices[0].Path.MatchString("/custom/three/service-ab"))
	require.True(t, runtimeConfig.Discovery.ExcludeServices[1].Path.MatchString("a"))
	require.True(t, runtimeConfig.Discovery.ExcludeServices[1].Path.MatchString("b"))
	require.True(t, runtimeConfig.Discovery.ExcludeServices[1].Path.MatchString("c"))
	require.Equal(
		t,
		obi.DefaultConfig.Discovery.ExcludedLinuxSystemPaths,
		runtimeConfig.Discovery.ExcludedLinuxSystemPaths,
	)
}

func TestMigrateConfigSupportsDeprecatedPathRegexp(t *testing.T) {
	output, _, err := migrateConfig([]byte(`
discovery:
  services:
    - exe_path_regexp: "^/srv/.*$"
  exclude_services:
    - exe_path_regexp: "^/srv/private/.*$"
  default_exclude_services:
    - exe_path_regexp: "^/usr/bin/obi$"
otel_traces_export:
  endpoint: http://collector:4317
`))
	require.NoError(t, err)

	doc, _, err := schema.ParseStandaloneYAML(output)
	require.NoError(t, err)
	runtimeConfig, err := convert.DocumentToRuntime(doc)
	require.NoError(t, err)
	require.Len(t, runtimeConfig.Discovery.Services, 1)
	require.True(t, runtimeConfig.Discovery.Services[0].Path.MatchString("/srv/api"))
	require.Len(t, runtimeConfig.Discovery.ExcludeServices, 2)
	var matchesDefault, matchesPrivate bool
	for _, selector := range runtimeConfig.Discovery.ExcludeServices {
		matchesDefault = matchesDefault || selector.Path.MatchString("/usr/bin/obi")
		matchesPrivate = matchesPrivate || selector.Path.MatchString("/srv/private/api")
	}
	require.True(t, matchesDefault)
	require.True(t, matchesPrivate)
}

func TestMigrateConfigRejectsCustomLanguageDetectionSkips(t *testing.T) {
	for _, value := range []string{
		"[]",
		`["/opt/system-services/"]`,
		`["/lib/systemd/"]`,
	} {
		_, _, err := migrateConfig([]byte(fmt.Sprintf(`
open_port: "8080"
discovery:
  excluded_linux_system_paths: %s
otel_traces_export:
  endpoint: http://collector:4317
`, value)))

		require.ErrorContains(t, err, "discovery.excluded_linux_system_paths")
	}
}

func TestMigrateConfigAcceptsDefaultLanguageDetectionSkips(t *testing.T) {
	output, _, err := migrateConfig([]byte(`
open_port: "8080"
discovery:
  excluded_linux_system_paths:
    - /lib/systemd/
    - /usr/lib/systemd/
    - /usr/libexec/
    - /sbin/
    - /usr/sbin/
otel_traces_export:
  endpoint: http://collector:4317
`))
	require.NoError(t, err)

	doc, _, err := schema.ParseStandaloneYAML(output)
	require.NoError(t, err)
	runtimeConfig, err := convert.DocumentToRuntime(doc)
	require.NoError(t, err)
	require.Equal(
		t,
		obi.DefaultConfig.Discovery.ExcludedLinuxSystemPaths,
		runtimeConfig.Discovery.ExcludedLinuxSystemPaths,
	)
}

func TestMigrateIntegrationConfigurations(t *testing.T) {
	tests := []struct {
		name   string
		input  func(t *testing.T) []byte
		verify func(t *testing.T, cfg *obi.Config)
	}{
		{
			name: "Docker Go OTEL gRPC",
			input: func(t *testing.T) []byte {
				return integrationConfig(t, "internal/test/integration/configs/obi-config-go-otel-grpc.yml")
			},
			verify: func(t *testing.T, cfg *obi.Config) {
				require.True(t, cfg.Enabled(obi.FeatureAppO11y))
				require.Len(t, cfg.Discovery.Instrument, 1)
				require.True(t, cfg.Discovery.Instrument[0].OpenPorts.Matches(8080))
				require.Equal(t, 8999, cfg.Prometheus.Port)
				require.Equal(t, "http://jaeger:4317", cfg.Traces.TracesEndpoint)
				require.Equal(t, otelcfg.ProtocolGRPC, cfg.Traces.TracesProtocol)
				require.NotNil(t, cfg.Routes)
				routes := cfg.Routes.DirectionalPolicies()
				require.Equal(t, "path", string(routes.Incoming.Unmatch))
				require.Equal(t, "path", string(routes.Outgoing.Unmatch))
			},
		},
		{
			name: "Docker Java",
			input: func(t *testing.T) []byte {
				return integrationConfig(t, "internal/test/integration/configs/obi-config-java.yml")
			},
			verify: func(t *testing.T, cfg *obi.Config) {
				require.True(t, cfg.Enabled(obi.FeatureAppO11y))
				require.Len(t, cfg.Discovery.Instrument, 1)
				require.True(t, cfg.Discovery.Instrument[0].OpenPorts.Matches(8085))
				require.Equal(t, "http://otelcol:4317", cfg.OTELMetrics.MetricsEndpoint)
				require.Equal(t, otelcfg.ProtocolGRPC, cfg.OTELMetrics.MetricsProtocol)
				require.NotNil(t, cfg.Routes)
				routes := cfg.Routes.DirectionalPolicies()
				require.Equal(t, []string{"/greeting"}, routes.Incoming.Patterns)
				require.Equal(t, []string{"/greeting"}, routes.Outgoing.Patterns)
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
				require.Equal(t, []string{"deployment.environment.name"}, cfg.Attributes.Kubernetes.ResourceLabels["deployment.environment.name"])
				require.Len(t, cfg.Discovery.Instrument, 5)
				require.GreaterOrEqual(t, len(cfg.Discovery.ExcludeInstrument), 1)
				require.True(t, cfg.Discovery.Instrument[0].Metadata["k8s_deployment_name"].MatchString("testserver"))
				require.True(t, cfg.Discovery.ExcludeInstrument[0].Metadata["k8s_deployment_name"].MatchString("testserver"))
				require.Equal(t, "http://otelcol:4317", cfg.OTELMetrics.MetricsEndpoint)
				require.Equal(t, otelcfg.ProtocolGRPC, cfg.OTELMetrics.MetricsProtocol)
				require.Equal(t, "http://otelcol:4317", cfg.Traces.TracesEndpoint)
				require.Equal(t, otelcfg.ProtocolGRPC, cfg.Traces.TracesProtocol)
				require.NotNil(t, cfg.Routes)
				routes := cfg.Routes.DirectionalPolicies()
				require.Equal(t, []string{"/metrics"}, routes.Incoming.IgnorePatterns)
				require.Equal(t, []string{"/metrics"}, routes.Outgoing.IgnorePatterns)
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
				require.Equal(t, "http://otelcol:4317", cfg.Traces.TracesEndpoint)
				require.Equal(t, otelcfg.ProtocolGRPC, cfg.Traces.TracesProtocol)
				require.NotNil(t, cfg.Routes)
				routes := cfg.Routes.DirectionalPolicies()
				require.Equal(t, []string{"/pingpong"}, routes.Incoming.Patterns)
				require.Equal(t, []string{"/pingpong"}, routes.Outgoing.Patterns)
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

func TestCollectorReceiverExamples(t *testing.T) {
	for _, path := range []string{
		"examples/otel-collector/config.yaml",
		"examples/otel-collector/smoke-config.yaml",
	} {
		t.Run(path, func(t *testing.T) {
			data := integrationConfig(t, path)
			var collector struct {
				Receivers struct {
					OBI map[string]any `yaml:"obi"`
				} `yaml:"receivers"`
			}
			require.NoError(t, yaml.Unmarshal(data, &collector))
			require.NotEmpty(t, collector.Receivers.OBI)

			receiverData, err := yaml.Marshal(collector.Receivers.OBI)
			require.NoError(t, err)
			receiver, err := schema.ParseReceiverYAML(receiverData)
			require.NoError(t, err)
			require.Equal(
				t,
				schema.CaptureActionExclude,
				receiver.Capture.Policy.DefaultAction,
			)
			require.NoError(t, validateConfig(receiverData, validationModeReceiver))
		})
	}
}

func integrationConfig(t *testing.T, relativePath string) []byte {
	t.Helper()

	contents, err := os.ReadFile(filepath.Join(repositoryRoot(t), relativePath))
	require.NoError(t, err)
	return contents
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
			name: "unsupported metric feature",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
metrics:
  features: [application, application_span]
prometheus_export:
  port: 9090
`,
			want: "metrics.features",
		},
		{
			name: "unknown metric feature",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
metrics:
  features: [application, totally_unknown]
prometheus_export:
  port: 9090
`,
			want: "metrics.features",
		},
		{
			name: "non-string metric feature",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
metrics:
  features: [application, 123]
prometheus_export:
  port: 9090
`,
			want: "metrics.features",
		},
		{
			name: "unknown deprecated metric feature",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
otel_metrics_export:
  endpoint: http://collector:4317
  features: [application, totally_unknown]
`,
			want: "otel_metrics_export.features",
		},
		{
			name: "per-service metric features",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
      metrics:
        features: [application]
prometheus_export:
  port: 9090
`,
			want: "discovery.instrument[0].metrics.features",
		},
		{
			name: "unsupported instrumentation selection",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
otel_traces_export:
  endpoint: http://collector:4317
  instrumentations: [http]
`,
			want: "otel_traces_export.instrumentations",
		},
		{
			name: "invalid trace ID ratio sampler argument",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
otel_traces_export:
  endpoint: http://collector:4317
  sampler:
    name: traceidratio
    arg: invalid
`,
			want: "otel_traces_export.sampler.arg",
		},
		{
			name: "implicit HTTP trace protocol",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
otel_traces_export:
  endpoint: http://collector:4318
`,
			want: "otel_traces_export.endpoint",
		},
		{
			name: "implicit HTTP metric protocol",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
metrics:
  features: [application]
otel_metrics_export:
  endpoint: http://collector:4318
`,
			want: "otel_metrics_export.endpoint",
		},
		{
			name: "implicit HTTP trace protocol explicitly empty",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
otel_traces_export:
  endpoint: http://collector:4318
  protocol: ""
`,
			want: "otel_traces_export.endpoint",
		},
		{
			name: "implicit HTTP metric protocol explicitly empty",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
metrics:
  features: [application]
otel_metrics_export:
  endpoint: http://collector:4318
  protocol: ""
`,
			want: "otel_metrics_export.endpoint",
		},
		{
			name: "unsupported exclusion selector field",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
  exclude_instrument:
    - name: ignored
      exe_path: "/tmp/*"
metrics:
  features: [application]
prometheus_export:
  port: 9090
`,
			want: "discovery.exclude_instrument[0].name",
		},
		{
			name: "unsupported legacy selector field",
			yaml: `
discovery:
  services:
    - name: ignored
      exe_path_regexp: "^/srv/.*$"
otel_traces_export:
  endpoint: http://collector:4317
`,
			want: "discovery.services[0].name",
		},
		{
			name: "already v2",
			yaml: validStandaloneV2,
			want: "already a standalone OBI config v2",
		},
		{
			name: "debug trace exporter",
			yaml: `
discovery:
  instrument:
    - exe_path: "/srv/*"
otel_traces_export:
  protocol: debug
`,
			want: "otel_traces_export.protocol",
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
		{name: "invalid migrate mode", args: []string{"migrate", "--mode=other", "missing"}, want: ExitUsage},
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
