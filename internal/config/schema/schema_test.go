// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseStandaloneYAMLDocument(t *testing.T) {
	t.Parallel()

	doc, cfg, err := ParseStandaloneYAML([]byte(`
file_format: "1.0"
resource:
  attributes:
    service.namespace: checkout
propagator:
  composite: [tracecontext, baggage]
tracer_provider:
  sampler:
    parent_based:
      root:
        always_on: {}
meter_provider:
  readers:
    - periodic: {}
instrumentation/development:
  ignored: true
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: include
      rules:
        - action: include
          name: checkout
          match:
            process:
              exe_path_glob: ["/usr/bin/checkout"]
          refine:
            exports:
              traces: false
              metrics: true
            http:
              routes:
                unmatched: wildcard
                patterns: ["/orders/{id}"]
              filters:
                traces:
                  status_code: ["5*"]
`))

	require.NoError(t, err)
	require.NotNil(t, doc)
	require.NotNil(t, cfg)
	require.Equal(t, "1.0", doc.FileFormat)
	require.Equal(t, SupportedVersion, cfg.Version)
	require.Equal(t, map[string]any{
		"root": map[string]any{
			"always_on": map[string]any{},
		},
	}, nestedMap(doc.TracerProvider, "sampler", "parent_based"))
	require.Equal(t, []any{map[string]any{"periodic": map[string]any{}}}, doc.MeterProvider["readers"])
	require.Equal(t, "include", cfg.Capture.Policy["default_action"])
	require.Len(t, cfg.Capture.Rules, 1)
	require.Equal(t, map[string]any{"traces": false, "metrics": true}, cfg.Capture.Rules[0].Refine.Exports)
	require.Equal(t, map[string]any{
		"routes": map[string]any{
			"unmatched": "wildcard",
			"patterns":  []any{"/orders/{id}"},
		},
		"filters": map[string]any{
			"traces": map[string]any{
				"status_code": []any{"5*"},
			},
		},
	}, cfg.Capture.Rules[0].Refine.HTTP)
}

func TestParseReceiverYAMLEmbedded(t *testing.T) {
	t.Parallel()

	cfg, err := ParseReceiverYAML([]byte(`
version: "2.0"
policy:
  default_action: exclude
rules:
  - action: include
    match:
      process:
        open_ports: 8080,8443
instrumentation:
  http:
    enabled:
      traces: true
      metrics: false
channels:
  buffer_len: 123
`))

	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, SupportedVersion, cfg.Version)
	require.Equal(t, "exclude", cfg.Capture.Policy["default_action"])
	require.Len(t, cfg.Capture.Rules, 1)
	require.Equal(t, "8080,8443", nestedMap(cfg.Capture.Rules[0].Match, "process")["open_ports"])
	require.Equal(t, map[string]any{"buffer_len": 123}, cfg.Capture.Channels)
	require.True(t, nestedMap(cfg.Capture.Instrumentation, "http", "enabled")["traces"].(bool))
	require.False(t, nestedMap(cfg.Capture.Instrumentation, "http", "enabled")["metrics"].(bool))
}

func TestReceiverRejectsStandaloneSections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
	}{
		{name: "map", value: "{}"},
		{name: "implicit null", value: ""},
		{name: "explicit null", value: "null"},
		{name: "list", value: "[]"},
	}
	for _, section := range []string{sectionEnrich, sectionCorrelation, sectionDaemon} {
		t.Run(section, func(t *testing.T) {
			t.Parallel()

			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					t.Parallel()

					_, err := ParseReceiverYAML([]byte("version: \"2.0\"\n" + section + ": " + test.value + "\n"))

					var notAllowed *SectionNotAllowedError
					require.ErrorAs(t, err, &notAllowed)
					require.Equal(t, section, notAllowed.Section)
					require.Contains(t, err.Error(), "receiver config")
					require.Contains(t, err.Error(), "standalone mode")
				})
			}
		})
	}
}

func TestStandaloneAllowsStandaloneSections(t *testing.T) {
	t.Parallel()

	_, cfg, err := ParseStandaloneYAML([]byte(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: include
    enrich: {}
    correlation: {}
    daemon: {}
`))

	require.NoError(t, err)
	require.NotNil(t, cfg)
}

func TestValidateReceiverRejectsDecodedStandaloneSections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     Extension
		section string
	}{
		{
			name:    sectionEnrich,
			cfg:     Extension{Version: SupportedVersion, Enrich: map[string]any{}},
			section: sectionEnrich,
		},
		{
			name:    sectionCorrelation,
			cfg:     Extension{Version: SupportedVersion, Correlation: map[string]any{}},
			section: sectionCorrelation,
		},
		{
			name:    sectionDaemon,
			cfg:     Extension{Version: SupportedVersion, Daemon: map[string]any{}},
			section: sectionDaemon,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateReceiver(&test.cfg)

			var notAllowed *SectionNotAllowedError
			require.ErrorAs(t, err, &notAllowed)
			require.Equal(t, test.section, notAllowed.Section)
		})
	}
}

func TestUnsupportedVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		yaml  string
		parse func([]byte) error
		want  string
	}{
		{
			name: "document",
			yaml: `
file_format: "1.0"
extensions:
  obi:
    version: "3.0"
`,
			parse: func(data []byte) error {
				_, _, err := ParseStandaloneYAML(data)
				return err
			},
			want: "3.0",
		},
		{
			name: "receiver",
			yaml: `
version: "3.0"
`,
			parse: func(data []byte) error {
				_, err := ParseReceiverYAML(data)
				return err
			},
			want: "3.0",
		},
		{
			name: "non string",
			yaml: `
version: 2.0
`,
			parse: func(data []byte) error {
				_, err := ParseReceiverYAML(data)
				return err
			},
			want: "2.0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.parse([]byte(test.yaml))

			var unsupported *UnsupportedVersionError
			require.ErrorAs(t, err, &unsupported)
			require.Equal(t, test.want, unsupported.Version)
		})
	}
}

func TestStandaloneNotV2(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "empty",
			yaml: "",
			want: "missing extensions.obi.version field",
		},
		{
			name: "missing version",
			yaml: "file_format: \"1.0\"\n",
			want: "missing extensions.obi.version field",
		},
		{
			name: "v1",
			yaml: `
ebpf: {}
discovery: {}
otel_metrics_export: {}
otel_traces_export: {}
prometheus_export: {}
network: {}
stats: {}
`,
			want: "detected legacy v1 config shape",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := ParseStandaloneYAML([]byte(test.yaml))

			var notV2 *NotV2Error
			require.ErrorAs(t, err, &notV2)
			require.Contains(t, err.Error(), test.want)
		})
	}
}

func TestReceiverNotV2(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "empty",
			yaml: "",
			want: "missing top-level OBI v2 version field",
		},
		{
			name: "missing version",
			yaml: "policy: {}\n",
			want: "missing top-level OBI v2 version field",
		},
		{
			name: "missing version with network capture",
			yaml: `
network:
  capture:
    enabled: true
`,
			want: "missing top-level OBI v2 version field",
		},
		{
			name: "v1",
			yaml: `
ebpf: {}
discovery: {}
otel_metrics_export: {}
otel_traces_export: {}
prometheus_export: {}
network: {}
stats: {}
`,
			want: "detected legacy v1 config shape",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseReceiverYAML([]byte(test.yaml))

			var notV2 *NotV2Error
			require.ErrorAs(t, err, &notV2)
			require.Contains(t, err.Error(), test.want)
		})
	}
}

func TestSpecificParsersRejectWrongLayout(t *testing.T) {
	t.Parallel()

	_, _, err := ParseStandaloneYAML([]byte(`
version: "2.0"
policy:
  default_action: include
network: {}
`))
	var standaloneNotV2 *NotV2Error
	require.ErrorAs(t, err, &standaloneNotV2)
	require.Contains(t, err.Error(), "missing extensions.obi.version field")

	_, err = ParseReceiverYAML([]byte(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture: {}
`))
	var receiverNotV2 *NotV2Error
	require.ErrorAs(t, err, &receiverNotV2)
	require.Contains(t, err.Error(), "missing top-level OBI v2 version field")
}

func nestedMap(raw map[string]any, path ...string) map[string]any {
	cur := raw
	for _, key := range path {
		next, _ := cur[key].(map[string]any)
		cur = next
	}
	return cur
}
