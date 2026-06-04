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

	tests := []string{"enrich", "correlation", "daemon"}
	for _, section := range tests {
		t.Run(section, func(t *testing.T) {
			t.Parallel()

			_, err := ParseReceiverMap(map[string]any{
				"version": "2.0",
				section:   map[string]any{},
			})

			var notAllowed *SectionNotAllowedError
			require.ErrorAs(t, err, &notAllowed)
			require.Equal(t, string(validationModeReceiver), notAllowed.Mode)
			require.Equal(t, section, notAllowed.Section)
			require.Contains(t, err.Error(), "standalone mode")
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
			want: "2",
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

func TestNotV2(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "empty",
			yaml: "",
			want: "missing OBI v2 version field",
		},
		{
			name: "missing version",
			yaml: "file_format: \"1.0\"\n",
			want: "missing OBI v2 version field",
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

			_, _, err := ParseYAML([]byte(test.yaml))

			var notV2 *NotV2Error
			require.ErrorAs(t, err, &notV2)
			require.Contains(t, err.Error(), test.want)
		})
	}
}

func TestParseYAMLAutoDetectsLayout(t *testing.T) {
	t.Parallel()

	doc, cfg, err := ParseYAML([]byte(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture: {}
`))
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.NotNil(t, cfg)

	doc, cfg, err = ParseYAML([]byte(`
version: "2.0"
policy:
  default_action: include
`))
	require.NoError(t, err)
	require.Nil(t, doc)
	require.NotNil(t, cfg)
	require.Equal(t, "include", cfg.Capture.Policy["default_action"])
}

func TestParseMapPreservesDocumentRaw(t *testing.T) {
	t.Parallel()

	raw := map[string]any{
		"file_format": "1.0",
		"extensions": map[string]any{
			"obi": map[string]any{
				"version": "2.0",
				"capture": map[string]any{
					"policy": map[string]any{
						"default_action": "include",
					},
				},
			},
		},
	}

	doc, cfg, err := ParseStandaloneMap(raw)

	require.NoError(t, err)
	doc.Raw["added"] = true
	cfg.Raw["added_to_extension"] = true
	cfg.Capture.Raw["added_to_capture"] = true

	require.True(t, raw["added"].(bool))
	require.True(t, raw["extensions"].(map[string]any)["obi"].(map[string]any)["added_to_extension"].(bool))
	require.True(t, cfg.Raw["capture"].(map[string]any)["added_to_capture"].(bool))
}
