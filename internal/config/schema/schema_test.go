// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	otelconfx "go.opentelemetry.io/contrib/otelconf/x"
)

func TestDocumentMarshalYAMLOmitsNullAdditionalProperties(t *testing.T) {
	t.Parallel()

	doc := Document{
		OpenTelemetryConfiguration: otelconfx.OpenTelemetryConfiguration{
			FileFormat: "1.0",
			MeterProvider: &otelconfx.MeterProvider{
				Readers: []otelconfx.MetricReader{{
					Periodic: &otelconfx.PeriodicMetricReader{
						Exporter: otelconfx.PushMetricExporter{},
					},
				}},
			},
		},
	}

	data, err := yaml.Marshal(doc)
	require.NoError(t, err)
	require.NotContains(t, string(data), "additionalproperties")
}

func TestParseStandaloneYAMLDocument(t *testing.T) {
	t.Parallel()

	doc, cfg, err := ParseStandaloneYAML([]byte(`
file_format: "1.0"
log_level: debug
resource:
  attributes:
    - name: service.namespace
      value: checkout
propagator:
  composite:
    - tracecontext:
    - baggage:
tracer_provider:
  sampler:
    parent_based:
      root:
        always_on:
meter_provider:
  readers:
    - periodic:
        interval: 1000
        exporter:
          otlp_grpc:
            endpoint: http://localhost:4317
            tls:
              insecure: true
instrumentation/development:
  go:
    go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp: {}
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: include
        match_order: last_match_wins
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
                incoming:
                  patterns: ["/orders/{id}"]
                outgoing:
                  patterns: ["/inventory/{id}"]
              filters:
                traces:
                  status_code:
                    match: "5*"
`))

	require.NoError(t, err)
	require.NotNil(t, doc)
	require.NotNil(t, cfg)
	require.Equal(t, "1.0", doc.FileFormat)
	require.True(t, doc.HasLogLevel())
	require.NotNil(t, doc.LogLevel)
	require.Equal(t, "debug", string(*doc.LogLevel))
	require.Equal(t, SupportedVersion, cfg.Version)
	require.NotNil(t, doc.InstrumentationDevelopment)
	require.Len(t, doc.Resource.Attributes, 1)
	require.Equal(t, "service.namespace", doc.Resource.Attributes[0].Name)
	require.Equal(t, "checkout", doc.Resource.Attributes[0].Value)
	require.Len(t, doc.Propagator.Composite, 2)
	require.NotNil(t, doc.TracerProvider.Sampler)
	require.NotNil(t, doc.TracerProvider.Sampler.ParentBased)
	require.NotNil(t, doc.TracerProvider.Sampler.ParentBased.Root)
	require.NotNil(t, doc.TracerProvider.Sampler.ParentBased.Root.AlwaysOn)
	require.Len(t, doc.MeterProvider.Readers, 1)
	require.NotNil(t, doc.MeterProvider.Readers[0].Periodic)
	require.NotNil(t, doc.MeterProvider.Readers[0].Periodic.Interval)
	require.Equal(t, int((time.Second).Milliseconds()), *doc.MeterProvider.Readers[0].Periodic.Interval)
	require.NotNil(t, doc.MeterProvider.Readers[0].Periodic.Exporter.OTLPGrpc)
	require.Equal(t, "http://localhost:4317", *doc.MeterProvider.Readers[0].Periodic.Exporter.OTLPGrpc.Endpoint)
	require.Equal(t, CaptureActionInclude, cfg.Capture.Policy.DefaultAction)
	require.Equal(t, MatchOrderLastMatchWins, cfg.Capture.Policy.MatchOrder)
	require.Len(t, cfg.Capture.Rules, 1)
	require.NotNil(t, cfg.Capture.Rules[0].Refine.Exports)
	require.Equal(t, ExportModeRefinement{Traces: false, Metrics: true}, *cfg.Capture.Rules[0].Refine.Exports)
	require.NotNil(t, cfg.Capture.Rules[0].Refine.HTTP)
	require.Equal(t, HTTPRefinementRoutes{
		Incoming: HTTPRefinementRoute{Patterns: []string{"/orders/{id}"}},
		Outgoing: HTTPRefinementRoute{Patterns: []string{"/inventory/{id}"}},
	}, cfg.Capture.Rules[0].Refine.HTTP.Routes)
	require.Equal(t, AttributeFilter{Match: "5*"}, cfg.Capture.Rules[0].Refine.HTTP.Filters.Traces["status_code"])
}

func TestParseStandaloneYAMLRejectsUnknownOpenTelemetryFields(t *testing.T) {
	t.Parallel()

	_, _, err := ParseStandaloneYAML([]byte(`
file_format: "1.0"
tracer_provider:
  typoo: true
extensions:
  obi:
    version: "2.0"
`))

	require.ErrorContains(t, err, "field tracer_provider.typoo not found")
}

func TestParseStandaloneYAMLAcceptsPublishedExtensionFields(t *testing.T) {
	t.Parallel()

	_, cfg, err := ParseStandaloneYAML([]byte(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      runtimes:
        go:
          filter: {}
        nodejs:
          filter: {}
        java:
          filter: {}
    enrich:
      enrichers:
        dns:
          enabled: true
      service_name:
        rules:
          - id: k8s-default
            from: kubernetes
            description: Default Kubernetes mapping.
            map:
              service.name: [app.kubernetes.io/name]
      attributes:
        rules:
          - id: k8s-default-attributes
            from: kubernetes
            description: Default Kubernetes attributes.
            add:
              map:
                k8s.pod.name: [kubernetes.pod.name]
    correlation:
      log_trace_annotation:
        filter: {}
`))

	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.Capture.Runtimes.Go.Filter)
	require.NotNil(t, cfg.Capture.Runtimes.NodeJS.Filter)
	require.NotNil(t, cfg.Capture.Runtimes.Java.Filter)
	require.Contains(t, cfg.Enrich.Enrichers.AdditionalProperties, "dns")
	require.Contains(t, cfg.Enrich.ServiceName.AdditionalProperties, "rules")
	require.Contains(t, cfg.Enrich.Attributes.AdditionalProperties, "rules")
	require.NotNil(t, cfg.Correlation.LogTraceAnnotation.Filter)
}

func TestParseStandaloneYAMLRecordsOpenTelemetryExtensionFields(t *testing.T) {
	t.Parallel()

	doc, _, err := ParseStandaloneYAML([]byte(`
file_format: "1.0"
vendor_extension:
  enabled: true
tracer_provider:
  sampler:
    vendor_sampler: {}
meter_provider:
  readers:
    - periodic:
        exporter:
          console: {}
        producers:
          - prometheus: {}
extensions:
  obi:
    version: "2.0"
`))

	require.NoError(t, err)
	require.Equal(t, []string{
		"vendor_extension",
		"tracer_provider.sampler.vendor_sampler",
		"meter_provider.readers[0].periodic.producers[0].prometheus",
	}, doc.OpenTelemetryExtensionFields())
}

func TestParsersRejectMultipleYAMLDocuments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		yaml  string
		parse func([]byte) error
	}{
		{
			name: "standalone",
			yaml: `
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
---
file_format: "1.0"
extensions:
  obi:
    version: "3.0"
`,
			parse: func(data []byte) error {
				_, _, err := ParseStandaloneYAML(data)
				return err
			},
		},
		{
			name: "receiver",
			yaml: `
version: "2.0"
---
version: "3.0"
`,
			parse: func(data []byte) error {
				_, err := ParseReceiverYAML(data)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.parse([]byte(test.yaml))
			require.ErrorContains(t, err, "must contain exactly one document")
		})
	}
}

func TestParseStandaloneYAMLRejectsDaemonLoggingLevel(t *testing.T) {
	t.Parallel()

	_, _, err := ParseStandaloneYAML([]byte(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    daemon:
      logging:
        level: INFO
`))
	require.Error(t, err)
	require.Contains(t, err.Error(), `unsupported daemon logging field "level"`)
	require.Contains(t, err.Error(), "top-level log_level")
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
	require.Equal(t, CaptureActionExclude, cfg.Capture.Policy.DefaultAction)
	require.Len(t, cfg.Capture.Rules, 1)
	require.NotNil(t, cfg.Capture.Rules[0].Match.Process.OpenPorts)
	require.Equal(t, []int{8080, 8443}, cfg.Capture.Rules[0].Match.Process.OpenPorts.AllValues())
	require.Equal(t, 123, cfg.Capture.Channels.BufferLen)
	require.True(t, cfg.Capture.Instrumentation.HTTP.Enabled.Traces)
	require.False(t, cfg.Capture.Instrumentation.HTTP.Enabled.Metrics)
}

func TestParsersRejectUnknownOBIFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		yaml  string
		parse func([]byte) error
	}{
		{
			name: "standalone",
			yaml: `
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      unknown_field: true
`,
			parse: func(data []byte) error {
				_, _, err := ParseStandaloneYAML(data)
				return err
			},
		},
		{
			name: "receiver",
			yaml: `
version: "2.0"
unknown_field: true
`,
			parse: func(data []byte) error {
				_, err := ParseReceiverYAML(data)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.parse([]byte(test.yaml))

			require.ErrorContains(t, err, "field unknown_field not found")
		})
	}
}

func TestParseReceiverRejectsInvalidTypedEnum(t *testing.T) {
	t.Parallel()

	_, err := ParseReceiverYAML([]byte(`
version: "2.0"
network:
  capture:
    source: made-up
`))

	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid source")
}

func TestParseReceiverRejectsInvalidCaptureAction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "default action",
			yaml: `
version: "2.0"
policy:
  default_action: drop
`,
		},
		{
			name: "rule action",
			yaml: `
version: "2.0"
rules:
  - action: drop
    match:
      process:
        exe_path_glob: ["/usr/bin/checkout"]
`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseReceiverYAML([]byte(test.yaml))

			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid action")
		})
	}
}

func TestParseStandaloneRejectsInvalidHistogramAggregation(t *testing.T) {
	t.Parallel()

	_, _, err := ParseStandaloneYAML([]byte(`
file_format: "1.0"
meter_provider:
  readers:
    - periodic:
        exporter:
          otlp_grpc:
            endpoint: http://localhost:4317
            default_histogram_aggregation: made-up
extensions:
  obi:
    version: "2.0"
    capture: {}
`))

	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid histogram aggregation")
	require.Contains(t, err.Error(), "made-up")
}

func TestParseStandaloneRejectsUnsupportedFileFormat(t *testing.T) {
	t.Parallel()

	_, _, err := ParseStandaloneYAML([]byte(`
file_format: "1.1"
extensions:
  obi:
    version: "2.0"
    capture: {}
`))

	var unsupported *UnsupportedFileFormatError
	require.ErrorAs(t, err, &unsupported)
	require.Equal(t, "1.1", unsupported.FileFormat)
	require.Contains(t, err.Error(), "file_format")
}

func TestReceiverRejectsStandaloneSections(t *testing.T) {
	t.Parallel()

	layouts := []struct {
		name   string
		prefix string
	}{
		{name: "v2", prefix: "version: \"2.0\"\n"},
		{name: "legacy selector", prefix: "open_port: \"8080\"\n"},
	}
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

			for _, layout := range layouts {
				t.Run(layout.name, func(t *testing.T) {
					t.Parallel()

					for _, test := range tests {
						t.Run(test.name, func(t *testing.T) {
							t.Parallel()

							_, err := ParseReceiverYAML([]byte(layout.prefix + section + ": " + test.value + "\n"))

							var notAllowed *SectionNotAllowedError
							require.ErrorAs(t, err, &notAllowed)
							require.Equal(t, section, notAllowed.Section)
							require.Contains(t, err.Error(), "receiver config")
							require.Contains(t, err.Error(), "standalone mode")
						})
					}
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
			cfg:     Extension{Version: SupportedVersion, Enrich: &Enrich{}},
			section: sectionEnrich,
		},
		{
			name:    sectionCorrelation,
			cfg:     Extension{Version: SupportedVersion, Correlation: &Correlation{}},
			section: sectionCorrelation,
		},
		{
			name:    sectionDaemon,
			cfg:     Extension{Version: SupportedVersion, Daemon: &Daemon{}},
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

	for _, yaml := range []string{
		`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture: {}
`,
		`
file_format: "1.0"
extensions:
  obi:
    capture: {}
`,
	} {
		_, err = ParseReceiverYAML([]byte(yaml))
		var wrongLayout *ReceiverLayoutError
		require.ErrorAs(t, err, &wrongLayout)
		var receiverNotV2 *NotV2Error
		require.NotErrorAs(t, err, &receiverNotV2)
		require.Contains(t, err.Error(), "extensions.obi.capture")
		require.Contains(t, err.Error(), "receiver top level")
	}
}
