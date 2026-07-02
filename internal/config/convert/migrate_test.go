// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/config/schema"
)

func TestMigrateV1YAMLDoesNotApplyEnvironmentOverrides(t *testing.T) {
	t.Setenv("OTEL_EBPF_OPEN_PORT", "9090")

	input := []byte(`
open_port: 8080
otel_traces_export:
  endpoint: http://localhost:4317
  protocol: grpc
`)
	got, _, err := MigrateV1YAML(input)

	require.NoError(t, err)
	require.Contains(t, string(got), `open_ports: "8080"`)
	require.NotContains(t, string(got), `open_ports: "9090"`)
	again, _, err := MigrateV1YAML(input)
	require.NoError(t, err)
	require.Equal(t, got, again)
}

func TestMigrateV1YAMLRejectsEnvironmentInterpolation(t *testing.T) {
	t.Parallel()

	_, _, err := MigrateV1YAML([]byte(`
open_port: ${APP_PORT:-8080}
`))

	require.ErrorContains(t, err, "environment interpolation is not supported")
}

func TestMigrateV1YAMLRejectsAllEnvironmentInterpolationForms(t *testing.T) {
	t.Parallel()

	_, _, err := MigrateV1YAML([]byte(`
attributes:
  kubernetes:
    cluster_name: $(CLUSTER_NAME)
`))

	require.ErrorContains(t, err, "environment interpolation is not supported")
}

func TestMigrateV1YAMLIgnoresInterpolationSyntaxInComments(t *testing.T) {
	t.Parallel()

	got, _, err := MigrateV1YAML([]byte(`
# ${IGNORED} and $(ALSO_IGNORED)
attributes:
  kubernetes:
    cluster_name: $${LITERAL}
`))

	require.NoError(t, err)
	require.Contains(t, string(got), `$${LITERAL}`)
}

func TestMigrateV1YAMLRejectsAliasesAndMergeKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   string
		expected string
	}{
		{
			name: "alias",
			config: `
routes:
  patterns: &patterns [/users/:id]
  ignored_patterns: *patterns
`,
			expected: "YAML aliases are not supported",
		},
		{
			name: "merge key",
			config: `
routes:
  <<: &defaults
    unmatched: path
`,
			expected: "YAML merge keys are not supported",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := MigrateV1YAML([]byte(test.config))

			require.ErrorContains(t, err, test.expected)
		})
	}
}

func TestMigrateV1YAMLRejectsUnknownV1Fields(t *testing.T) {
	t.Parallel()

	_, _, err := MigrateV1YAML([]byte(`
open_port: 8080
unknown_setting: true
`))

	require.ErrorContains(t, err, "field unknown_setting not found")

	_, _, err = MigrateV1YAML([]byte(`
extensions:
  obi:
    version: "2.0"
`))
	require.ErrorContains(t, err, "input contains config v2 extensions")
}

func TestMigrateV1YAMLReportsUnsupportedFieldsInOrder(t *testing.T) {
	t.Parallel()

	_, _, err := MigrateV1YAML([]byte(`
service_name: checkout
prometheus_export:
  path: /custom-metrics
discovery:
  instrument:
    - open_ports: 8080
      sampler:
        name: always_on
`))

	require.EqualError(t, err, "v1 fields outside the supported migration contract: "+
		"discovery.instrument[0].sampler, prometheus_export.path, service_name")
}

func TestMigrateV1YAMLRejectsNullPointerSections(t *testing.T) {
	t.Parallel()

	_, _, err := MigrateV1YAML([]byte(`
routes: null
name_resolver: null
`))

	require.EqualError(t, err, "v1 fields outside the supported migration contract: name_resolver, routes")
}

func TestMigrateV1YAMLRejectsUnsupportedMetricFeature(t *testing.T) {
	t.Parallel()

	_, _, err := MigrateV1YAML([]byte(`
metrics:
  features: [application, application_service_graph]
`))

	require.EqualError(t, err, "v1 fields outside the supported migration contract: metrics.features[1]")
}

func TestMigrateV1YAMLRejectsNonGRPCTransport(t *testing.T) {
	t.Parallel()

	_, _, err := MigrateV1YAML([]byte(`
open_port: 8080
otel_traces_export:
  endpoint: http://localhost:4318
  protocol: http/protobuf
`))

	require.EqualError(t, err, "v1 fields outside the supported migration contract: otel_traces_export.protocol")
}

func TestMigrateV1YAMLRejectsNonGRPCProtocolWithoutEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   string
		expected string
	}{
		{
			name: "traces",
			config: `
otel_traces_export:
  protocol: http/protobuf
`,
			expected: "otel_traces_export.protocol",
		},
		{
			name: "metrics",
			config: `
otel_metrics_export:
  protocol: http/json
`,
			expected: "otel_metrics_export.protocol",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := MigrateV1YAML([]byte(test.config))

			require.EqualError(t, err, "v1 fields outside the supported migration contract: "+test.expected)
		})
	}
}

func TestMigrateV1YAMLRejectsNonFiniteSamplerRatio(t *testing.T) {
	t.Parallel()

	for _, ratio := range []string{"NaN", "+Inf", "-Inf"} {
		t.Run(ratio, func(t *testing.T) {
			t.Parallel()

			_, _, err := MigrateV1YAML([]byte(`
otel_traces_export:
  sampler:
    name: traceidratio
    arg: "` + ratio + `"
`))

			require.EqualError(t, err, "v1 fields outside the supported migration contract: "+
				"otel_traces_export.sampler.arg")
		})
	}
}

func TestMigrateV1YAMLRejectsImplicitNetworkCaptureEnablement(t *testing.T) {
	t.Parallel()

	_, _, err := MigrateV1YAML([]byte(`
metrics:
  features: [network]
network:
  enable: false
`))

	require.EqualError(t, err, "v1 fields outside the supported migration contract: metrics.features[0]")

	_, _, err = MigrateV1YAML([]byte(`
metrics:
  features: [network]
network:
  enable: false
otel_metrics_export:
  endpoint: http://localhost:4317
  protocol: grpc
`))
	require.NoError(t, err)
}

func TestMigrateV1YAMLPreservesAdditionalPropertiesMapKey(t *testing.T) {
	t.Parallel()

	encoded, _, err := MigrateV1YAML([]byte(`
filter:
  application:
    additionalproperties:
      match: foo
`))
	require.NoError(t, err)

	doc, _, err := schema.ParseStandaloneYAML(encoded)
	require.NoError(t, err)
	cfg, err := DocumentToRuntime(doc)
	require.NoError(t, err)
	require.Equal(t, "foo", cfg.Filters.Application["additionalproperties"].Match)
}
