// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"testing"

	"github.com/caarlos0/env/v11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestFeatureYAML(t *testing.T) {
	doc := struct {
		Features Features
	}{}
	require.NoError(t,
		yaml.Unmarshal([]byte(`features: [application, application_span_otel, application_runtime]`), &doc))

	assert.True(t, doc.Features.has(FeatureApplicationRED))
	assert.True(t, doc.Features.has(FeatureSpanOTel))
	assert.True(t, doc.Features.has(FeatureApplicationRuntime))
	assert.True(t, doc.Features.has(FeatureApplicationRED|FeatureSpanOTel))
	assert.False(t, doc.Features.has(FeatureSpanLegacy))
	assert.False(t, doc.Features.has(FeatureApplicationRED|FeatureSpanLegacy))
	assert.False(t, doc.Features.has(FeatureAll))
}

func TestFeatureEnv(t *testing.T) {
	doc := struct {
		Features Features `env:"FOO"`
	}{}
	t.Setenv("FOO", "network")
	require.NoError(t, env.Parse(&doc))

	assert.True(t, doc.Features.has(FeatureNetwork))
	assert.False(t, doc.Features.has(FeatureSpanOTel))
	assert.False(t, doc.Features.has(FeatureSpanLegacy))
	assert.False(t, doc.Features.has(FeatureAll))
}

func TestFeatureEnv_NetworkFlowPackets(t *testing.T) {
	doc := struct {
		Features Features `env:"FOO"`
	}{}
	t.Setenv("FOO", "network_flow_packets")
	require.NoError(t, env.Parse(&doc))

	assert.True(t, doc.Features.has(FeatureNetworkFlowPackets))
	assert.True(t, doc.Features.NetworkFlowPackets())
	assert.True(t, doc.Features.AnyNetwork())
	assert.False(t, doc.Features.NetworkBytes())
	assert.False(t, doc.Features.has(FeatureAll))
}

func TestFeatureEnv_Separator(t *testing.T) {
	doc := struct {
		Features Features `env:"FOO" envSeparator:","`
	}{}
	t.Setenv("FOO", "network,application,application_span_otel,application_runtime")
	require.NoError(t, env.Parse(&doc))

	assert.True(t, doc.Features.has(FeatureNetwork))
	assert.True(t, doc.Features.has(FeatureApplicationRED|FeatureSpanOTel))
	assert.True(t, doc.Features.AppRuntime())
	assert.False(t, doc.Features.has(FeatureSpanLegacy))
	assert.False(t, doc.Features.has(FeatureAll))
}

func TestFeatureApplicationAliasDoesNotIncludeRuntime(t *testing.T) {
	features := mustLoadFeatures(t, "application")

	assert.True(t, features.has(FeatureApplicationRED))
	assert.False(t, features.has(FeatureApplicationRuntime))
	assert.False(t, AppO11yFeatures.has(FeatureApplicationRuntime))
	assert.True(t, mustLoadFeatures(t, "application_runtime").AnyAppO11yMetric())
	assert.True(t, mustLoadFeatures(t, "application_runtime").AppOrSpan())
}

func mustLoadFeatures(t *testing.T, names ...string) Features {
	t.Helper()
	features, err := LoadFeatures(names)
	require.NoError(t, err)
	return features
}

func TestLoadFeaturesRejectsUnknownNames(t *testing.T) {
	_, err := LoadFeatures([]string{"application_jvm"})
	require.ErrorContains(t, err, `unknown metrics feature "application_jvm"`)

	_, err = LoadFeatures([]string{"application", "application_runtme"})
	require.ErrorContains(t, err, "application_runtme")

	// empty entries (trailing commas in env values) are not an error
	features, err := LoadFeatures([]string{"application", ""})
	require.NoError(t, err)
	assert.True(t, features.has(FeatureApplicationRED))

	// the error names the valid features so a typo is self-diagnosing
	_, err = LoadFeatures([]string{"no_such_feature"})
	require.ErrorContains(t, err, "application_runtime")
}

// An unset OTEL_EBPF_METRICS_FEATURES resolves to an empty envDefault string
// (perapp.MetricsConfig), so UnmarshalText("") runs on every default
// deployment and must keep yielding Undefined rather than an error.
func TestFeatureUnmarshalTextEmpty(t *testing.T) {
	var features Features
	require.NoError(t, features.UnmarshalText(nil))
	assert.True(t, features.Undefined())

	require.NoError(t, features.UnmarshalText([]byte("")))
	assert.True(t, features.Undefined())
}

func TestFeatureEnv_All(t *testing.T) {
	doc := struct {
		Features Features `env:"FOO" envSeparator:","`
	}{}
	t.Setenv("FOO", "all")
	require.NoError(t, env.Parse(&doc))

	assert.True(t, doc.Features.has(FeatureNetwork))
	assert.True(t, doc.Features.has(FeatureApplicationRED|FeatureSpanOTel))
	assert.True(t, doc.Features.has(FeatureSpanLegacy))
	assert.True(t, doc.Features.has(FeatureAll))
}

func TestFeatureYAML_All(t *testing.T) {
	doc := struct {
		Features Features
	}{}
	require.NoError(t,
		yaml.Unmarshal([]byte(`features: ["*"]`), &doc))

	assert.True(t, doc.Features.has(FeatureApplicationRED))
	assert.True(t, doc.Features.has(FeatureSpanOTel))
	assert.True(t, doc.Features.has(FeatureSpanLegacy))
	assert.True(t, doc.Features.has(FeatureAll))
}

func TestFeatureYAML_Error(t *testing.T) {
	doc := struct {
		Features Features
	}{}
	require.Error(t,
		yaml.Unmarshal([]byte(`features: {hello: world}`), &doc))
	require.Error(t,
		yaml.Unmarshal([]byte(`features: [{hello: world}]`), &doc))
}

func TestFeatureEmpty(t *testing.T) {
	t.Run("empty YAML", func(t *testing.T) {
		doc := struct {
			Features Features
		}{}
		require.NoError(t,
			yaml.Unmarshal([]byte(`features: []`), &doc))
		require.True(t, doc.Features.Empty())
		require.False(t, doc.Features.Undefined())
	})
}

func TestResolveSpanMetricsConflict(t *testing.T) {
	t.Run("only legacy no conflict", func(t *testing.T) {
		f := FeatureSpanLegacy | FeatureNetwork
		resolved := f.ResolveSpanMetricsConflict()
		assert.False(t, resolved)
		assert.True(t, f.has(FeatureSpanLegacy))
	})
	t.Run("only otel no conflict", func(t *testing.T) {
		f := FeatureSpanOTel
		resolved := f.ResolveSpanMetricsConflict()
		assert.False(t, resolved)
		assert.True(t, f.has(FeatureSpanOTel))
	})
	t.Run("both enabled removes legacy keeps otel", func(t *testing.T) {
		f := FeatureSpanLegacy | FeatureSpanOTel | FeatureNetwork
		resolved := f.ResolveSpanMetricsConflict()
		assert.True(t, resolved)
		assert.True(t, f.has(FeatureSpanOTel))
		assert.True(t, f.has(FeatureNetwork))
		assert.False(t, f.has(FeatureSpanLegacy))
	})
	t.Run("neither enabled", func(t *testing.T) {
		f := FeatureNetwork
		resolved := f.ResolveSpanMetricsConflict()
		assert.False(t, resolved)
		assert.True(t, f.has(FeatureNetwork))
	})
}

func TestInvalidSpanMetricsConfig(t *testing.T) {
	tests := []struct {
		name     string
		features Features
		expected bool
	}{
		{"only legacy", FeatureSpanLegacy, false},
		{"only otel", FeatureSpanOTel, false},
		{"both legacy and otel", FeatureSpanLegacy | FeatureSpanOTel, true},
		{"both via FeatureAll", FeatureAll, false},
		{"both plus other features", FeatureSpanLegacy | FeatureSpanOTel | FeatureNetwork, true},
		{"neither", FeatureNetwork, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.features.InvalidSpanMetricsConfig())
		})
	}
}

func TestFeatureJSONSchemaFlagsDeprecatedNames(t *testing.T) {
	items := Features(0).JSONSchema().Items
	require.Len(t, items.OneOf, 2)

	assert.False(t, items.OneOf[0].Deprecated)
	assert.Contains(t, items.OneOf[0].Enum, "application_span_otel")
	assert.Contains(t, items.OneOf[0].Enum, "*")
	assert.NotContains(t, items.OneOf[0].Enum, "application_span")
	assert.NotContains(t, items.OneOf[0].Enum, "application_span_sizes")

	assert.True(t, items.OneOf[1].Deprecated)
	assert.Equal(t, []any{"application_span", "application_span_sizes"}, items.OneOf[1].Enum)

	// the schema names the migration target instead of pointing elsewhere for it
	assert.Contains(t, items.OneOf[1].Description, "application_span (use application_span_otel)")
	assert.Contains(t, items.OneOf[1].Description, "application_span_sizes (no direct replacement)")
}

func TestDeprecatedEnabled(t *testing.T) {
	assert.Equal(t,
		[]DeprecatedFeature{{Name: "application_span", Replacement: "application_span_otel"}},
		mustLoadFeatures(t, "application", "application_span").DeprecatedEnabled())

	assert.Equal(t,
		[]DeprecatedFeature{{Name: "application_span_sizes"}},
		mustLoadFeatures(t, "application_span_sizes").DeprecatedEnabled())

	assert.Empty(t, mustLoadFeatures(t, "application", "application_span_otel").DeprecatedEnabled())
}

func TestFeatureUndefined(t *testing.T) {
	t.Run("undefined YAML", func(t *testing.T) {
		doc := struct {
			Features Features
		}{}
		require.NoError(t,
			yaml.Unmarshal([]byte(`{}`), &doc))
		require.False(t, doc.Features.Empty())
		require.True(t, doc.Features.Undefined())
	})
	t.Run("undefined env", func(t *testing.T) {
		doc := struct {
			Features Features `env:"FOO"`
		}{}
		require.NoError(t, env.Parse(&doc))
		require.False(t, doc.Features.Empty())
		require.True(t, doc.Features.Undefined())
	})
}
