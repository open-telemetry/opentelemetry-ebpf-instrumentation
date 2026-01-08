// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"testing"

	"github.com/caarlos0/env/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestFeatureYAML(t *testing.T) {
	doc := struct {
		Features Features
	}{}
	require.NoError(t,
		yaml.Unmarshal([]byte(`features: [application, application_span_otel]`), &doc))

	assert.True(t, doc.Features.has(FeatureApplicationRED))
	assert.True(t, doc.Features.has(FeatureSpanOTel))
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

func TestFeatureEnv_Separator(t *testing.T) {
	doc := struct {
		Features Features `env:"FOO" envSeparator:","`
	}{}
	t.Setenv("FOO", "network,application,application_span_otel")
	require.NoError(t, env.Parse(&doc))

	assert.True(t, doc.Features.has(FeatureNetwork))
	assert.True(t, doc.Features.has(FeatureApplicationRED|FeatureSpanOTel))
	assert.False(t, doc.Features.has(FeatureSpanLegacy))
	assert.False(t, doc.Features.has(FeatureAll))
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
