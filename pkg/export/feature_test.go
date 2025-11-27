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

	assert.True(t, doc.Features.Has(FeatureApplication))
	assert.True(t, doc.Features.Has(FeatureSpanOTel))
	assert.True(t, doc.Features.Has(FeatureApplication|FeatureSpanOTel))
	assert.False(t, doc.Features.Has(FeatureProcess))
	assert.False(t, doc.Features.Has(FeatureApplication|FeatureProcess))
	assert.False(t, doc.Features.Has(FeatureAll))
}

func TestFeatureEnv(t *testing.T) {
	doc := struct {
		Features Features `env:"FOO"`
	}{}
	t.Setenv("FOO", "network")
	require.NoError(t, env.Parse(&doc))

	assert.True(t, doc.Features.Has(FeatureNetwork))
	assert.False(t, doc.Features.Has(FeatureSpanOTel))
	assert.False(t, doc.Features.Has(FeatureProcess))
	assert.False(t, doc.Features.Has(FeatureAll))
}

func TestFeatureEnv_Separator(t *testing.T) {
	doc := struct {
		Features Features `env:"FOO" envSeparator:","`
	}{}
	t.Setenv("FOO", "network,application,application_span_otel")
	require.NoError(t, env.Parse(&doc))

	assert.True(t, doc.Features.Has(FeatureNetwork))
	assert.True(t, doc.Features.Has(FeatureApplication|FeatureSpanOTel))
	assert.False(t, doc.Features.Has(FeatureProcess))
	assert.False(t, doc.Features.Has(FeatureAll))
}

func TestFeatureEnv_All(t *testing.T) {
	doc := struct {
		Features Features `env:"FOO" envSeparator:","`
	}{}
	t.Setenv("FOO", "all")
	require.NoError(t, env.Parse(&doc))

	assert.True(t, doc.Features.Has(FeatureNetwork))
	assert.True(t, doc.Features.Has(FeatureApplication|FeatureSpanOTel))
	assert.True(t, doc.Features.Has(FeatureProcess))
	assert.True(t, doc.Features.Has(FeatureAll))
}

func TestFeatureYAML_All(t *testing.T) {
	doc := struct {
		Features Features
	}{}
	require.NoError(t,
		yaml.Unmarshal([]byte(`features: ["*"]`), &doc))

	assert.True(t, doc.Features.Has(FeatureApplication))
	assert.True(t, doc.Features.Has(FeatureSpanOTel))
	assert.True(t, doc.Features.Has(FeatureProcess))
	assert.True(t, doc.Features.Has(FeatureAll))
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
