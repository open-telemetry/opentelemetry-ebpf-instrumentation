// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package instrumenter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/otel/decfg"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/transform"
)

func TestServiceNameTemplate(t *testing.T) {
	cfg := &obi.Config{
		Attributes: obi.Attributes{
			Kubernetes: transform.KubernetesDecorator{
				ServiceNameTemplate: "{{asdf}}",
			},
		},
	}

	temp, err := buildServiceNameTemplate(cfg)
	assert.Nil(t, temp)
	if assert.Error(t, err) {
		assert.Equal(t, `unable to parse service name template: template: serviceNameTemplate:1: function "asdf" not defined`, err.Error())
	}

	cfg.Attributes.Kubernetes.ServiceNameTemplate = `{{- if eq .Meta.Pod nil }}{{.Meta.Name}}{{ else }}{{- .Meta.Namespace }}/{{ index .Meta.Labels "app.kubernetes.io/name" }}/{{ index .Meta.Labels "app.kubernetes.io/component" -}}{{ if .ContainerName }}/{{ .ContainerName -}}{{ end -}}{{ end -}}`
	temp, err = buildServiceNameTemplate(cfg)

	require.NoError(t, err)
	assert.NotNil(t, temp)

	cfg.Attributes.Kubernetes.ServiceNameTemplate = ""
	temp, err = buildServiceNameTemplate(cfg)
	require.NoError(t, err)
	assert.Nil(t, temp)
}

func TestNormalizeConfig_MeterProvider(t *testing.T) {
	type testCase struct {
		name     string
		expected export.Features
		cfg      obi.Config
	}
	testCases := []testCase{{
		name:     "default global meter provider",
		expected: export.FeatureApplication,
		cfg: obi.Config{
			Metrics:       otelcfg.MetricsConfig{DeprFeatures: export.FeatureEBPF},
			Prometheus:    prom.PrometheusConfig{Features: export.FeatureNetwork},
			MeterProvider: decfg.MeterProvider{Features: export.FeatureApplication},
		},
	}, {
		name:     "OTEL endpoint and legacy features are defined",
		expected: export.FeatureEBPF,
		cfg: obi.Config{
			Metrics:       otelcfg.MetricsConfig{MetricsEndpoint: "http://foo", DeprFeatures: export.FeatureEBPF},
			Prometheus:    prom.PrometheusConfig{Features: export.FeatureNetwork},
			MeterProvider: decfg.MeterProvider{Features: export.FeatureApplication},
		},
	}, {
		name:     "OTEL endpoint defined but legacy features are not",
		expected: export.FeatureApplication,
		cfg: obi.Config{
			Metrics:       otelcfg.MetricsConfig{MetricsEndpoint: "http://foo"},
			Prometheus:    prom.PrometheusConfig{Features: export.FeatureNetwork},
			MeterProvider: decfg.MeterProvider{Features: export.FeatureApplication},
		},
	}, {
		name:     "Prom endpoint and legacy features are defined",
		expected: export.FeatureNetwork,
		cfg: obi.Config{
			Metrics:       otelcfg.MetricsConfig{DeprFeatures: export.FeatureEBPF},
			Prometheus:    prom.PrometheusConfig{Port: 8080, Features: export.FeatureNetwork},
			MeterProvider: decfg.MeterProvider{Features: export.FeatureApplication},
		},
	}, {
		name:     "Prom endpoint defined but legacy features are not",
		expected: export.FeatureApplication,
		cfg: obi.Config{
			Metrics:       otelcfg.MetricsConfig{MetricsEndpoint: "http://foo"},
			Prometheus:    prom.PrometheusConfig{Port: 8080},
			MeterProvider: decfg.MeterProvider{Features: export.FeatureApplication},
		},
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			normalizeConfig(&cfg)
			assert.Equal(t, tc.expected, cfg.MeterProvider.Features)
		})
	}
}

func TestNormalizeConfig_Network(t *testing.T) {
	obi := obi.Config{
		NetworkFlows:  obi.NetworkConfig{Enable: true},
		MeterProvider: decfg.MeterProvider{Features: export.FeatureApplication},
	}
	normalizeConfig(&obi)
	assert.Equal(t, export.FeatureApplication|export.FeatureNetwork,
		obi.MeterProvider.Features)
}
