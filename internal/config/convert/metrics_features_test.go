// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestV2MetricFeatures(t *testing.T) {
	t.Parallel()

	for name, feature := range export.FeatureMapper {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			body := fmt.Sprintf("metrics:\n  features: [%q]\n", name)
			receiver, err := schema.ParseReceiverYAML([]byte("version: '2.0'\n" + body))
			require.NoError(t, err)
			got, err := V2ToRuntime(receiver)
			require.NoError(t, err)
			require.Equal(t, feature, got.Metrics.Features)

			cfg := obi.DefaultConfig
			cfg.Metrics.Features = feature
			doc, _ := RuntimeToV2(&cfg)
			data, err := yaml.Marshal(doc)
			require.NoError(t, err)
			parsed, _, err := schema.ParseStandaloneYAML(data)
			require.NoError(t, err)
			got, err = DocumentToRuntime(parsed)
			require.NoError(t, err)
			require.Equal(t, feature, got.Metrics.Features)
		})
	}
}

func TestV2MetricFeaturesOverrideEnablement(t *testing.T) {
	t.Parallel()

	for _, features := range []string{"[]", "[application_service_graph, application_span_otel]"} {
		t.Run(features, func(t *testing.T) {
			t.Parallel()

			ext, err := schema.ParseReceiverYAML([]byte(`
version: '2.0'
network:
  capture:
    enabled: true
  stats:
    enabled: true
    features: [tcp_rtt]
metrics:
  features: ` + features + "\n"))
			require.NoError(t, err)
			got, err := V2ToRuntime(ext)
			require.NoError(t, err)
			require.False(t, got.Metrics.Features.AppRED())
			require.False(t, got.Metrics.Features.AnyNetwork())
			require.False(t, got.Metrics.Features.StatMetrics())
			require.True(t, got.NetworkFlows.Enable)
			if features == "[]" {
				require.True(t, got.Metrics.Features.Empty())
			} else {
				require.True(t, got.Metrics.Features.ServiceGraph())
				require.True(t, got.Metrics.Features.SpanMetrics())
			}
		})
	}
}

func TestV2MetricFeaturesOmitted(t *testing.T) {
	t.Parallel()

	ext, err := schema.ParseReceiverYAML([]byte(`
version: '2.0'
instrumentation:
  http:
    enabled:
      body_size_metrics: false
network:
  capture:
    enabled: true
  stats:
    features: [tcp_rtt]
`))
	require.NoError(t, err)
	got, err := V2ToRuntime(ext)
	require.NoError(t, err)
	require.Equal(t, export.FeatureApplicationRED|export.FeatureNetwork|export.FeatureStatsTCPRtt, got.Metrics.Features)
}

func TestV2MetricFeaturesRejectUnknown(t *testing.T) {
	t.Parallel()

	ext, err := schema.ParseReceiverYAML([]byte(`
version: '2.0'
metrics:
  features: [service_graph]
`))
	require.NoError(t, err)
	_, err = V2ToRuntime(ext)
	require.ErrorContains(t, err, `capture.metrics.features: unknown metrics feature "service_graph"`)
}

func TestV2MetricFeaturesPreserveProtocolEnablement(t *testing.T) {
	t.Parallel()

	ext, err := schema.ParseReceiverYAML([]byte(`
version: '2.0'
metrics:
  features: [application_span_otel, application_service_graph]
instrumentation:
  http:
    enabled:
      traces: true
      metrics: false
`))
	require.NoError(t, err)
	got, err := V2ToRuntime(ext)
	require.NoError(t, err)
	require.True(t, got.Metrics.Features.SpanMetrics())
	require.True(t, got.Metrics.Features.ServiceGraph())
	selection := instrumentations.NewInstrumentationSelection(got.OTELMetrics.Instrumentations)
	require.False(t, selection.HTTPEnabled())
	require.True(t, selection.GRPCEnabled())
	require.Equal(t, got.OTELMetrics.Instrumentations, got.Prometheus.Instrumentations)
	require.True(t, instrumentations.NewInstrumentationSelection(got.Traces.Instrumentations).HTTPEnabled())

	_, docExt := RuntimeToV2(got)
	got, err = V2ToRuntime(docExt)
	require.NoError(t, err)
	require.False(t, instrumentations.NewInstrumentationSelection(got.OTELMetrics.Instrumentations).HTTPEnabled())
}
