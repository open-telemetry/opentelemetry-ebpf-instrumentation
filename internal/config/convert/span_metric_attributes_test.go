// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/obi"
)

const spanMetricSelectionDocument = `
file_format: "1.0"
meter_provider:
  readers:
    - periodic:
        exporter:
          otlp_grpc:
            endpoint: http://collector:4317
    - pull:
        exporter:
          prometheus/development:
            port: 9090
extensions:
  obi:
    version: "2.0"
    capture:
      metrics:
        features: [application, application_span_otel]
      attributes:
        select:
          traces.span.metrics.*:
            include: [service.version]
    daemon:
      telemetry:
        metrics:
          prometheus:
            extra_span_resource_attributes: [deployment_environment]
`

func importSpanMetricSelection(t *testing.T, data []byte) *obi.Config {
	t.Helper()
	doc, _, err := schema.ParseStandaloneYAML(data)
	require.NoError(t, err)
	cfg, err := DocumentToRuntime(doc)
	require.NoError(t, err)
	return cfg
}

func spanMetricPairAttributes(t *testing.T, cfg *obi.Config, legacy []attr.Name) []attr.Name {
	t.Helper()
	selector, err := attributes.NewAttrSelector(attributes.AttrGroups(-1), &attributes.SelectorConfig{
		SelectionCfg:   cfg.Attributes.Select,
		UseV2Selection: cfg.Attributes.UseV2Selection,
	})
	require.NoError(t, err)
	return selector.ForSpanMetrics(legacy, attributes.SpanMetricsDurationOTel, attributes.SpanMetricsCallsOTel)
}

func TestSpanMetricSelectionRoundTripsWithActiveExporters(t *testing.T) {
	first := importSpanMetricSelection(t, []byte(spanMetricSelectionDocument))
	require.Equal(t, []attr.Name{"service.version"}, spanMetricPairAttributes(t, first, nil))

	doc, _ := RuntimeToV2(first)
	data, err := yaml.Marshal(doc)
	require.NoError(t, err)
	second := importSpanMetricSelection(t, data)

	require.Equal(t, []attr.Name{"service.version"}, spanMetricPairAttributes(t, second, nil))
	require.Equal(t, []string{"deployment_environment"}, second.Prometheus.ExtraSpanResourceLabels)
}

func TestDeprecatedPrometheusSpanResourceAttributesStillApply(t *testing.T) {
	cfg := importSpanMetricSelection(t, []byte(spanMetricSelectionDocument))
	require.Equal(t, []string{"deployment_environment"}, cfg.Prometheus.ExtraSpanResourceLabels)
	require.Empty(t, cfg.OTELMetrics.ExtraSpanResourceLabels)
	require.Equal(t,
		[]attr.Name{"deployment.environment", "service.version"},
		spanMetricPairAttributes(t, cfg, []attr.Name{"deployment.environment"}))
}
