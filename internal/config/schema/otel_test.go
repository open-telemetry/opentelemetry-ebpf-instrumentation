// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

func TestOTLPGRPCMetricExporterDefaultHistogramAggregationYAML(t *testing.T) {
	t.Parallel()

	var exporter OTLPGRPCMetricExporter
	err := yaml.Unmarshal([]byte(`
endpoint: http://localhost:4317
default_histogram_aggregation: base2_exponential_bucket_histogram
tls:
  insecure: true
`), &exporter)
	require.NoError(t, err)
	require.Equal(t, "http://localhost:4317", exporter.Endpoint)
	require.Equal(t, otelcfg.HistogramAggregationExponential, exporter.DefaultHistogramAggregation)
	require.True(t, exporter.TLS.Insecure)
}

func TestOTLPGRPCExporterRejectsMetricHistogramAggregation(t *testing.T) {
	t.Parallel()

	var exporter OTLPGRPCExporter
	err := yaml.Unmarshal([]byte(`
endpoint: http://localhost:4317
default_histogram_aggregation: explicit_bucket_histogram
`), &exporter)
	require.Error(t, err)
	require.Contains(t, err.Error(), "default_histogram_aggregation is only valid for metric exporters")
}

func TestOTLPGRPCExporterRejectsInvalidNestedYAML(t *testing.T) {
	t.Parallel()

	var exporter OTLPGRPCExporter
	err := yaml.Unmarshal([]byte(`
retry:
  initial_interval: []
`), &exporter)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duration must be a scalar")
}
