// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	otelmetric "go.opentelemetry.io/obi/pkg/export/otel/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

var defaultStatRttInstrument = otelmetric.Instrument{
	Name:  attributes.StatTCPRtt.OTEL,
	Scope: instrumentation.Scope{Name: statScopeName},
}

func TestStatRttHistogramView_ExponentialUsesConfiguredMaxSizeAndScale(t *testing.T) {
	cfg := &otelcfg.MetricsConfig{
		HistogramAggregation: otelcfg.HistogramAggregationExponential,
		ExponentialHistogram: otelcfg.ExponentialHistogramConfig{
			MaxSize:  64,
			MaxScale: 12,
		},
		// ExponentialHistogram ignores Buckets,
		// added empty for the reader.
		Buckets: export.Buckets{},
	}

	view := statRttHistogramView(cfg)

	stream, ok := view(defaultStatRttInstrument)
	require.True(t, ok)

	aggregation, ok := stream.Aggregation.(sdkmetric.AggregationBase2ExponentialHistogram)
	require.True(t, ok)
	assert.Equal(t, int32(64), aggregation.MaxSize)
	assert.Equal(t, int32(12), aggregation.MaxScale)
}

func TestStatRttHistogramView_ExplicitUsesBuckets(t *testing.T) {
	buckets := []float64{0.001, 0.010, 0.100, 1.0}
	cfg := &otelcfg.MetricsConfig{
		HistogramAggregation: otelcfg.HistogramAggregationExplicit,
		Buckets: export.Buckets{
			StatTCPRttHistogram: buckets,
		},
	}

	view := statRttHistogramView(cfg)

	stream, ok := view(defaultStatRttInstrument)
	require.True(t, ok)

	aggregation, ok := stream.Aggregation.(sdkmetric.AggregationExplicitBucketHistogram)
	require.True(t, ok)
	assert.Equal(t, buckets, aggregation.Boundaries)
}

func TestStatRttHistogramView_InvalidAggregationFallsBackToExplicit(t *testing.T) {
	buckets := []float64{0.001, 0.010, 0.100, 1.0}
	cfg := &otelcfg.MetricsConfig{
		HistogramAggregation: "invalid_value",
		Buckets: export.Buckets{
			StatTCPRttHistogram: buckets,
		},
	}

	view := statRttHistogramView(cfg)

	stream, ok := view(defaultStatRttInstrument)
	require.True(t, ok)

	aggregation, ok := stream.Aggregation.(sdkmetric.AggregationExplicitBucketHistogram)
	require.True(t, ok)
	assert.Equal(t, buckets, aggregation.Boundaries)
}
