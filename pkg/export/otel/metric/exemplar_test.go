// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metric

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/export/otel/metric/components/exemplar"
)

func TestExemplarFilterOptionTakesPrecedenceOverEnvironment(t *testing.T) {
	tests := []struct {
		name          string
		configured    exemplar.Filter
		env           string
		sampled       bool
		wantExemplars bool
	}{
		{name: "configured always_off overrides env always_on", configured: exemplar.AlwaysOffFilter, env: "always_on", sampled: true},
		{name: "configured always_on overrides env always_off", configured: exemplar.AlwaysOnFilter, env: "always_off", wantExemplars: true},
		{name: "configured trace_based skips unsampled", configured: exemplar.SampledFilter, env: "always_on"},
		{name: "configured trace_based keeps sampled", configured: exemplar.SampledFilter, env: "always_off", sampled: true, wantExemplars: true},
		{name: "nil filter uses env always_off", env: "always_off", sampled: true},
		{name: "nil filter uses env always_on", env: "always_on", wantExemplars: true},
		{name: "nil filter and unset env default to trace_based", sampled: true, wantExemplars: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("OTEL_METRICS_EXEMPLAR_FILTER", test.env)

			reader := NewManualReader()
			meter := NewMeterProvider(WithReader(reader), WithExemplarFilter(test.configured)).Meter("exemplars")
			counter, err := meter.Int64Counter("requests")
			require.NoError(t, err)

			counter.Add(spanContext(test.sampled), 1)

			var data metricdata.ResourceMetrics
			require.NoError(t, reader.Collect(t.Context(), &data))
			require.Len(t, data.ScopeMetrics, 1)
			require.Len(t, data.ScopeMetrics[0].Metrics, 1)
			sum, ok := data.ScopeMetrics[0].Metrics[0].Data.(metricdata.Sum[int64])
			require.True(t, ok)
			require.Len(t, sum.DataPoints, 1)
			require.Equal(t, test.wantExemplars, len(sum.DataPoints[0].Exemplars) > 0)
		})
	}
}

func spanContext(sampled bool) context.Context {
	flags := trace.TraceFlags(0)
	if sampled {
		flags = trace.FlagsSampled
	}
	return trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1},
		SpanID:     trace.SpanID{1},
		TraceFlags: flags,
	}))
}
