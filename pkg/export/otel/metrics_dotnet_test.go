// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestDotnetRuntimeCounterSnapshots(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })
	var metrics RuntimeMetrics
	require.NoError(t, setupDotnetRuntimeMeters(&metrics.dotnetMetrics, provider.Meter(reporterName)))
	collect := func() map[string]int64 {
		var data metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(t.Context(), &data))
		values := map[string]int64{}
		for _, scope := range data.ScopeMetrics {
			for _, m := range scope.Metrics {
				if m.Name != attributes.DotnetGCCollections.OTEL {
					continue
				}
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				require.True(t, sum.IsMonotonic)
				for _, point := range sum.DataPoints {
					generation, ok := point.Attributes.Value(attribute.Key("dotnet.gc.heap.generation"))
					require.True(t, ok)
					values[generation.AsString()] = point.Value
				}
			}
		}
		return values
	}
	counts := [3]uint64{}
	snapshot := runtimemetrics.RuntimeMetricSnapshot{
		PID: 123, Generation: 1,
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableDotnet, Features: export.FeatureApplicationRuntime},
		Dotnet:  &runtimemetrics.DotnetRuntimeMetricSnapshot{GCCollections: [3]*uint64{&counts[0], &counts[1], &counts[2]}},
	}
	recordRuntimeMetrics(t.Context(), &metrics, snapshot)
	require.Equal(t, map[string]int64{"gen0": 0, "gen1": 0, "gen2": 0}, collect())
	counts = [3]uint64{3, 5, 7}
	recordRuntimeMetrics(t.Context(), &metrics, snapshot)
	recordRuntimeMetrics(t.Context(), &metrics, snapshot)
	require.Equal(t, map[string]int64{"gen0": 3, "gen1": 5, "gen2": 7}, collect())

	otherCounts := [3]uint64{2, 4, 6}
	other := snapshot
	other.PID = 456
	other.Dotnet = &runtimemetrics.DotnetRuntimeMetricSnapshot{GCCollections: [3]*uint64{&otherCounts[0], &otherCounts[1], &otherCounts[2]}}
	recordRuntimeMetrics(t.Context(), &metrics, other)
	recordRuntimeMetrics(t.Context(), &metrics, snapshot)
	recordRuntimeMetrics(t.Context(), &metrics, other)
	require.Equal(t, map[string]int64{"gen0": 5, "gen1": 9, "gen2": 13}, collect())

	snapshot.Generation = 2
	counts = [3]uint64{1, 2, 3}
	recordRuntimeMetrics(t.Context(), &metrics, snapshot)
	require.Equal(t, map[string]int64{"gen0": 6, "gen1": 11, "gen2": 16}, collect())

	snapshot.Removed = true
	snapshot.Generation = 1
	recordRuntimeMetrics(t.Context(), &metrics, snapshot)
	require.Len(t, metrics.dotnetMetrics.values, 2)
	snapshot.Removed = false
	snapshot.Generation = 2
	recordRuntimeMetrics(t.Context(), &metrics, snapshot)
	recordRuntimeMetrics(t.Context(), &metrics, other)
	require.Equal(t, map[string]int64{"gen0": 6, "gen1": 11, "gen2": 16}, collect())

	snapshot.Removed = true
	recordRuntimeMetrics(t.Context(), &metrics, snapshot)
	require.Len(t, metrics.dotnetMetrics.values, 1)
	recordRuntimeMetrics(t.Context(), &metrics, other)
	require.Equal(t, map[string]int64{"gen0": 6, "gen1": 11, "gen2": 16}, collect())
	other.Removed = true
	recordRuntimeMetrics(t.Context(), &metrics, other)
	require.Empty(t, metrics.dotnetMetrics.values)
	require.Equal(t, map[string]int64{"gen0": 6, "gen1": 11, "gen2": 16}, collect())
}
