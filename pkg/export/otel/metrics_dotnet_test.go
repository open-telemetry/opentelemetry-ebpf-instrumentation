// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestDotnetRuntimeCurrentValuesExpirePerProcess(t *testing.T) {
	for _, ttl := range []time.Duration{time.Minute, 0} {
		t.Run(ttl.String(), func(t *testing.T) {
			reader := metric.NewManualReader()
			provider := metric.NewMeterProvider(metric.WithReader(reader))
			t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })
			var metrics RuntimeMetrics
			require.NoError(t, setupDotnetRuntimeMeters(&metrics.dotnetMetrics, provider.Meter(reporterName), ttl))
			now := time.Unix(1000, 0)
			metrics.dotnetMetrics.clock = func() time.Time { return now }
			sample := func(current int64, collections uint64) *runtimemetrics.DotnetRuntimeMetricSnapshot {
				return &runtimemetrics.DotnetRuntimeMetricSnapshot{
					ProcessMemoryWorkingSet: &current,
					GCCollections:           [3]*uint64{&collections},
				}
			}
			first := runtimemetrics.RuntimeMetricSnapshot{
				PID: 123, Generation: 1,
				Service: svc.Attrs{SDKLanguage: svc.InstrumentableDotnet, Features: export.FeatureApplicationRuntime},
				Dotnet:  sample(10, 5),
			}
			second := first
			second.PID = 456
			second.Dotnet = sample(20, 8)
			publish := func(snapshot runtimemetrics.RuntimeMetricSnapshot) {
				recordRuntimeMetrics(t.Context(), &metrics, snapshot)
			}
			assertValue := func(name string, want int64) {
				t.Helper()
				points := collectGoRuntimeInt64Points(t, reader, name)
				require.Len(t, points, 1, name)
				require.Equal(t, want, points[0].Value, name)
			}
			publish(first)
			publish(second)
			now = now.Add(30 * time.Second)
			publish(second)
			now = now.Add(30 * time.Second)
			publish(second)
			assertValue(attributes.DotnetProcessMemoryWorkingSet.OTEL, 30)
			now = now.Add(time.Nanosecond)
			publish(second)
			if ttl == 0 {
				assertValue(attributes.DotnetProcessMemoryWorkingSet.OTEL, 30)
			} else {
				assertValue(attributes.DotnetProcessMemoryWorkingSet.OTEL, 20)
			}
			first.Dotnet = sample(7, 5)
			publish(first)
			assertValue(attributes.DotnetProcessMemoryWorkingSet.OTEL, 27)
			assertValue(attributes.DotnetGCCollections.OTEL, 13)
			first.Dotnet = sample(7, 6)
			publish(first)
			assertValue(attributes.DotnetGCCollections.OTEL, 14)

			now = now.Add(time.Minute + time.Nanosecond)
			publish(runtimemetrics.RuntimeMetricSnapshot{})
			if ttl == 0 {
				assertValue(attributes.DotnetProcessMemoryWorkingSet.OTEL, 27)
			} else {
				require.Empty(t, collectGoRuntimeInt64Points(t, reader, attributes.DotnetProcessMemoryWorkingSet.OTEL))
			}
			publish(first)
			assertValue(attributes.DotnetGCCollections.OTEL, 14)
		})
	}
}

func TestDotnetRuntimeCurrentValuesAggregateProcesses(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })
	var metrics dotnetRuntimeMetrics
	require.NoError(t, setupDotnetRuntimeMeters(&metrics, provider.Meter(reporterName), 0))
	values := func(value int64) *runtimemetrics.DotnetRuntimeMetricSnapshot {
		return &runtimemetrics.DotnetRuntimeMetricSnapshot{
			ProcessMemoryWorkingSet: &value, GCCommittedMemory: &value,
			ThreadPoolThreadCount: &value, ThreadPoolQueueLength: &value,
			TimerCount: &value, AssemblyCount: &value,
		}
	}
	assertTotal := func(want int64) {
		t.Helper()
		for _, name := range []attributes.Name{
			attributes.DotnetProcessMemoryWorkingSet, attributes.DotnetGCCommittedMemory,
			attributes.DotnetThreadPoolThreadCount, attributes.DotnetThreadPoolQueueLength,
			attributes.DotnetTimerCount, attributes.DotnetAssemblyCount,
		} {
			collected := collectGoRuntimeInt64Metric(t, reader, name.OTEL)
			require.Equal(t, name.Unit, collected.Unit)
			sum, ok := collected.Data.(metricdata.Sum[int64])
			require.True(t, ok, name.OTEL)
			require.False(t, sum.IsMonotonic, name.OTEL)
			require.Len(t, sum.DataPoints, 1, name.OTEL)
			require.Equal(t, want, sum.DataPoints[0].Value, name.OTEL)
		}
	}
	first := runtimemetrics.RuntimeMetricSnapshot{PID: 123, Generation: 1, Dotnet: values(10)}
	second := runtimemetrics.RuntimeMetricSnapshot{PID: 456, Generation: 2, Dotnet: values(20)}
	recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
	recordDotnetRuntimeMetrics(t.Context(), &metrics, second)
	assertTotal(30)
	first.Dotnet = values(4)
	recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
	assertTotal(24)
	first.Dotnet = &runtimemetrics.DotnetRuntimeMetricSnapshot{}
	recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
	assertTotal(20)
	first.Dotnet = values(4)
	recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
	first.Generation = 3
	first.Dotnet = values(7)
	recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
	assertTotal(27)
	first.Removed = true
	first.Generation = 1
	recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
	assertTotal(27)
	first.Generation = 3
	recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
	assertTotal(20)
	second.Removed = true
	recordDotnetRuntimeMetrics(t.Context(), &metrics, second)
	for _, name := range []attributes.Name{
		attributes.DotnetProcessMemoryWorkingSet, attributes.DotnetGCCommittedMemory,
		attributes.DotnetThreadPoolThreadCount, attributes.DotnetThreadPoolQueueLength,
		attributes.DotnetTimerCount, attributes.DotnetAssemblyCount,
	} {
		require.Empty(t, collectGoRuntimeInt64Points(t, reader, name.OTEL), name.OTEL)
	}
	second.Removed = false
	second.Dotnet = values(0)
	recordDotnetRuntimeMetrics(t.Context(), &metrics, second)
	assertTotal(0)
}

func TestDotnetRuntimeCounterSnapshots(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })
	var metrics RuntimeMetrics
	require.NoError(t, setupDotnetRuntimeMeters(&metrics.dotnetMetrics, provider.Meter(reporterName), 0))
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
