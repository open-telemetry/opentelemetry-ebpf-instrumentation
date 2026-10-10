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
					ProcessCPUCount: &current, ProcessMemoryWorkingSet: &current,
					GCCollections: [3]*uint64{&collections},
					GCHeapSize:    [runtimemetrics.DotnetHeapGenerationCount]*int64{&current},
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
			firstExpiration := now
			expectedExpiration := time.Time{}
			if ttl != 0 {
				expectedExpiration = firstExpiration
			}
			assertValue := func(name string, want int64) {
				t.Helper()
				names := []string{name}
				if name == attributes.DotnetProcessMemoryWorkingSet.OTEL {
					names = append(names, attributes.DotnetProcessCPUCount.OTEL, attributes.DotnetGCHeapSize.OTEL)
				}
				for _, metricName := range names {
					points := collectGoRuntimeInt64Points(t, reader, metricName)
					require.Len(t, points, 1, metricName)
					require.Equal(t, want, points[0].Value, metricName)
				}
			}
			publish(first)
			publish(second)
			require.Equal(t, expectedExpiration, metrics.dotnetMetrics.lastExpiration)
			now = now.Add(30 * time.Second)
			publish(second)
			require.Equal(t, expectedExpiration, metrics.dotnetMetrics.lastExpiration)
			now = now.Add(30 * time.Second)
			publish(second)
			require.Equal(t, expectedExpiration, metrics.dotnetMetrics.lastExpiration)
			assertValue(attributes.DotnetProcessMemoryWorkingSet.OTEL, 30)
			now = now.Add(time.Nanosecond)
			publish(second)
			if ttl == 0 {
				assertValue(attributes.DotnetProcessMemoryWorkingSet.OTEL, 30)
			} else {
				require.Equal(t, now, metrics.dotnetMetrics.lastExpiration)
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
				require.Empty(t, collectGoRuntimeInt64Points(t, reader, attributes.DotnetProcessCPUCount.OTEL))
				require.Empty(t, collectGoRuntimeInt64Points(t, reader, attributes.DotnetGCHeapSize.OTEL))
			}
			publish(first)
			assertValue(attributes.DotnetGCCollections.OTEL, 14)
		})
	}
}

func TestDotnetRuntimeCurrentValueAvailability(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })
	var metrics dotnetRuntimeMetrics
	require.NoError(t, setupDotnetRuntimeMeters(&metrics, provider.Meter(reporterName), 0))
	assertValue := func(name string, want *int64) {
		t.Helper()
		points := collectGoRuntimeInt64Points(t, reader, name)
		if want == nil {
			require.Empty(t, points, name)
			return
		}
		require.Len(t, points, 1, name)
		require.Equal(t, *want, points[0].Value, name)
	}
	memory := int64(10)
	assembly := int64(20)
	first := runtimemetrics.RuntimeMetricSnapshot{
		PID: 123, Generation: 1,
		Dotnet: &runtimemetrics.DotnetRuntimeMetricSnapshot{ProcessMemoryWorkingSet: &memory},
	}
	second := runtimemetrics.RuntimeMetricSnapshot{
		PID: 456, Generation: 1,
		Dotnet: &runtimemetrics.DotnetRuntimeMetricSnapshot{AssemblyCount: &assembly},
	}
	recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
	recordDotnetRuntimeMetrics(t.Context(), &metrics, second)
	assertValue(attributes.DotnetProcessMemoryWorkingSet.OTEL, &memory)
	assertValue(attributes.DotnetAssemblyCount.OTEL, &assembly)

	first.Removed = true
	recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
	assertValue(attributes.DotnetProcessMemoryWorkingSet.OTEL, nil)
	assertValue(attributes.DotnetAssemblyCount.OTEL, &assembly)

	zero := int64(0)
	second.Dotnet = &runtimemetrics.DotnetRuntimeMetricSnapshot{AssemblyCount: &zero}
	recordDotnetRuntimeMetrics(t.Context(), &metrics, second)
	assertValue(attributes.DotnetAssemblyCount.OTEL, &zero)
	second.Removed = true
	recordDotnetRuntimeMetrics(t.Context(), &metrics, second)
	assertValue(attributes.DotnetAssemblyCount.OTEL, nil)
	require.Equal(t, dotnetRuntimeMetricCounts{}, metrics.activeCurrent)
}

func TestDotnetRuntimeExpiryWaitsForNextSweep(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })
	var metrics RuntimeMetrics
	require.NoError(t, setupDotnetRuntimeMeters(&metrics.dotnetMetrics, provider.Meter(reporterName), time.Minute))
	now := time.Unix(1000, 0)
	metrics.dotnetMetrics.clock = func() time.Time { return now }
	recordRuntimeMetrics(t.Context(), &metrics, runtimemetrics.RuntimeMetricSnapshot{})
	now = now.Add(time.Second)
	value := int64(10)
	snapshot := runtimemetrics.RuntimeMetricSnapshot{
		PID: 123, Generation: 1,
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableDotnet, Features: export.FeatureApplicationRuntime},
		Dotnet:  &runtimemetrics.DotnetRuntimeMetricSnapshot{ProcessMemoryWorkingSet: &value},
	}
	recordRuntimeMetrics(t.Context(), &metrics, snapshot)
	now = now.Add(59*time.Second + time.Nanosecond)
	recordRuntimeMetrics(t.Context(), &metrics, runtimemetrics.RuntimeMetricSnapshot{})
	lastSweep := metrics.dotnetMetrics.lastExpiration
	now = now.Add(2 * time.Second)
	recordRuntimeMetrics(t.Context(), &metrics, runtimemetrics.RuntimeMetricSnapshot{})
	require.Equal(t, lastSweep, metrics.dotnetMetrics.lastExpiration)
	points := collectGoRuntimeInt64Points(t, reader, attributes.DotnetProcessMemoryWorkingSet.OTEL)
	require.Len(t, points, 1)
	require.Equal(t, value, points[0].Value)
	now = lastSweep.Add(time.Minute + time.Nanosecond)
	recordRuntimeMetrics(t.Context(), &metrics, runtimemetrics.RuntimeMetricSnapshot{})
	require.Empty(t, collectGoRuntimeInt64Points(t, reader, attributes.DotnetProcessMemoryWorkingSet.OTEL))
}

func TestDotnetRuntimeCurrentValuesAggregateProcesses(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })
	var metrics dotnetRuntimeMetrics
	require.NoError(t, setupDotnetRuntimeMeters(&metrics, provider.Meter(reporterName), 0))
	values := func(value int64) *runtimemetrics.DotnetRuntimeMetricSnapshot {
		return &runtimemetrics.DotnetRuntimeMetricSnapshot{
			ProcessCPUCount: &value, ProcessMemoryWorkingSet: &value, GCCommittedMemory: &value,
			ThreadPoolThreadCount: &value, ThreadPoolQueueLength: &value,
			TimerCount: &value, AssemblyCount: &value,
		}
	}
	assertTotal := func(want int64) {
		t.Helper()
		for _, name := range []attributes.Name{
			attributes.DotnetProcessCPUCount, attributes.DotnetProcessMemoryWorkingSet, attributes.DotnetGCCommittedMemory,
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
		attributes.DotnetProcessCPUCount, attributes.DotnetProcessMemoryWorkingSet, attributes.DotnetGCCommittedMemory,
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

func TestDotnetRuntimeCumulativeDurationCounters(t *testing.T) {
	for _, tc := range []struct {
		name attributes.Name
		mode string
		set  func(*runtimemetrics.DotnetRuntimeMetricSnapshot, *float64)
	}{
		{attributes.DotnetGCPauseTime, "", func(s *runtimemetrics.DotnetRuntimeMetricSnapshot, v *float64) { s.GCPauseTime = v }},
		{attributes.DotnetJITCompilationTime, "", func(s *runtimemetrics.DotnetRuntimeMetricSnapshot, v *float64) { s.JITCompilationTime = v }},
		{attributes.DotnetProcessCPUTime, "user", func(s *runtimemetrics.DotnetRuntimeMetricSnapshot, v *float64) { s.ProcessCPUTimeUser = v }},
		{attributes.DotnetProcessCPUTime, "system", func(s *runtimemetrics.DotnetRuntimeMetricSnapshot, v *float64) { s.ProcessCPUTimeSystem = v }},
	} {
		t.Run(tc.name.OTEL+"/"+tc.mode, func(t *testing.T) {
			reader := metric.NewManualReader()
			provider := metric.NewMeterProvider(metric.WithReader(reader))
			t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })
			var metrics dotnetRuntimeMetrics
			require.NoError(t, setupDotnetRuntimeMeters(&metrics, provider.Meter(reporterName), 0))
			sample := func(value float64) *runtimemetrics.DotnetRuntimeMetricSnapshot {
				snapshot := &runtimemetrics.DotnetRuntimeMetricSnapshot{}
				tc.set(snapshot, &value)
				return snapshot
			}
			assertTotal := func(expected float64) {
				t.Helper()
				var data metricdata.ResourceMetrics
				require.NoError(t, reader.Collect(t.Context(), &data))
				for _, scope := range data.ScopeMetrics {
					for _, m := range scope.Metrics {
						if m.Name != tc.name.OTEL {
							continue
						}
						require.Equal(t, "s", m.Unit)
						sum, ok := m.Data.(metricdata.Sum[float64])
						require.True(t, ok)
						require.True(t, sum.IsMonotonic)
						require.Equal(t, metricdata.CumulativeTemporality, sum.Temporality)
						require.Len(t, sum.DataPoints, 1)
						if tc.mode == "" {
							require.Zero(t, sum.DataPoints[0].Attributes.Len())
						} else {
							require.Equal(t, 1, sum.DataPoints[0].Attributes.Len())
							mode, ok := sum.DataPoints[0].Attributes.Value("cpu.mode")
							require.True(t, ok)
							require.Equal(t, tc.mode, mode.AsString())
						}
						require.InDelta(t, expected, sum.DataPoints[0].Value, 1e-12)
						return
					}
				}
				t.Fatalf("missing metric %s", tc.name.OTEL)
			}
			first := runtimemetrics.RuntimeMetricSnapshot{PID: 123, Generation: 1, Dotnet: &runtimemetrics.DotnetRuntimeMetricSnapshot{}}
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			var absent metricdata.ResourceMetrics
			require.NoError(t, reader.Collect(t.Context(), &absent))
			for _, scope := range absent.ScopeMetrics {
				for _, m := range scope.Metrics {
					require.NotEqual(t, tc.name.OTEL, m.Name)
				}
			}
			first.Dotnet = sample(0)
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			assertTotal(0)
			first.Dotnet = sample(0.5)
			second := runtimemetrics.RuntimeMetricSnapshot{PID: 456, Generation: 1, Dotnet: sample(1.25)}
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			recordDotnetRuntimeMetrics(t.Context(), &metrics, second)
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			assertTotal(1.75)

			first.Dotnet = &runtimemetrics.DotnetRuntimeMetricSnapshot{}
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			assertTotal(1.75)
			first.Dotnet = sample(0.75)
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			assertTotal(2)
			first.Dotnet = sample(0.125)
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			assertTotal(2.125)
			first.Generation = 2
			first.Dotnet = sample(0.25)
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			assertTotal(2.375)

			first.Removed = true
			first.Generation = 1
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			require.Len(t, metrics.values, 2)
			first.Generation = 2
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			require.Len(t, metrics.values, 1)
			assertTotal(2.375)
			second.Dotnet = sample(1.5)
			recordDotnetRuntimeMetrics(t.Context(), &metrics, second)
			assertTotal(2.625)
			second.Removed = true
			recordDotnetRuntimeMetrics(t.Context(), &metrics, second)
			require.Empty(t, metrics.values)
			assertTotal(2.625)
		})
	}
}

func TestDotnetRuntimeCumulativeIntegerCounters(t *testing.T) {
	for _, tc := range []struct {
		name attributes.Name
		set  func(*runtimemetrics.DotnetRuntimeMetricSnapshot, *uint64)
	}{
		{attributes.DotnetGCHeapTotalAllocated, func(s *runtimemetrics.DotnetRuntimeMetricSnapshot, v *uint64) { s.GCHeapTotalAllocated = v }},
		{attributes.DotnetJITCompiledILSize, func(s *runtimemetrics.DotnetRuntimeMetricSnapshot, v *uint64) { s.JITCompiledILSize = v }},
		{attributes.DotnetJITCompiledMethods, func(s *runtimemetrics.DotnetRuntimeMetricSnapshot, v *uint64) { s.JITCompiledMethods = v }},
		{attributes.DotnetThreadPoolWorkItemCount, func(s *runtimemetrics.DotnetRuntimeMetricSnapshot, v *uint64) { s.ThreadPoolWorkItemCount = v }},
		{attributes.DotnetMonitorLockContentions, func(s *runtimemetrics.DotnetRuntimeMetricSnapshot, v *uint64) { s.MonitorLockContentions = v }},
	} {
		t.Run(tc.name.OTEL, func(t *testing.T) {
			reader := metric.NewManualReader()
			provider := metric.NewMeterProvider(metric.WithReader(reader))
			t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })
			var metrics dotnetRuntimeMetrics
			require.NoError(t, setupDotnetRuntimeMeters(&metrics, provider.Meter(reporterName), 0))
			sample := func(value uint64) *runtimemetrics.DotnetRuntimeMetricSnapshot {
				snapshot := &runtimemetrics.DotnetRuntimeMetricSnapshot{}
				tc.set(snapshot, &value)
				return snapshot
			}
			assertTotal := func(expected int64) {
				t.Helper()
				var data metricdata.ResourceMetrics
				require.NoError(t, reader.Collect(t.Context(), &data))
				for _, scope := range data.ScopeMetrics {
					for _, m := range scope.Metrics {
						if m.Name != tc.name.OTEL {
							continue
						}
						require.Equal(t, tc.name.Unit, m.Unit)
						sum, ok := m.Data.(metricdata.Sum[int64])
						require.True(t, ok)
						require.True(t, sum.IsMonotonic)
						require.Equal(t, metricdata.CumulativeTemporality, sum.Temporality)
						require.Len(t, sum.DataPoints, 1)
						require.Zero(t, sum.DataPoints[0].Attributes.Len())
						require.Equal(t, expected, sum.DataPoints[0].Value)
						return
					}
				}
				t.Fatalf("missing metric %s", tc.name.OTEL)
			}
			first := runtimemetrics.RuntimeMetricSnapshot{PID: 123, Generation: 1, Dotnet: &runtimemetrics.DotnetRuntimeMetricSnapshot{}}
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			require.Empty(t, collectGoRuntimeInt64Points(t, reader, tc.name.OTEL))
			first.Dotnet = sample(0)
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			assertTotal(0)
			first.Dotnet = sample(10)
			second := runtimemetrics.RuntimeMetricSnapshot{PID: 456, Generation: 1, Dotnet: sample(20)}
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			recordDotnetRuntimeMetrics(t.Context(), &metrics, second)
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			assertTotal(30)

			first.Dotnet = &runtimemetrics.DotnetRuntimeMetricSnapshot{}
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			assertTotal(30)
			first.Dotnet = sample(15)
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			assertTotal(35)
			first.Dotnet = sample(2)
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			assertTotal(37)
			first.Generation = 2
			first.Dotnet = sample(1)
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			assertTotal(38)

			first.Removed = true
			first.Generation = 1
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			require.Len(t, metrics.values, 2)
			first.Generation = 2
			recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
			require.Len(t, metrics.values, 1)
			assertTotal(38)
			second.Dotnet = sample(21)
			recordDotnetRuntimeMetrics(t.Context(), &metrics, second)
			assertTotal(39)
			second.Removed = true
			recordDotnetRuntimeMetrics(t.Context(), &metrics, second)
			require.Empty(t, metrics.values)
			assertTotal(39)
		})
	}
}

func TestDotnetHeapSizeLifecycle(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })
	var metrics dotnetRuntimeMetrics
	require.NoError(t, setupDotnetRuntimeMeters(&metrics, provider.Meter(reporterName), 0))
	sample := func(base int64) *runtimemetrics.DotnetRuntimeMetricSnapshot {
		values := &runtimemetrics.DotnetRuntimeMetricSnapshot{}
		for generation := range values.GCHeapSize {
			value := base + int64(generation)
			values.GCHeapSize[generation] = &value
		}
		return values
	}
	assertSizes := func(base int64, contributors int) {
		t.Helper()
		points := collectGoRuntimeInt64Points(t, reader, attributes.DotnetGCHeapSize.OTEL)
		if contributors == 0 {
			require.Empty(t, points)
			return
		}
		collected := collectGoRuntimeInt64Metric(t, reader, attributes.DotnetGCHeapSize.OTEL)
		require.Equal(t, "By", collected.Unit)
		sum, ok := collected.Data.(metricdata.Sum[int64])
		require.True(t, ok)
		require.False(t, sum.IsMonotonic)
		require.Len(t, points, runtimemetrics.DotnetHeapGenerationCount)
		got := map[string]int64{}
		for _, point := range points {
			generation, ok := point.Attributes.Value("dotnet.gc.heap.generation")
			require.True(t, ok)
			got[generation.AsString()] = point.Value
		}
		for generation, name := range runtimemetrics.DotnetHeapGenerations() {
			require.Equal(t, base+int64(generation*contributors), got[name], name)
		}
	}
	first := runtimemetrics.RuntimeMetricSnapshot{PID: 1, Generation: 1, Dotnet: sample(100)}
	second := runtimemetrics.RuntimeMetricSnapshot{PID: 2, Generation: 1, Dotnet: sample(200)}
	recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
	recordDotnetRuntimeMetrics(t.Context(), &metrics, second)
	assertSizes(300, 2)
	first.Dotnet = sample(0)
	recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
	assertSizes(200, 2)
	first.Generation++
	first.Dotnet = sample(10)
	recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
	assertSizes(210, 2)
	stale := first
	stale.Generation--
	stale.Removed = true
	recordDotnetRuntimeMetrics(t.Context(), &metrics, stale)
	assertSizes(210, 2)
	second.Dotnet = &runtimemetrics.DotnetRuntimeMetricSnapshot{}
	recordDotnetRuntimeMetrics(t.Context(), &metrics, second)
	assertSizes(10, 1)
	first.Removed = true
	recordDotnetRuntimeMetrics(t.Context(), &metrics, first)
	assertSizes(0, 0)
	require.Equal(t, dotnetRuntimeMetricCounts{}, metrics.activeCurrent)
}
