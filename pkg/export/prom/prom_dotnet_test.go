// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestDotnetRuntimeCollectorLabels(t *testing.T) {
	collector := newDotnetRuntimeMetricsCollector([]string{
		"service_name", "dotnet_gc_heap_generation", "service_namespace",
	}, time.Now, time.Minute)
	require.Equal(t, []int{0, 2}, collector.baseLabelIndexes)
	registry := prometheus.NewRegistry()
	require.NoError(t, registry.Register(collector.collections))
	collector.collections.WithLabelValues("orders", "production", "gen2").Metric.Add(3)
	point := gatheredMetric(t, registry, attributes.DotnetGCCollections.Prom, map[string]string{
		"service_name": "orders", "service_namespace": "production", "dotnet_gc_heap_generation": "gen2",
	})
	require.NotNil(t, point)
	require.InDelta(t, 3, point.GetCounter().GetValue(), 0)
}

func TestDotnetRuntimeCurrentValuesExpirePerProcess(t *testing.T) {
	for _, ttl := range []time.Duration{time.Minute, 0} {
		t.Run(ttl.String(), func(t *testing.T) {
			now := time.Unix(1000, 0)
			previousClock := timeNow
			timeNow = func() time.Time { return now }
			t.Cleanup(func() { timeNow = previousClock })
			registry := prometheus.NewRegistry()
			reporter, err := newReporter(
				t.Context(),
				&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
				&PrometheusConfig{Registry: registry, TTL: ttl},
				&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRuntime},
				&attributes.SelectorConfig{SelectionCfg: attributes.Selection{
					attributes.Resource.Section: attributes.InclusionLists{Include: []string{"service.name"}},
				}},
				request.UnresolvedNames{}, nil,
				msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1)), nil,
			)
			require.NoError(t, err)
			sample := func(current int64, collections uint64) *runtimemetrics.DotnetRuntimeMetricSnapshot {
				return &runtimemetrics.DotnetRuntimeMetricSnapshot{
					ProcessMemoryWorkingSet: &current,
					GCCollections:           [3]*uint64{&collections},
				}
			}
			first := runtimemetrics.RuntimeMetricSnapshot{
				PID: 123, Generation: 1,
				Service: svc.Attrs{UID: svc.UID{Name: "orders"}, SDKLanguage: svc.InstrumentableDotnet, Features: export.FeatureApplicationRuntime},
				Dotnet:  sample(10, 5),
			}
			second := first
			second.PID = 456
			second.Dotnet = sample(20, 8)
			publish := func(snapshot runtimemetrics.RuntimeMetricSnapshot) {
				reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{snapshot})
			}
			labels := map[string]string{"service_name": "orders"}
			assertCurrent := func(want float64) {
				t.Helper()
				point := gatheredMetric(t, registry, attributes.DotnetProcessMemoryWorkingSet.Prom, labels)
				require.NotNil(t, point)
				require.InDelta(t, want, point.GetGauge().GetValue(), 0)
			}
			assertCollections := func(want float64) {
				t.Helper()
				point := gatheredMetric(t, registry, attributes.DotnetGCCollections.Prom,
					map[string]string{"service_name": "orders", "dotnet_gc_heap_generation": "gen0"})
				require.NotNil(t, point)
				require.InDelta(t, want, point.GetCounter().GetValue(), 0)
			}
			publish(first)
			publish(second)
			firstExpiration := now
			expectedExpiration := time.Time{}
			if ttl != 0 {
				expectedExpiration = firstExpiration
			}
			require.Equal(t, expectedExpiration, reporter.dotnetRuntimeMetrics.lastExpiration)
			now = now.Add(30 * time.Second)
			publish(second)
			require.Equal(t, expectedExpiration, reporter.dotnetRuntimeMetrics.lastExpiration)
			now = now.Add(30 * time.Second)
			publish(second)
			require.Equal(t, expectedExpiration, reporter.dotnetRuntimeMetrics.lastExpiration)
			assertCurrent(30)
			now = now.Add(time.Nanosecond)
			publish(second)
			if ttl == 0 {
				assertCurrent(30)
			} else {
				require.Equal(t, now, reporter.dotnetRuntimeMetrics.lastExpiration)
				assertCurrent(20)
			}
			first.Dotnet = sample(7, 5)
			publish(first)
			assertCurrent(27)
			assertCollections(13)
			first.Dotnet = sample(7, 6)
			publish(first)
			assertCollections(14)

			now = now.Add(time.Minute + time.Nanosecond)
			publish(runtimemetrics.RuntimeMetricSnapshot{})
			if ttl == 0 {
				assertCurrent(27)
			} else {
				require.Nil(t, gatheredMetric(t, registry, attributes.DotnetProcessMemoryWorkingSet.Prom, labels))
			}
			publish(first)
			if ttl == 0 {
				assertCurrent(27)
			} else {
				assertCurrent(7)
			}
		})
	}
}

func TestDotnetRuntimeCurrentValuesAggregateProcesses(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter, err := newReporter(
		t.Context(),
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&PrometheusConfig{Registry: registry, TTL: time.Minute},
		&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRuntime},
		&attributes.SelectorConfig{SelectionCfg: attributes.Selection{
			attributes.Resource.Section: attributes.InclusionLists{Include: []string{"service.name"}},
		}},
		request.UnresolvedNames{}, nil,
		msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1)), nil,
	)
	require.NoError(t, err)
	values := func(value int64) *runtimemetrics.DotnetRuntimeMetricSnapshot {
		return &runtimemetrics.DotnetRuntimeMetricSnapshot{
			ProcessMemoryWorkingSet: &value, GCCommittedMemory: &value,
			ThreadPoolThreadCount: &value, ThreadPoolQueueLength: &value,
			TimerCount: &value, AssemblyCount: &value,
		}
	}
	assertValues := func(service string, expected *int64) {
		t.Helper()
		for _, name := range []string{
			attributes.DotnetProcessMemoryWorkingSet.Prom, attributes.DotnetGCCommittedMemory.Prom,
			attributes.DotnetThreadPoolThreadCount.Prom, attributes.DotnetThreadPoolQueueLength.Prom,
			attributes.DotnetTimerCount.Prom, attributes.DotnetAssemblyCount.Prom,
		} {
			point := gatheredMetric(t, registry, name, map[string]string{"service_name": service})
			if expected == nil {
				require.Nil(t, point, name)
				continue
			}
			require.NotNil(t, point, name)
			require.NotNil(t, point.Gauge, name)
			require.InDelta(t, float64(*expected), point.GetGauge().GetValue(), 0, name)
		}
	}
	publish := func(snapshot runtimemetrics.RuntimeMetricSnapshot) {
		reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{snapshot})
	}
	snapshot := runtimemetrics.RuntimeMetricSnapshot{
		PID: 123, Generation: 1,
		Service: svc.Attrs{UID: svc.UID{Name: "orders"}, SDKLanguage: svc.InstrumentableDotnet, Features: export.FeatureApplicationRuntime},
		Dotnet:  values(10),
	}
	other := snapshot
	other.PID = 456
	other.Dotnet = values(20)
	publish(snapshot)
	publish(other)
	expected := int64(30)
	assertValues("orders", &expected)

	snapshot.Dotnet = values(4)
	publish(snapshot)
	expected = 24
	assertValues("orders", &expected)
	snapshot.Dotnet = &runtimemetrics.DotnetRuntimeMetricSnapshot{}
	publish(snapshot)
	expected = 20
	assertValues("orders", &expected)

	snapshot.Generation = 2
	snapshot.Dotnet = values(7)
	publish(snapshot)
	expected = 27
	assertValues("orders", &expected)
	snapshot.Removed = true
	snapshot.Generation = 1
	publish(snapshot)
	assertValues("orders", &expected)
	snapshot.Generation = 2
	publish(snapshot)
	expected = 20
	assertValues("orders", &expected)
	other.Removed = true
	publish(other)
	assertValues("orders", nil)

	snapshot.Removed = false
	snapshot.Dotnet = values(0)
	publish(snapshot)
	expected = 0
	assertValues("orders", &expected)

	other.Removed = false
	other.Service.UID.Name = "orders-worker"
	publish(other)
	reporter.dotnetRuntimeMetrics.delete(reporter.labelValuesTargetInfo(&snapshot.Service))
	assertValues("orders", nil)
	expected = 20
	assertValues("orders-worker", &expected)
	require.Len(t, reporter.dotnetRuntimeMetrics.currentValues, 1)

	other.Service.UID.Name = "renamed-worker"
	publish(other)
	assertValues("orders-worker", nil)
	assertValues("renamed-worker", &expected)

	// Each metric retains its own contributors, including reported zero.
	snapshot.Service = other.Service
	snapshot.Dotnet = values(3)
	publish(snapshot)
	other.Dotnet = &runtimemetrics.DotnetRuntimeMetricSnapshot{AssemblyCount: new(int64)}
	publish(other)
	for _, name := range []string{
		attributes.DotnetProcessMemoryWorkingSet.Prom, attributes.DotnetAssemblyCount.Prom,
	} {
		point := gatheredMetric(t, registry, name, map[string]string{"service_name": "renamed-worker"})
		require.NotNil(t, point)
		require.InDelta(t, 3, point.GetGauge().GetValue(), 0)
	}
	snapshot.Removed = true
	publish(snapshot)
	require.Nil(t, gatheredMetric(t, registry, attributes.DotnetProcessMemoryWorkingSet.Prom,
		map[string]string{"service_name": "renamed-worker"}))
	point := gatheredMetric(t, registry, attributes.DotnetAssemblyCount.Prom,
		map[string]string{"service_name": "renamed-worker"})
	require.NotNil(t, point)
	require.Zero(t, point.GetGauge().GetValue())
	other.Removed = true
	publish(other)
	require.Nil(t, gatheredMetric(t, registry, attributes.DotnetAssemblyCount.Prom,
		map[string]string{"service_name": "renamed-worker"}))
	require.Empty(t, reporter.dotnetRuntimeMetrics.currentAggregates)
}

func TestDotnetRuntimeDeleteMatchesExactLabels(t *testing.T) {
	collector := newDotnetRuntimeMetricsCollector([]string{"service_name"}, time.Now, time.Minute)
	registry := prometheus.NewRegistry()
	require.NoError(t, registry.Register(collector.collections))
	collector.values = make(map[dotnetRuntimeCounterKey]uint64)
	for _, name := range []string{"orders", "orders-worker"} {
		collector.collections.WithLabelValues(name, "gen2").Metric.Add(3)
		collector.values[dotnetRuntimeCounterKey{
			labels:     runtimeMetricLabelTuple([]string{name, "gen2"}),
			baseLabels: runtimeMetricLabelTuple([]string{name}),
		}] = 3
	}
	collector.delete([]string{"orders"})
	require.Nil(t, gatheredMetric(t, registry, attributes.DotnetGCCollections.Prom,
		map[string]string{"service_name": "orders", "dotnet_gc_heap_generation": "gen2"}))
	require.NotNil(t, gatheredMetric(t, registry, attributes.DotnetGCCollections.Prom,
		map[string]string{"service_name": "orders-worker", "dotnet_gc_heap_generation": "gen2"}))
	require.Len(t, collector.values, 1)
	for key := range collector.values {
		require.Equal(t, runtimeMetricLabelTuple([]string{"orders-worker"}), key.baseLabels)
	}
}

func TestDotnetRuntimeCounterSnapshots(t *testing.T) {
	selection := attributes.Selection{
		attributes.Resource.Section: attributes.InclusionLists{Include: []string{"service.name"}},
	}
	registry := prometheus.NewRegistry()
	reporter, err := newReporter(
		t.Context(),
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&PrometheusConfig{Registry: registry, TTL: time.Minute},
		&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRuntime},
		&attributes.SelectorConfig{SelectionCfg: selection},
		request.UnresolvedNames{},
		nil,
		msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1)),
		nil,
	)
	require.NoError(t, err)
	assertCounts := func(expected [3]uint64) {
		t.Helper()
		for generation, name := range []string{"gen0", "gen1", "gen2"} {
			point := gatheredMetric(t, registry, attributes.DotnetGCCollections.Prom, map[string]string{
				"service_name": "orders", "dotnet_gc_heap_generation": name,
			})
			require.NotNil(t, point)
			require.InDelta(t, float64(expected[generation]), point.GetCounter().GetValue(), 0)
		}
	}
	counts := [3]uint64{}
	snapshot := runtimemetrics.RuntimeMetricSnapshot{
		PID: 123, Generation: 1,
		Service: svc.Attrs{UID: svc.UID{Name: "orders"}, SDKLanguage: svc.InstrumentableDotnet, Features: export.FeatureApplicationRuntime},
		Dotnet:  &runtimemetrics.DotnetRuntimeMetricSnapshot{GCCollections: [3]*uint64{&counts[0], &counts[1], &counts[2]}},
	}
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{snapshot})
	assertCounts([3]uint64{0, 0, 0})
	counts = [3]uint64{3, 5, 7}
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{snapshot})
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{snapshot})
	assertCounts([3]uint64{3, 5, 7})

	otherCounts := [3]uint64{2, 4, 6}
	other := snapshot
	other.PID = 456
	other.Dotnet = &runtimemetrics.DotnetRuntimeMetricSnapshot{GCCollections: [3]*uint64{&otherCounts[0], &otherCounts[1], &otherCounts[2]}}
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{other})
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{snapshot})
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{other})
	assertCounts([3]uint64{5, 9, 13})

	snapshot.Generation = 2
	counts = [3]uint64{1, 2, 3}
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{snapshot})
	assertCounts([3]uint64{6, 11, 16})

	snapshot.Removed = true
	snapshot.Generation = 1
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{snapshot})
	require.Len(t, reporter.dotnetRuntimeMetrics.values, 6)
	snapshot.Removed = false
	snapshot.Generation = 2
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{snapshot})
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{other})
	assertCounts([3]uint64{6, 11, 16})

	snapshot.Removed = true
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{snapshot})
	require.Len(t, reporter.dotnetRuntimeMetrics.values, 3)
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{other})
	assertCounts([3]uint64{6, 11, 16})
	other.Removed = true
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{other})
	require.Empty(t, reporter.dotnetRuntimeMetrics.values)
	assertCounts([3]uint64{6, 11, 16})
}
