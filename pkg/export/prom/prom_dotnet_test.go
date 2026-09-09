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
			require.Equal(t, float64(expected[generation]), point.GetCounter().GetValue())
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
