// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestGoRuntimeCPUTimeCounterDeltaResetAndRemoval(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := newGoRuntimeMetricsCollector(nil)
	registry.MustRegister(collector.cpuTime)

	cpu := &runtimemetrics.GoRuntimeCPUTimeSnapshot{UserTime: 100}
	collector.collectCPUTime(nil, cpu)
	assertGoRuntimeCPUTime(t, registry, 100)

	cpu.UserTime = 250
	collector.collectCPUTime(nil, cpu)
	assertGoRuntimeCPUTime(t, registry, 250)

	cpu.UserTime = 50
	collector.collectCPUTime(nil, cpu)
	assertGoRuntimeCPUTime(t, registry, 50)

	collector.collectCPUTime(nil, nil)
	assert.Nil(t, gatheredMetric(t, registry, attributes.GoRuntimeCPUTime.Prom, map[string]string{
		"go_cpu_state":          "user",
		"go_cpu_detailed_state": "",
	}))
}

func TestGoRuntimeGCCyclesCounterDeltaResetAndRemoval(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := newGoRuntimeMetricsCollector(nil)
	registry.MustRegister(collector.memoryGCCycles)

	for _, value := range []uint64{10, 15, 2} {
		collector.addGCCycles(nil, value)
		metric := gatheredMetric(t, registry, attributes.GoRuntimeMemoryGCCycles.Prom, nil)
		require.NotNil(t, metric)
		assert.InDelta(t, float64(value), metric.GetCounter().GetValue(), 0)
	}

	collector.deleteGCCycles(nil)
	assert.Nil(t, gatheredMetric(t, registry, attributes.GoRuntimeMemoryGCCycles.Prom, nil))
}

func TestGoRuntimeMemoryCountersDeltaResetAndRemoval(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := newGoRuntimeMetricsCollector(nil)
	registry.MustRegister(collector.memoryAllocated, collector.memoryAllocations)

	metrics := []struct {
		counter *prometheus.CounterVec
		name    string
	}{
		{counter: collector.memoryAllocated, name: attributes.GoRuntimeMemoryAllocated.Prom},
		{counter: collector.memoryAllocations, name: attributes.GoRuntimeMemoryAllocations.Prom},
	}
	for _, metric := range metrics {
		for _, value := range []uint64{10, 15, 2} {
			collector.addCounter(metric.counter, metric.name, nil, value, 1)
			got := gatheredMetric(t, registry, metric.name, nil)
			require.NotNil(t, got)
			assert.InDelta(t, float64(value), got.GetCounter().GetValue(), 0)
		}

		collector.deleteCounter(metric.counter, metric.name, nil)
		assert.Nil(t, gatheredMetric(t, registry, metric.name, nil))
	}
}

func TestGoRuntimeMemoryMetricsRemovedWhenSnapshotFieldsBecomeUnavailable(t *testing.T) {
	reporter, registry, snapshot := newGoRuntimeMemoryMetricsTestReporter(t)

	reporter.collectGoRuntimeMetrics(snapshot)
	assertGoRuntimeMemoryMetricsPresent(t, registry)

	metrics := snapshot.Go
	snapshot.Go = &runtimemetrics.GoRuntimeMetricSnapshot{}
	reporter.collectGoRuntimeMetrics(snapshot)
	assertGoRuntimeMemoryMetricsAbsent(t, registry)

	snapshot.Go = metrics
	reporter.collectGoRuntimeMetrics(snapshot)
	assertGoRuntimeMemoryMetricsPresent(t, registry)
}

func TestDeleteRuntimeMetricsRemovesGoRuntimeMemoryMetrics(t *testing.T) {
	reporter, registry, snapshot := newGoRuntimeMemoryMetricsTestReporter(t)

	reporter.collectGoRuntimeMetrics(snapshot)
	assertGoRuntimeMemoryMetricsPresent(t, registry)

	reporter.deleteRuntimeMetrics(&snapshot.Service)
	assertGoRuntimeMemoryMetricsAbsent(t, registry)

	reporter.collectGoRuntimeMetrics(snapshot)
	assertGoRuntimeMemoryMetricsPresent(t, registry)
}

func newGoRuntimeMemoryMetricsTestReporter(
	t *testing.T,
) (*metricsReporter, *prometheus.Registry, runtimemetrics.RuntimeMetricSnapshot) {
	t.Helper()

	selection := attributes.Selection{
		attributes.Resource.Section: attributes.InclusionLists{Include: []string{"service.name"}},
	}
	reporter := &metricsReporter{userAttribSelection: selection}
	reporter.goRuntimeMetrics = newGoRuntimeMetricsCollector(
		labelNamesTargetInfo(false, false, &reporter.nodeMeta, nil, selection),
	)
	registry := prometheus.NewRegistry()
	registry.MustRegister(
		reporter.goRuntimeMetrics.memoryUsed,
		reporter.goRuntimeMetrics.memoryAllocated,
		reporter.goRuntimeMetrics.memoryAllocations,
	)

	stack := int64(10)
	other := int64(20)
	allocated := uint64(30)
	allocations := uint64(40)
	return reporter, registry, runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{UID: svc.UID{Name: "orders"}},
		Go: &runtimemetrics.GoRuntimeMetricSnapshot{
			MemoryUsedStack:   &stack,
			MemoryUsedOther:   &other,
			MemoryAllocated:   &allocated,
			MemoryAllocations: &allocations,
		},
	}
}

func assertGoRuntimeMemoryMetricsPresent(t *testing.T, registry *prometheus.Registry) {
	t.Helper()

	for _, metric := range goRuntimeMemoryMetricSeries() {
		require.NotNil(t, gatheredMetric(t, registry, metric.name, metric.labels))
	}
}

func assertGoRuntimeMemoryMetricsAbsent(t *testing.T, registry *prometheus.Registry) {
	t.Helper()

	for _, metric := range goRuntimeMemoryMetricSeries() {
		assert.Nil(t, gatheredMetric(t, registry, metric.name, metric.labels))
	}
}

func goRuntimeMemoryMetricSeries() []struct {
	name   string
	labels map[string]string
} {
	return []struct {
		name   string
		labels map[string]string
	}{
		{
			name: attributes.GoRuntimeMemoryUsed.Prom,
			labels: map[string]string{
				"service_name":   "orders",
				"go_memory_type": "stack",
			},
		},
		{
			name: attributes.GoRuntimeMemoryUsed.Prom,
			labels: map[string]string{
				"service_name":   "orders",
				"go_memory_type": "other",
			},
		},
		{
			name:   attributes.GoRuntimeMemoryAllocated.Prom,
			labels: map[string]string{"service_name": "orders"},
		},
		{
			name:   attributes.GoRuntimeMemoryAllocations.Prom,
			labels: map[string]string{"service_name": "orders"},
		},
	}
}

func assertGoRuntimeCPUTime(t *testing.T, registry *prometheus.Registry, nanoseconds int64) {
	t.Helper()

	metric := gatheredMetric(t, registry, attributes.GoRuntimeCPUTime.Prom, map[string]string{
		"go_cpu_state":          "user",
		"go_cpu_detailed_state": "",
	})
	require.NotNil(t, metric)
	assert.InDelta(t, float64(nanoseconds)/float64(time.Second), metric.GetCounter().GetValue(), 1e-12)
}
