// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	appexec "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel"
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

func TestGoRuntimeGoroutineCountGaugeAndRemoval(t *testing.T) {
	selection := attributes.Selection{
		attributes.Resource.Section: attributes.InclusionLists{Include: []string{"service.name"}},
	}
	reporter := &metricsReporter{userAttribSelection: selection}
	reporter.goRuntimeMetrics = newGoRuntimeMetricsCollector(
		labelNamesTargetInfo(false, false, &reporter.nodeMeta, nil, selection),
	)
	registry := prometheus.NewRegistry()
	registry.MustRegister(reporter.goRuntimeMetrics.goroutineCount)

	count := int64(12)
	snapshot := runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{UID: svc.UID{Name: "orders"}},
		Go:      &runtimemetrics.GoRuntimeMetricSnapshot{GoroutineCount: &count},
	}
	reporter.collectGoRuntimeMetrics(snapshot)
	labels := map[string]string{"service_name": "orders"}
	metric := gatheredMetric(t, registry, attributes.GoRuntimeGoroutineCount.Prom, labels)
	require.NotNil(t, metric)
	assert.InDelta(t, float64(count), metric.GetGauge().GetValue(), 0)

	snapshot.Go.GoroutineCount = nil
	reporter.collectGoRuntimeMetrics(snapshot)
	assert.Nil(t, gatheredMetric(t, registry, attributes.GoRuntimeGoroutineCount.Prom, labels))

	snapshot.Go.GoroutineCount = &count
	reporter.collectGoRuntimeMetrics(snapshot)
	reporter.deleteRuntimeMetrics(&snapshot.Service)
	assert.Nil(t, gatheredMetric(t, registry, attributes.GoRuntimeGoroutineCount.Prom, labels))

	reporter.collectGoRuntimeMetrics(snapshot)
	require.NotNil(t, gatheredMetric(t, registry, attributes.GoRuntimeGoroutineCount.Prom, labels))
}

func TestGoRuntimeMemoryGCGoalGaugeAndRemoval(t *testing.T) {
	selection := attributes.Selection{
		attributes.Resource.Section: attributes.InclusionLists{Include: []string{"service.name"}},
	}
	reporter := &metricsReporter{userAttribSelection: selection}
	reporter.goRuntimeMetrics = newGoRuntimeMetricsCollector(
		labelNamesTargetInfo(false, false, &reporter.nodeMeta, nil, selection),
	)
	registry := prometheus.NewRegistry()
	registry.MustRegister(reporter.goRuntimeMetrics.memoryGCGoal)

	goal := int64(4096)
	snapshot := runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{UID: svc.UID{Name: "orders"}},
		Go:      &runtimemetrics.GoRuntimeMetricSnapshot{MemoryGCGoal: &goal},
	}
	reporter.collectGoRuntimeMetrics(snapshot)
	labels := map[string]string{"service_name": "orders"}
	metric := gatheredMetric(t, registry, attributes.GoRuntimeMemoryGCGoal.Prom, labels)
	require.NotNil(t, metric)
	assert.InDelta(t, float64(goal), metric.GetGauge().GetValue(), 0)

	snapshot.Go.MemoryGCGoal = nil
	reporter.collectGoRuntimeMetrics(snapshot)
	assert.Nil(t, gatheredMetric(t, registry, attributes.GoRuntimeMemoryGCGoal.Prom, labels))

	snapshot.Go.MemoryGCGoal = &goal
	reporter.collectGoRuntimeMetrics(snapshot)
	reporter.deleteRuntimeMetrics(&snapshot.Service)
	assert.Nil(t, gatheredMetric(t, registry, attributes.GoRuntimeMemoryGCGoal.Prom, labels))
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

func TestPythonRuntimeCountersByGenerationAndRetention(t *testing.T) {
	selection := attributes.Selection{
		attributes.Resource.Section: attributes.InclusionLists{Include: []string{"service.name"}},
	}
	reporter := &metricsReporter{userAttribSelection: selection}
	reporter.pythonRuntimeMetrics = newPythonRuntimeMetricsCollector(
		labelNamesTargetInfo(false, false, &reporter.nodeMeta, nil, selection),
		time.Now,
		time.Minute,
	)
	registry := prometheus.NewRegistry()
	registry.MustRegister(reporter.pythonRuntimeMetrics.collectors()...)

	snapshot := runtimemetrics.RuntimeMetricSnapshot{
		PID:     123,
		Service: svc.Attrs{UID: svc.UID{Name: "orders"}},
		Python: &runtimemetrics.PythonRuntimeMetricSnapshot{Generations: [3]runtimemetrics.PythonGCGenerationMetrics{
			{Collections: 10, CollectedObjects: 20, UncollectableObjects: 1},
			{Collections: 11, CollectedObjects: 21, UncollectableObjects: 2},
			{Collections: 12, CollectedObjects: 22, UncollectableObjects: 3},
		}},
	}
	reporter.collectPythonRuntimeMetrics(snapshot)

	labels := map[string]string{"service_name": "orders", "cpython_gc_generation": "1"}
	metric := gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, labels)
	require.NotNil(t, metric)
	assert.InDelta(t, 11, metric.GetCounter().GetValue(), 0)

	snapshot.Python.Generations[1].Collections = 14
	reporter.collectPythonRuntimeMetrics(snapshot)
	metric = gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, labels)
	require.NotNil(t, metric)
	assert.InDelta(t, 14, metric.GetCounter().GetValue(), 0)

	snapshot.Python.Generations[1].Collections = 3
	reporter.collectPythonRuntimeMetrics(snapshot)
	metric = gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, labels)
	require.NotNil(t, metric)
	assert.InDelta(t, 17, metric.GetCounter().GetValue(), 0)

	reporter.deleteRuntimeMetrics(&snapshot.Service)
	metric = gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, labels)
	require.NotNil(t, metric)
	assert.InDelta(t, 17, metric.GetCounter().GetValue(), 0)
}

func TestPythonRuntimeIgnoresSnapshotAfterProcessTermination(t *testing.T) {
	selection := attributes.Selection{
		attributes.Resource.Section: attributes.InclusionLists{Include: []string{"service.name"}},
	}
	reporter := &metricsReporter{
		pidsTracker:         otel.NewPidServiceTracker(),
		userAttribSelection: selection,
	}
	reporter.pythonRuntimeMetrics = newPythonRuntimeMetricsCollector(
		labelNamesTargetInfo(false, false, &reporter.nodeMeta, nil, selection),
		time.Now,
		time.Minute,
	)
	registry := prometheus.NewRegistry()
	registry.MustRegister(reporter.pythonRuntimeMetrics.collectors()...)

	exportModes := services.NewExportModes()
	exportModes.AllowMetrics()
	service := svc.Attrs{
		UID:         svc.UID{Name: "orders"},
		SDKLanguage: svc.InstrumentablePython,
		Features:    export.FeatureApplicationRuntime,
		ExportModes: exportModes,
	}
	snapshot := runtimemetrics.RuntimeMetricSnapshot{
		PID: 123, Generation: 7, Service: service,
		Python: &runtimemetrics.PythonRuntimeMetricSnapshot{},
	}
	snapshot.Python.Generations[1].Collections = 11
	reporter.pidsTracker.AddPIDWithGeneration(snapshot.PID, service.UID, snapshot.Generation)
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{snapshot})

	labels := map[string]string{"service_name": "orders", "cpython_gc_generation": "1"}
	require.NotNil(t, gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, labels))

	reporter.deleteRuntimeMetrics(&service)
	reporter.pidsTracker.RemovePID(snapshot.PID)
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{snapshot})
	metric := gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, labels)
	require.NotNil(t, metric)
	assert.InDelta(t, 11, metric.GetCounter().GetValue(), 0)
}

func TestPythonRuntimeCollectorFiltersGenerationFromExtraLabels(t *testing.T) {
	collector := newPythonRuntimeMetricsCollector([]string{
		"service_name",
		"cpython_gc_generation",
	}, time.Now, time.Minute)
	registry := prometheus.NewRegistry()
	assert.NotPanics(t, func() {
		registry.MustRegister(collector.collectors()...)
	})
}

func TestPythonRuntimeCountersAggregatePerPIDBaselines(t *testing.T) {
	now := time.Now()
	selection := attributes.Selection{
		attributes.Resource.Section: attributes.InclusionLists{Include: []string{"service.name"}},
	}
	reporter := &metricsReporter{userAttribSelection: selection}
	reporter.pythonRuntimeMetrics = newPythonRuntimeMetricsCollector(
		labelNamesTargetInfo(false, false, &reporter.nodeMeta, nil, selection),
		func() time.Time { return now },
		time.Minute,
	)
	registry := prometheus.NewRegistry()
	registry.MustRegister(reporter.pythonRuntimeMetrics.collectors()...)

	service := svc.Attrs{UID: svc.UID{Name: "workers"}}
	first := runtimemetrics.RuntimeMetricSnapshot{PID: 101, Service: service, Python: &runtimemetrics.PythonRuntimeMetricSnapshot{}}
	first.Python.Generations[1].Collections = 11
	second := runtimemetrics.RuntimeMetricSnapshot{PID: 202, Service: service, Python: &runtimemetrics.PythonRuntimeMetricSnapshot{}}
	second.Python.Generations[1].Collections = 21
	reporter.collectPythonRuntimeMetrics(first)
	reporter.collectPythonRuntimeMetrics(second)

	labels := map[string]string{"service_name": "workers", "cpython_gc_generation": "1"}
	metric := gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, labels)
	require.NotNil(t, metric)
	assert.InDelta(t, 32, metric.GetCounter().GetValue(), 0)

	first.Python.Generations[1].Collections = 14
	reporter.collectPythonRuntimeMetrics(first)
	metric = gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, labels)
	require.NotNil(t, metric)
	assert.InDelta(t, 35, metric.GetCounter().GetValue(), 0)

	first.Removed = true
	reporter.collectPythonRuntimeMetrics(first)
	metric = gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, labels)
	require.NotNil(t, metric)
	assert.InDelta(t, 35, metric.GetCounter().GetValue(), 0)
	second.Removed = true
	reporter.collectPythonRuntimeMetrics(second)
	metric = gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, labels)
	require.NotNil(t, metric)
	assert.InDelta(t, 35, metric.GetCounter().GetValue(), 0)

	now = now.Add(2 * time.Minute)
	assert.Nil(t, gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, labels))

	reporter.deleteRuntimeMetrics(&service)
	assert.Nil(t, gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, labels))
}

func TestPythonRuntimeCountersRefreshTTLWithUnchangedSnapshot(t *testing.T) {
	now := time.Now()
	selection := attributes.Selection{
		attributes.Resource.Section: attributes.InclusionLists{Include: []string{"service.name"}},
	}
	reporter := &metricsReporter{userAttribSelection: selection}
	reporter.pythonRuntimeMetrics = newPythonRuntimeMetricsCollector(
		labelNamesTargetInfo(false, false, &reporter.nodeMeta, nil, selection),
		func() time.Time { return now },
		5*time.Second,
	)
	registry := prometheus.NewRegistry()
	registry.MustRegister(reporter.pythonRuntimeMetrics.collectors()...)

	snapshot := runtimemetrics.RuntimeMetricSnapshot{
		PID:     123,
		Service: svc.Attrs{UID: svc.UID{Name: "orders"}},
		Python:  &runtimemetrics.PythonRuntimeMetricSnapshot{},
	}
	snapshot.Python.Generations[0].Collections = 10
	reporter.collectPythonRuntimeMetrics(snapshot)

	now = now.Add(4 * time.Second)
	reporter.collectPythonRuntimeMetrics(snapshot)
	now = now.Add(4 * time.Second)
	labels := map[string]string{"service_name": "orders", "cpython_gc_generation": "0"}
	require.NotNil(t, gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, labels))

	now = now.Add(2 * time.Second)
	assert.Nil(t, gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, labels))
}

func TestPythonRuntimeCountersSurviveWorkerDiscovery(t *testing.T) {
	selection := attributes.Selection{
		attributes.Resource.Section: attributes.InclusionLists{Include: []string{"service.name"}},
	}
	reporter := &metricsReporter{
		serviceMap:          map[svc.UID]svc.Attrs{},
		pidsTracker:         otel.NewPidServiceTracker(),
		userAttribSelection: selection,
	}
	reporter.pythonRuntimeMetrics = newPythonRuntimeMetricsCollector(
		labelNamesTargetInfo(false, false, &reporter.nodeMeta, nil, selection),
		time.Now,
		time.Minute,
	)
	reporter.targetInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "test_python_worker_target_info"},
		labelNamesTargetInfo(false, false, &reporter.nodeMeta, nil, selection),
	)
	reporter.createEventMetrics = func(*svc.Attrs) {}
	reporter.deleteEventMetrics = reporter.deleteMetricsForService
	reporter.deleteEventMetricsPreservingHistograms = reporter.deleteMetricsForServicePreservingRuntimeHistograms

	registry := prometheus.NewRegistry()
	registry.MustRegister(reporter.pythonRuntimeMetrics.collectors()...)
	service := svc.Attrs{UID: svc.UID{Name: "workers"}}
	for _, pid := range []app.PID{101, 202} {
		reporter.handleProcessEvent(appexec.ProcessEvent{
			Type: appexec.ProcessEventCreated,
			File: appexec.New(appexec.Init{Pid: pid, Service: service}),
		}, slog.Default())
		if pid == 101 {
			snapshot := runtimemetrics.RuntimeMetricSnapshot{
				PID: pid, Service: service, Python: &runtimemetrics.PythonRuntimeMetricSnapshot{},
			}
			snapshot.Python.Generations[1].Collections = 11
			reporter.collectPythonRuntimeMetrics(snapshot)
		}
	}

	labels := map[string]string{"service_name": "workers", "cpython_gc_generation": "1"}
	metric := gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, labels)
	require.NotNil(t, metric)
	assert.InDelta(t, 11, metric.GetCounter().GetValue(), 0)
}

func TestPythonRuntimeWorkerGenerationUsesParentService(t *testing.T) {
	service := svc.Attrs{
		UID:         svc.UID{Name: "workers"},
		SDKLanguage: svc.InstrumentablePython,
	}
	reporter := &metricsReporter{
		serviceMap:  map[svc.UID]svc.Attrs{},
		pidsTracker: otel.NewPidServiceTracker(),
	}
	reporter.createEventMetrics = func(*svc.Attrs) {}
	reporter.deleteEventMetrics = func(*svc.Attrs) {}
	reporter.deleteEventMetricsPreservingHistograms = func(*svc.Attrs) {}
	parent := appexec.New(appexec.Init{Pid: 100, Service: service})
	workerLifecycle := func(generation uint64) *appexec.FileInfo {
		worker := appexec.New(appexec.Init{Pid: 101})
		worker.SetRuntimeMetricServiceSource(parent)
		worker.SetRuntimeMetricGeneration(worker.Pid(), generation)
		return worker
	}
	snapshot := func(generation uint64) runtimemetrics.RuntimeMetricSnapshot {
		return runtimemetrics.RuntimeMetricSnapshot{
			PID: 101, Service: service, Generation: generation,
			Python: &runtimemetrics.PythonRuntimeMetricSnapshot{},
		}
	}

	first := workerLifecycle(1)
	reporter.handleProcessEvent(appexec.ProcessEvent{Type: appexec.ProcessEventCreated, File: first}, slog.Default())
	assert.True(t, reporter.runtimeSnapshotProcessLive(snapshot(1)))
	reporter.handleProcessEvent(appexec.ProcessEvent{Type: appexec.ProcessEventTerminated, File: first}, slog.Default())
	assert.False(t, reporter.runtimeSnapshotProcessLive(snapshot(1)))

	second := workerLifecycle(2)
	reporter.handleProcessEvent(appexec.ProcessEvent{Type: appexec.ProcessEventCreated, File: second}, slog.Default())
	assert.False(t, reporter.runtimeSnapshotProcessLive(snapshot(1)))
	assert.True(t, reporter.runtimeSnapshotProcessLive(snapshot(2)))
}

func TestPythonRuntimeCountersDeleteStaleMetadataLabels(t *testing.T) {
	t.Run("same PID", func(t *testing.T) {
		testPythonRuntimeMetadataRefresh(t, 101)
	})
	t.Run("new worker PID", func(t *testing.T) {
		testPythonRuntimeMetadataRefresh(t, 202)
	})
}

func TestPythonRuntimeCountersDeleteStaleSnapshotLabels(t *testing.T) {
	selection := attributes.Selection{
		attributes.Resource.Section: attributes.InclusionLists{Include: []string{"service.name", "host.name"}},
	}
	reporter := &metricsReporter{userAttribSelection: selection}
	reporter.pythonRuntimeMetrics = newPythonRuntimeMetricsCollector(
		labelNamesTargetInfo(false, false, &reporter.nodeMeta, nil, selection),
		time.Now,
		time.Minute,
	)
	registry := prometheus.NewRegistry()
	registry.MustRegister(reporter.pythonRuntimeMetrics.collectors()...)

	snapshot := runtimemetrics.RuntimeMetricSnapshot{
		PID:     101,
		Service: svc.Attrs{UID: svc.UID{Name: "workers"}, HostName: "old-host"},
		Python:  &runtimemetrics.PythonRuntimeMetricSnapshot{},
	}
	snapshot.Python.Generations[1].Collections = 11
	reporter.collectPythonRuntimeMetrics(snapshot)

	oldLabels := map[string]string{
		"service_name": "workers", "host_name": "old-host", "cpython_gc_generation": "1",
	}
	require.NotNil(t, gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, oldLabels))

	snapshot.Removed = true
	snapshot.ServiceChanged = true
	reporter.collectPythonRuntimeMetrics(snapshot)
	assert.Nil(t, gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, oldLabels))
}

func TestPythonRuntimeDeleteMatchesExactBaseLabels(t *testing.T) {
	collector := newPythonRuntimeMetricsCollector([]string{"service_name"}, time.Now, time.Minute)
	registry := prometheus.NewRegistry()
	registry.MustRegister(collector.collectors()...)

	collector.addCounter(101, collector.collections, attributes.CPythonGCCollections.Prom, []string{"prod", "0"}, 10)
	collector.addCounter(202, collector.collections, attributes.CPythonGCCollections.Prom, []string{"production", "0"}, 20)

	collector.delete([]string{"prod"})
	assert.Nil(t, gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, map[string]string{
		"service_name": "prod", "cpython_gc_generation": "0",
	}))

	collector.addCounter(202, collector.collections, attributes.CPythonGCCollections.Prom, []string{"production", "0"}, 25)
	metric := gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, map[string]string{
		"service_name": "production", "cpython_gc_generation": "0",
	})
	require.NotNil(t, metric)
	assert.InDelta(t, 25, metric.GetCounter().GetValue(), 0)
}

func testPythonRuntimeMetadataRefresh(t *testing.T, eventPID app.PID) {
	selection := attributes.Selection{
		attributes.Resource.Section: attributes.InclusionLists{Include: []string{"service.name", "host.name"}},
	}
	labelNames := labelNamesTargetInfo(false, false, &meta.NodeMeta{}, nil, selection)
	reporter := &metricsReporter{
		serviceMap:          map[svc.UID]svc.Attrs{},
		pidsTracker:         otel.NewPidServiceTracker(),
		userAttribSelection: selection,
	}
	reporter.pythonRuntimeMetrics = newPythonRuntimeMetricsCollector(labelNames, time.Now, time.Minute)
	reporter.targetInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "test_python_metadata_target_info"},
		labelNames,
	)
	reporter.createEventMetrics = func(*svc.Attrs) {}
	reporter.deleteEventMetrics = reporter.deleteMetricsForService

	registry := prometheus.NewRegistry()
	registry.MustRegister(reporter.pythonRuntimeMetrics.collectors()...)
	uid := svc.UID{Name: "workers"}
	oldService := svc.Attrs{UID: uid, HostName: "old-host"}
	newService := svc.Attrs{UID: uid, HostName: "new-host"}
	pid := app.PID(101)
	reporter.handleProcessEvent(appexec.ProcessEvent{
		Type: appexec.ProcessEventCreated,
		File: appexec.New(appexec.Init{Pid: pid, Service: oldService}),
	}, slog.Default())
	snapshot := runtimemetrics.RuntimeMetricSnapshot{
		PID: pid, Service: oldService, Python: &runtimemetrics.PythonRuntimeMetricSnapshot{},
	}
	snapshot.Python.Generations[1].Collections = 11
	reporter.collectPythonRuntimeMetrics(snapshot)

	oldLabels := map[string]string{
		"service_name": "workers", "host_name": "old-host", "cpython_gc_generation": "1",
	}
	require.NotNil(t, gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, oldLabels))
	reporter.handleProcessEvent(appexec.ProcessEvent{
		Type: appexec.ProcessEventCreated,
		File: appexec.New(appexec.Init{Pid: eventPID, Service: newService}),
	}, slog.Default())
	assert.Nil(t, gatheredMetric(t, registry, attributes.CPythonGCCollections.Prom, oldLabels))
}
