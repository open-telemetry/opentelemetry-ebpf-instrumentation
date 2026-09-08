// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	metricdata "go.opentelemetry.io/otel/sdk/metric/metricdata"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	appruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestRuntimeMetricsReporterEvictsServiceAfterLastPIDTerminates(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "orders"}}
	constructed := 0
	evicted := []*RuntimeMetrics{}

	reporters, err := otelcfg.NewReporterPool[*svc.Attrs, *RuntimeMetrics](
		10,
		time.Minute,
		time.Now,
		func(_ svc.UID, metrics *RuntimeMetrics) {
			evicted = append(evicted, metrics)
		},
		func(_ *svc.Attrs) (*RuntimeMetrics, error) {
			constructed++
			return &RuntimeMetrics{}, nil
		},
	)
	require.NoError(t, err)

	reporter := RuntimeMetricsReporter{
		reporters:  reporters,
		pidTracker: NewPidServiceTracker(),
	}
	processEvent := func(pid app.PID, eventType exec.ProcessEventType) *exec.ProcessEvent {
		file := exec.New(exec.Init{Pid: pid, Service: service})
		file.SetRuntimeMetricGeneration(pid, uint64(pid))
		return &exec.ProcessEvent{
			Type: eventType,
			File: file,
		}
	}

	reporter.onProcessEvent(processEvent(101, exec.ProcessEventCreated))
	reporter.onProcessEvent(processEvent(202, exec.ProcessEventCreated))
	first, err := reporter.reporters.For(&service)
	require.NoError(t, err)
	first.jvmMetrics.runtimeEntries = map[jvmRuntimeEntryKey]*jvmRuntimeEntry{
		{pid: 101, generation: 101}: {},
		{pid: 202, generation: 202}: {},
	}

	reporter.onProcessEvent(processEvent(101, exec.ProcessEventTerminated))
	assert.NotContains(t, first.jvmMetrics.runtimeEntries, jvmRuntimeEntryKey{pid: 101, generation: 101})
	assert.Contains(t, first.jvmMetrics.runtimeEntries, jvmRuntimeEntryKey{pid: 202, generation: 202})
	current, err := reporter.reporters.For(&service)
	require.NoError(t, err)
	assert.Same(t, first, current)
	assert.Empty(t, evicted)

	reporter.onProcessEvent(processEvent(202, exec.ProcessEventTerminated))
	second, err := reporter.reporters.For(&service)
	require.NoError(t, err)

	assert.NotSame(t, first, second)
	assert.Equal(t, []*RuntimeMetrics{first}, evicted)
	assert.Equal(t, 2, constructed)
}

func TestRuntimeMetricsReporterRetainsFinalPythonMetricsAfterTermination(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })

	exportModes := services.NewExportModes()
	exportModes.AllowMetrics()
	service := svc.Attrs{
		UID:         svc.UID{Name: "orders"},
		SDKLanguage: svc.InstrumentablePython,
		Features:    export.FeatureApplicationRuntime,
		ExportModes: exportModes,
	}
	metrics := &RuntimeMetrics{ctx: t.Context(), service: &service, provider: provider}
	require.NoError(t, setupPythonRuntimeMeters(&metrics.pythonMetrics, provider.Meter(reporterName)))
	evicted := []*RuntimeMetrics{}
	reporters, err := otelcfg.NewReporterPool[*svc.Attrs, *RuntimeMetrics](
		10,
		time.Minute,
		time.Now,
		func(_ svc.UID, metrics *RuntimeMetrics) { evicted = append(evicted, metrics) },
		func(*svc.Attrs) (*RuntimeMetrics, error) { return metrics, nil },
	)
	require.NoError(t, err)

	reporter := RuntimeMetricsReporter{
		ctx:            t.Context(),
		reporters:      reporters,
		pidTracker:     NewPidServiceTracker(),
		log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		runtimeEnabled: runtimemetrics.Enabled{Runtime: true},
	}
	file := exec.New(exec.Init{Pid: 101, Service: service})
	file.SetRuntimeMetricGeneration(101, 1)
	reporter.onProcessEvent(&exec.ProcessEvent{Type: exec.ProcessEventCreated, File: file})
	first, err := reporter.reporters.For(&service)
	require.NoError(t, err)

	reporter.onProcessEvent(&exec.ProcessEvent{
		Type: exec.ProcessEventTerminated,
		File: file,
		FinalPythonRuntimeMetrics: []appruntime.PythonRuntimeMetricFinal{{
			PID:        101,
			Generation: 1,
			HasValue:   true,
			Generations: [3]appruntime.PythonGCGenerationMetrics{{
				Collections: 12,
			}},
		}},
	})

	current, exists := reporter.reporters.Lookup(service.UID)
	require.True(t, exists)
	assert.Same(t, first, current)
	assert.Empty(t, evicted)
	assertPythonRuntimePoint(t, reader, attributes.CPythonGCCollections.OTEL, 0, 12)
}

func TestRuntimeMetricsReporterTracksInheritedChildPIDHistograms(t *testing.T) {
	service := svc.Attrs{
		UID:         svc.UID{Name: "orders"},
		ProcPID:     42,
		SDKLanguage: svc.InstrumentableGolang,
	}
	var metrics *RuntimeMetrics
	reporters, err := otelcfg.NewReporterPool[*svc.Attrs, *RuntimeMetrics](
		10,
		time.Minute,
		time.Now,
		func(_ svc.UID, _ *RuntimeMetrics) {},
		func(*svc.Attrs) (*RuntimeMetrics, error) {
			metrics = &RuntimeMetrics{
				goHistogramProducer: newGoRuntimeHistogramProducer(metricdata.CumulativeTemporality),
			}
			return metrics, nil
		},
	)
	require.NoError(t, err)

	reporter := RuntimeMetricsReporter{
		ctx:            t.Context(),
		reporters:      reporters,
		pidTracker:     NewPidServiceTracker(),
		log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		runtimeEnabled: runtimemetrics.Enabled{Runtime: true},
	}
	processEvent := func(pid app.PID, eventType exec.ProcessEventType) *exec.ProcessEvent {
		return &exec.ProcessEvent{
			Type: eventType,
			File: exec.New(exec.Init{Pid: pid, Service: service}),
		}
	}
	snapshot := func(pid app.PID, population uint64) runtimemetrics.RuntimeMetricSnapshot {
		counts := testGoRuntimeHistogramCounts()
		counts[0] = population
		value := testGoRuntimeHistogramSnapshot(
			runtimemetrics.GoHistogramKindGCPause,
			pid,
			time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC),
			counts,
			0,
			0,
		)
		value.Service = service
		return value
	}

	reporter.onProcessEvent(processEvent(service.ProcPID, exec.ProcessEventCreated))
	reporter.onProcessEvent(processEvent(101, exec.ProcessEventCreated))
	reporter.onProcessEvent(processEvent(202, exec.ProcessEventCreated))
	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{
		snapshot(101, 2),
		snapshot(202, 3),
	})
	require.NotNil(t, metrics)
	assert.Equal(t, uint64(5), testProducedHistogramPoint(
		t,
		metrics.goHistogramProducer,
		attributes.GoRuntimeMemoryGCPauseDuration.OTEL,
	).Count)

	reporter.onProcessEvent(processEvent(101, exec.ProcessEventTerminated))
	assert.Equal(t, uint64(5), testProducedHistogramPoint(
		t,
		metrics.goHistogramProducer,
		attributes.GoRuntimeMemoryGCPauseDuration.OTEL,
	).Count)

	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{snapshot(202, 4)})
	assert.Equal(t, uint64(6), testProducedHistogramPoint(
		t,
		metrics.goHistogramProducer,
		attributes.GoRuntimeMemoryGCPauseDuration.OTEL,
	).Count)

	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{snapshot(101, 7)})
	assert.Equal(t, uint64(6), testProducedHistogramPoint(
		t,
		metrics.goHistogramProducer,
		attributes.GoRuntimeMemoryGCPauseDuration.OTEL,
	).Count)
}

func TestRuntimeMetricsReporterAcceptsSnapshotsBeforeCreationAndSkipsAfterTermination(t *testing.T) {
	service := svc.Attrs{
		UID:         svc.UID{Name: "orders"},
		ProcPID:     101,
		SDKLanguage: svc.InstrumentableGolang,
	}
	constructed := 0

	reporters, err := otelcfg.NewReporterPool[*svc.Attrs, *RuntimeMetrics](
		10,
		time.Minute,
		time.Now,
		func(_ svc.UID, _ *RuntimeMetrics) {},
		func(_ *svc.Attrs) (*RuntimeMetrics, error) {
			constructed++
			return &RuntimeMetrics{}, nil
		},
	)
	require.NoError(t, err)

	reporter := RuntimeMetricsReporter{
		reporters:      reporters,
		pidTracker:     NewPidServiceTracker(),
		log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		runtimeEnabled: runtimemetrics.Enabled{Runtime: true},
	}
	processEvent := func(eventType exec.ProcessEventType, generation uint64) *exec.ProcessEvent {
		file := exec.New(exec.Init{Pid: 101, Service: service})
		file.SetRuntimeMetricGeneration(101, generation)
		return &exec.ProcessEvent{
			Type: eventType,
			File: file,
		}
	}
	snapshots := []runtimemetrics.RuntimeMetricSnapshot{{
		PID:        101,
		Service:    service,
		Generation: 1,
		Go:         &runtimemetrics.GoRuntimeMetricSnapshot{},
	}}

	reporter.reportRuntimeMetrics(snapshots)
	assert.Equal(t, 1, constructed)

	reporter.onProcessEvent(processEvent(exec.ProcessEventCreated, 1))
	reporter.reportRuntimeMetrics(snapshots)
	assert.Equal(t, 1, constructed)

	reporter.onProcessEvent(processEvent(exec.ProcessEventTerminated, 1))
	reporter.reportRuntimeMetrics(snapshots)
	assert.Equal(t, 1, constructed,
		"in-flight snapshot must not resurrect the removed reporter")

	reusedPIDSnapshot := snapshots[0]
	reusedPIDSnapshot.Generation = 2
	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{reusedPIDSnapshot})
	assert.Equal(t, 2, constructed,
		"a reused PID generation must be accepted before its creation event")
}

func TestRuntimeMetricsReporterTracksWorkerGenerationWithParentService(t *testing.T) {
	service := svc.Attrs{
		UID:         svc.UID{Name: "workers"},
		SDKLanguage: svc.InstrumentablePython,
	}
	reporters, err := otelcfg.NewReporterPool[*svc.Attrs, *RuntimeMetrics](
		10,
		time.Minute,
		time.Now,
		func(svc.UID, *RuntimeMetrics) {},
		func(service *svc.Attrs) (*RuntimeMetrics, error) { return &RuntimeMetrics{service: service}, nil },
	)
	require.NoError(t, err)
	reporter := RuntimeMetricsReporter{
		reporters:  reporters,
		pidTracker: NewPidServiceTracker(),
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	parent := exec.New(exec.Init{Pid: 100, Service: service})
	workerLifecycle := func(generation uint64) *exec.FileInfo {
		worker := exec.New(exec.Init{Pid: 101})
		worker.SetRuntimeMetricServiceSource(parent)
		worker.SetRuntimeMetricGeneration(worker.Pid(), generation)
		return worker
	}
	snapshot := func(generation uint64) runtimemetrics.RuntimeMetricSnapshot {
		workerService := service
		workerService.ProcPID = 101
		return runtimemetrics.RuntimeMetricSnapshot{
			PID: 101, Service: workerService, Generation: generation,
			Python: &runtimemetrics.PythonRuntimeMetricSnapshot{},
		}
	}

	first := workerLifecycle(1)
	reporter.onProcessEvent(&exec.ProcessEvent{Type: exec.ProcessEventCreated, File: first})
	assert.True(t, reporter.snapshotProcessLive(snapshot(1)))
	reporter.onProcessEvent(&exec.ProcessEvent{Type: exec.ProcessEventTerminated, File: first})
	assert.False(t, reporter.snapshotProcessLive(snapshot(1)))

	second := workerLifecycle(2)
	reporter.onProcessEvent(&exec.ProcessEvent{Type: exec.ProcessEventCreated, File: second})
	assert.False(t, reporter.snapshotProcessLive(snapshot(1)))
	assert.True(t, reporter.snapshotProcessLive(snapshot(2)))
}

func TestRuntimeMetricsReporterProcessesPythonRemovalAfterTermination(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })

	exportModes := services.NewExportModes()
	exportModes.AllowMetrics()
	service := svc.Attrs{
		UID:         svc.UID{Name: "orders"},
		SDKLanguage: svc.InstrumentablePython,
		Features:    export.FeatureApplicationRuntime,
		ExportModes: exportModes,
	}
	metrics := &RuntimeMetrics{ctx: t.Context(), service: &service, provider: provider}
	require.NoError(t, setupPythonRuntimeMeters(&metrics.pythonMetrics, provider.Meter(reporterName)))

	reporters, err := otelcfg.NewReporterPool[*svc.Attrs, *RuntimeMetrics](
		10,
		time.Minute,
		time.Now,
		func(svc.UID, *RuntimeMetrics) {},
		func(*svc.Attrs) (*RuntimeMetrics, error) { return metrics, nil },
	)
	require.NoError(t, err)
	reporter := RuntimeMetricsReporter{
		ctx:            t.Context(),
		reporters:      reporters,
		pidTracker:     NewPidServiceTracker(),
		log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		runtimeEnabled: runtimemetrics.Enabled{Runtime: true},
	}
	processEvent := func(pid app.PID, eventType exec.ProcessEventType) *exec.ProcessEvent {
		file := exec.New(exec.Init{Pid: pid, Service: service})
		file.SetRuntimeMetricGeneration(pid, 1)
		return &exec.ProcessEvent{Type: eventType, File: file}
	}
	snapshot := func(pid app.PID, collections uint64) runtimemetrics.RuntimeMetricSnapshot {
		pidService := service
		pidService.ProcPID = pid
		return runtimemetrics.RuntimeMetricSnapshot{
			Service:    pidService,
			PID:        pid,
			Generation: 1,
			Python: &runtimemetrics.PythonRuntimeMetricSnapshot{
				Generations: [3]runtimemetrics.PythonGCGenerationMetrics{{Collections: collections}},
			},
		}
	}

	reporter.onProcessEvent(processEvent(101, exec.ProcessEventCreated))
	reporter.onProcessEvent(processEvent(202, exec.ProcessEventCreated))
	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{
		snapshot(101, 11),
		snapshot(202, 22),
	})
	require.Len(t, metrics.pythonMetrics.values, 2)

	reporter.onProcessEvent(processEvent(101, exec.ProcessEventTerminated))
	tombstone := snapshot(101, 0)
	tombstone.Generation = 0
	tombstone.Removed = true
	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{tombstone})

	require.Len(t, metrics.pythonMetrics.values, 1)
	assert.NotContains(t, metrics.pythonMetrics.values, app.PID(101))
	assert.Contains(t, metrics.pythonMetrics.values, app.PID(202))
	assertPythonRuntimePoint(t, reader, attributes.CPythonGCCollections.OTEL, 0, 33)
}

func TestRuntimeMetricsReporterEvictsReporterAfterServiceAttributesChange(t *testing.T) {
	exportModes := services.NewExportModes()
	exportModes.AllowMetrics()
	oldService := svc.Attrs{
		UID:         svc.UID{Name: "orders"},
		HostName:    "old-host",
		SDKLanguage: svc.InstrumentablePython,
		Features:    export.FeatureApplicationRuntime,
		ExportModes: exportModes,
	}
	evicted := []*RuntimeMetrics{}
	reporters, err := otelcfg.NewReporterPool[*svc.Attrs, *RuntimeMetrics](
		10,
		time.Minute,
		time.Now,
		func(_ svc.UID, metrics *RuntimeMetrics) { evicted = append(evicted, metrics) },
		func(service *svc.Attrs) (*RuntimeMetrics, error) { return &RuntimeMetrics{service: service}, nil },
	)
	require.NoError(t, err)
	reporter := RuntimeMetricsReporter{
		reporters:      reporters,
		pidTracker:     NewPidServiceTracker(),
		log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		runtimeEnabled: runtimemetrics.Enabled{Runtime: true},
	}

	file := exec.New(exec.Init{Pid: 101, Service: oldService})
	reporter.onProcessEvent(&exec.ProcessEvent{Type: exec.ProcessEventCreated, File: file})
	oldMetrics, err := reporter.reporters.For(&oldService)
	require.NoError(t, err)

	file.SetHostName("new-host")
	reporter.onProcessEvent(&exec.ProcessEvent{Type: exec.ProcessEventCreated, File: file})

	assert.Equal(t, []*RuntimeMetrics{oldMetrics}, evicted)
	_, exists := reporter.reporters.Lookup(oldService.UID)
	assert.False(t, exists)
}

func TestRuntimeMetricsReporterShouldReportSnapshot(t *testing.T) {
	exportMetrics := services.NewExportModes()
	exportMetrics.AllowMetrics()
	blockMetrics := services.NewExportModes()

	reporter := &RuntimeMetricsReporter{
		runtimeEnabled: runtimemetrics.Enabled{Runtime: true},
	}

	require.True(t, reporter.shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableGolang},
		Go:      &runtimemetrics.GoRuntimeMetricSnapshot{},
	}))
	require.True(t, reporter.shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{
			Features:    export.FeatureApplicationRuntime,
			ExportModes: exportMetrics,
		},
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{Kind: appruntime.JVMMetricMemoryUsed},
	}))

	assert.False(t, (&RuntimeMetricsReporter{runtimeEnabled: runtimemetrics.Enabled{Runtime: false}}).shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableGolang},
		Go:      &runtimemetrics.GoRuntimeMetricSnapshot{},
	}))
	assert.False(t, reporter.shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava},
		Go:      &runtimemetrics.GoRuntimeMetricSnapshot{},
	}))
	assert.False(t, (&RuntimeMetricsReporter{runtimeEnabled: runtimemetrics.Enabled{Runtime: false}}).shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{
			Features:    export.FeatureApplicationRuntime,
			ExportModes: exportMetrics,
		},
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{},
	}))
	assert.False(t, reporter.shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{
			Features:    export.FeatureApplicationRED,
			ExportModes: exportMetrics,
		},
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{},
	}))
	assert.False(t, reporter.shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{
			Features:    export.FeatureApplicationRuntime,
			ExportModes: blockMetrics,
		},
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{},
	}))
	assert.False(t, reporter.shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{}))
}

func TestSetupRuntimeMetersUsesSharedRuntimeGate(t *testing.T) {
	provider := metric.NewMeterProvider()
	defer func() {
		require.NoError(t, provider.Shutdown(t.Context()))
	}()
	meter := provider.Meter(reporterName)

	disabled := RuntimeMetrics{ctx: t.Context()}
	require.NoError(t, setupRuntimeMeters(&disabled, meter, time.Minute, runtimemetrics.Enabled{}, export.DefaultBuckets))
	assert.Nil(t, disabled.goMetrics.memoryLimit)
	assert.Nil(t, disabled.jvmMetrics.memoryUsed)

	enabled := RuntimeMetrics{ctx: t.Context()}
	require.NoError(t, setupRuntimeMeters(&enabled, meter, time.Minute, runtimemetrics.Enabled{Runtime: true}, export.DefaultBuckets))
	assert.NotNil(t, enabled.goMetrics.memoryLimit)
	assert.NotNil(t, enabled.jvmMetrics.memoryUsed)
	assert.NotNil(t, enabled.pythonMetrics.collections)
}

func TestPythonRuntimeCountersByGeneration(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })

	var metrics pythonRuntimeMetrics
	require.NoError(t, setupPythonRuntimeMeters(&metrics, provider.Meter(reporterName)))

	snapshot := runtimemetrics.RuntimeMetricSnapshot{PID: 123, Python: &runtimemetrics.PythonRuntimeMetricSnapshot{
		Generations: [3]runtimemetrics.PythonGCGenerationMetrics{
			{Collections: 10, CollectedObjects: 20, UncollectableObjects: 1},
			{Collections: 11, CollectedObjects: 21, UncollectableObjects: 2},
			{Collections: 12, CollectedObjects: 22, UncollectableObjects: 3},
		},
	}}
	recordPythonRuntimeMetrics(t.Context(), &metrics, snapshot)

	collections := collectPythonRuntimePoints(t, reader, attributes.CPythonGCCollections.OTEL)
	require.Len(t, collections, 3)
	assert.Equal(t, int64(10), collections[0])
	assert.Equal(t, int64(11), collections[1])
	assert.Equal(t, int64(12), collections[2])

	snapshot.Python.Generations[0].Collections = 15
	recordPythonRuntimeMetrics(t.Context(), &metrics, snapshot)
	collections = collectPythonRuntimePoints(t, reader, attributes.CPythonGCCollections.OTEL)
	assert.Equal(t, int64(15), collections[0])
	assert.Equal(t, int64(11), collections[1])

	snapshot.Python.Generations[0].Collections = 4
	recordPythonRuntimeMetrics(t.Context(), &metrics, snapshot)
	collections = collectPythonRuntimePoints(t, reader, attributes.CPythonGCCollections.OTEL)
	assert.Equal(t, int64(19), collections[0])

	snapshot.Removed = true
	recordPythonRuntimeMetrics(t.Context(), &metrics, snapshot)
	assert.Equal(t, collections, collectPythonRuntimePoints(t, reader, attributes.CPythonGCCollections.OTEL))
}

func TestPythonRuntimeCountersAggregatePerPIDBaselines(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })

	var metrics pythonRuntimeMetrics
	require.NoError(t, setupPythonRuntimeMeters(&metrics, provider.Meter(reporterName)))

	first := runtimemetrics.RuntimeMetricSnapshot{PID: 101, Python: &runtimemetrics.PythonRuntimeMetricSnapshot{}}
	first.Python.Generations[1].Collections = 11
	second := runtimemetrics.RuntimeMetricSnapshot{PID: 202, Python: &runtimemetrics.PythonRuntimeMetricSnapshot{}}
	second.Python.Generations[1].Collections = 21
	recordPythonRuntimeMetrics(t.Context(), &metrics, first)
	recordPythonRuntimeMetrics(t.Context(), &metrics, second)

	assertPythonRuntimePoint(t, reader, attributes.CPythonGCCollections.OTEL, 1, 32)

	first.Python.Generations[1].Collections = 14
	recordPythonRuntimeMetrics(t.Context(), &metrics, first)
	assertPythonRuntimePoint(t, reader, attributes.CPythonGCCollections.OTEL, 1, 35)

	first.Removed = true
	recordPythonRuntimeMetrics(t.Context(), &metrics, first)
	assert.Len(t, metrics.values, 1)
	assertPythonRuntimePoint(t, reader, attributes.CPythonGCCollections.OTEL, 1, 35)
	second.Removed = true
	recordPythonRuntimeMetrics(t.Context(), &metrics, second)
	assert.Empty(t, metrics.values)
	assertPythonRuntimePoint(t, reader, attributes.CPythonGCCollections.OTEL, 1, 35)
}

func assertPythonRuntimePoint(
	t *testing.T,
	reader *metric.ManualReader,
	name string,
	generation int64,
	want int64,
) {
	t.Helper()
	value, ok := pythonRuntimePoint(t, reader, name, generation)
	require.True(t, ok)
	assert.Equal(t, want, value)
}

func pythonRuntimePoint(
	t *testing.T,
	reader *metric.ManualReader,
	name string,
	generation int64,
) (int64, bool) {
	t.Helper()
	collected := collectGoRuntimeInt64Metric(t, reader, name)
	if collected.Name == "" {
		return 0, false
	}
	sum, ok := collected.Data.(metricdata.Sum[int64])
	require.True(t, ok)
	for _, point := range sum.DataPoints {
		_, hasPID := point.Attributes.Value(attribute.Key("process.pid"))
		require.False(t, hasPID)
		pointGeneration, hasGeneration := point.Attributes.Value(attribute.Key("cpython.gc.generation"))
		if hasGeneration && pointGeneration.AsInt64() == generation {
			return point.Value, true
		}
	}
	return 0, false
}

func collectPythonRuntimePoints(t *testing.T, reader *metric.ManualReader, name string) map[int]int64 {
	t.Helper()

	collected := collectGoRuntimeInt64Metric(t, reader, name)
	if collected.Name == "" {
		return nil
	}
	sum, ok := collected.Data.(metricdata.Sum[int64])
	require.True(t, ok)

	points := make(map[int]int64, len(sum.DataPoints))
	for _, point := range sum.DataPoints {
		generation, ok := point.Attributes.Value(attribute.Key("cpython.gc.generation"))
		require.True(t, ok)
		points[int(generation.AsInt64())] = point.Value
	}
	return points
}

func TestGoRuntimeCPUTimeCounterDeltaResetAndRemoval(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() {
		require.NoError(t, provider.Shutdown(t.Context()))
	})

	var metrics goRuntimeMetrics
	require.NoError(t, setupGoRuntimeMeters(&metrics, provider.Meter(reporterName)))

	cpu := &runtimemetrics.GoRuntimeCPUTimeSnapshot{UserTime: 100}
	recordGoRuntimeCPUTime(t.Context(), &metrics, cpu)
	points := collectGoRuntimeCPUTimePoints(t, reader)
	user := points[goCPUTimePointKey{state: "user"}]
	assert.InDelta(t, float64(100*time.Nanosecond)/float64(time.Second), user.Value, 1e-12)
	assert.False(t, user.Attributes.HasValue(semconv.GoCPUDetailedStateKey))
	gcAssist := points[goCPUTimePointKey{state: "gc", detailedState: "gc/mark/assist"}]
	assert.True(t, gcAssist.Attributes.HasValue(semconv.GoCPUDetailedStateKey))

	cpu.UserTime = 250
	recordGoRuntimeCPUTime(t.Context(), &metrics, cpu)
	points = collectGoRuntimeCPUTimePoints(t, reader)
	assert.InDelta(t, float64(250*time.Nanosecond)/float64(time.Second),
		points[goCPUTimePointKey{state: "user"}].Value, 1e-12)

	cpu.UserTime = 50
	recordGoRuntimeCPUTime(t.Context(), &metrics, cpu)
	points = collectGoRuntimeCPUTimePoints(t, reader)
	assert.InDelta(t, float64(50*time.Nanosecond)/float64(time.Second),
		points[goCPUTimePointKey{state: "user"}].Value, 1e-12)

	recordGoRuntimeCPUTime(t.Context(), &metrics, nil)
	assert.Empty(t, collectGoRuntimeCPUTimePoints(t, reader))
	assert.Empty(t, metrics.cpuTimeValues)
}

func TestGoRuntimeMemoryMetricsDeltaResetAndRemoval(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() {
		require.NoError(t, provider.Shutdown(t.Context()))
	})

	var metrics goRuntimeMetrics
	require.NoError(t, setupGoRuntimeMeters(&metrics, provider.Meter(reporterName)))
	assertMemoryUsed := func(wantStack, wantOther int64) {
		used := collectGoRuntimeInt64Points(t, reader, attributes.GoRuntimeMemoryUsed.OTEL)
		require.Len(t, used, 2)
		usedByType := map[string]int64{}
		for _, point := range used {
			memoryType, ok := point.Attributes.Value(semconv.GoMemoryTypeKey)
			require.True(t, ok)
			usedByType[memoryType.AsString()] = point.Value
		}
		assert.Equal(t, wantStack, usedByType["stack"])
		assert.Equal(t, wantOther, usedByType["other"])
	}

	stack := int64(100)
	other := int64(200)
	allocated := uint64(1000)
	allocations := uint64(10)
	recordGoRuntimeMetrics(t.Context(), &metrics, runtimemetrics.RuntimeMetricSnapshot{
		Go: &runtimemetrics.GoRuntimeMetricSnapshot{
			MemoryUsedStack:   &stack,
			MemoryUsedOther:   &other,
			MemoryAllocated:   &allocated,
			MemoryAllocations: &allocations,
		},
	})

	assertMemoryUsed(100, 200)
	assert.Equal(t, int64(1000), collectSingleGoRuntimeInt64Value(t, reader, attributes.GoRuntimeMemoryAllocated.OTEL))
	assert.Equal(t, int64(10), collectSingleGoRuntimeInt64Value(t, reader, attributes.GoRuntimeMemoryAllocations.OTEL))

	stack = 50
	other = 250
	changedMemoryUsed := runtimemetrics.RuntimeMetricSnapshot{
		Go: &runtimemetrics.GoRuntimeMetricSnapshot{
			MemoryUsedStack: &stack,
			MemoryUsedOther: &other,
		},
	}
	recordGoRuntimeMetrics(t.Context(), &metrics, changedMemoryUsed)
	assertMemoryUsed(50, 250)

	recordGoRuntimeMetrics(t.Context(), &metrics, changedMemoryUsed)
	assertMemoryUsed(50, 250)

	allocated = 50
	allocations = 2
	recordGoRuntimeMetrics(t.Context(), &metrics, runtimemetrics.RuntimeMetricSnapshot{
		Go: &runtimemetrics.GoRuntimeMetricSnapshot{
			MemoryAllocated:   &allocated,
			MemoryAllocations: &allocations,
		},
	})
	assert.Equal(t, int64(50), collectSingleGoRuntimeInt64Value(t, reader, attributes.GoRuntimeMemoryAllocated.OTEL))
	assert.Equal(t, int64(2), collectSingleGoRuntimeInt64Value(t, reader, attributes.GoRuntimeMemoryAllocations.OTEL))
	assert.Empty(t, collectGoRuntimeInt64Points(t, reader, attributes.GoRuntimeMemoryUsed.OTEL))

	recordGoRuntimeMetrics(t.Context(), &metrics, runtimemetrics.RuntimeMetricSnapshot{
		Go: &runtimemetrics.GoRuntimeMetricSnapshot{},
	})
	assert.Empty(t, collectGoRuntimeInt64Points(t, reader, attributes.GoRuntimeMemoryAllocated.OTEL))
	assert.Empty(t, collectGoRuntimeInt64Points(t, reader, attributes.GoRuntimeMemoryAllocations.OTEL))
}

func TestGoRuntimeGoroutineCountCurrentValueAndRemoval(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() {
		require.NoError(t, provider.Shutdown(t.Context()))
	})

	var metrics goRuntimeMetrics
	require.NoError(t, setupGoRuntimeMeters(&metrics, provider.Meter(reporterName)))
	require.NotNil(t, metrics.goroutineCount)

	for _, value := range []int64{10, 15, 3} {
		recordGoRuntimeMetrics(t.Context(), &metrics, runtimemetrics.RuntimeMetricSnapshot{
			Go: &runtimemetrics.GoRuntimeMetricSnapshot{GoroutineCount: &value},
		})
		assert.Equal(t, "{goroutine}", collectGoRuntimeInt64Metric(
			t, reader, attributes.GoRuntimeGoroutineCount.OTEL,
		).Unit)
		assert.Equal(t, value, collectSingleGoRuntimeInt64Value(
			t, reader, attributes.GoRuntimeGoroutineCount.OTEL,
		))
	}

	recordGoRuntimeMetrics(t.Context(), &metrics, runtimemetrics.RuntimeMetricSnapshot{
		Go: &runtimemetrics.GoRuntimeMetricSnapshot{},
	})
	assert.Empty(t, collectGoRuntimeInt64Points(t, reader, attributes.GoRuntimeGoroutineCount.OTEL))
}

func TestGoRuntimeMemoryGCGoalCurrentValueAndRemoval(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })

	var metrics goRuntimeMetrics
	require.NoError(t, setupGoRuntimeMeters(&metrics, provider.Meter(reporterName)))
	require.NotNil(t, metrics.memoryGCGoal)

	for _, value := range []int64{1024, 4096, 2048} {
		recordGoRuntimeMetrics(t.Context(), &metrics, runtimemetrics.RuntimeMetricSnapshot{
			Go: &runtimemetrics.GoRuntimeMetricSnapshot{MemoryGCGoal: &value},
		})
		assert.Equal(t, "By", collectGoRuntimeInt64Metric(
			t, reader, attributes.GoRuntimeMemoryGCGoal.OTEL,
		).Unit)
		assert.Equal(t, value, collectSingleGoRuntimeInt64Value(
			t, reader, attributes.GoRuntimeMemoryGCGoal.OTEL,
		))
	}

	recordGoRuntimeMetrics(t.Context(), &metrics, runtimemetrics.RuntimeMetricSnapshot{
		Go: &runtimemetrics.GoRuntimeMetricSnapshot{},
	})
	assert.Empty(t, collectGoRuntimeInt64Points(t, reader, attributes.GoRuntimeMemoryGCGoal.OTEL))
}

type goCPUTimePointKey struct {
	state         string
	detailedState string
}

func collectGoRuntimeCPUTimePoints(
	t *testing.T,
	reader *metric.ManualReader,
) map[goCPUTimePointKey]metricdata.DataPoint[float64] {
	t.Helper()

	var resourceMetrics metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &resourceMetrics))

	points := map[goCPUTimePointKey]metricdata.DataPoint[float64]{}
	for _, scopeMetrics := range resourceMetrics.ScopeMetrics {
		for _, collected := range scopeMetrics.Metrics {
			if collected.Name != attributes.GoRuntimeCPUTime.OTEL {
				continue
			}

			sum, ok := collected.Data.(metricdata.Sum[float64])
			require.True(t, ok)
			for _, point := range sum.DataPoints {
				state, ok := point.Attributes.Value(semconv.GoCPUStateKey)
				require.True(t, ok)
				key := goCPUTimePointKey{state: state.AsString()}
				if detailedState, ok := point.Attributes.Value(semconv.GoCPUDetailedStateKey); ok {
					key.detailedState = detailedState.AsString()
				}
				points[key] = point
			}
		}
	}

	return points
}

func collectSingleGoRuntimeInt64Value(t *testing.T, reader *metric.ManualReader, name string) int64 {
	t.Helper()

	points := collectGoRuntimeInt64Points(t, reader, name)
	require.Len(t, points, 1)
	return points[0].Value
}

func collectGoRuntimeInt64Points(
	t *testing.T,
	reader *metric.ManualReader,
	name string,
) []metricdata.DataPoint[int64] {
	t.Helper()

	metric := collectGoRuntimeInt64Metric(t, reader, name)
	if metric.Name == "" {
		return nil
	}
	sum, ok := metric.Data.(metricdata.Sum[int64])
	require.True(t, ok)
	return sum.DataPoints
}

func collectGoRuntimeInt64Metric(
	t *testing.T,
	reader *metric.ManualReader,
	name string,
) metricdata.Metrics {
	t.Helper()

	var resourceMetrics metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &resourceMetrics))

	for _, scopeMetrics := range resourceMetrics.ScopeMetrics {
		for _, collected := range scopeMetrics.Metrics {
			if collected.Name != name {
				continue
			}
			return collected
		}
	}

	return metricdata.Metrics{}
}
