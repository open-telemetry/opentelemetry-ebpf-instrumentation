// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"log/slog"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
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

const testPromRuntimeHistogramPopulationCount = 160

func TestGoRuntimeHistogramCollectorExportsExactMetrics(t *testing.T) {
	collector := newGoRuntimeHistogramCollector([]string{"service_name", "service_namespace"})
	registry := prometheus.NewRegistry()
	registry.MustRegister(collector)

	gcCounts := testPromRuntimeHistogramCounts()
	gcCounts[0] = 2
	gcCounts[12] = 3
	gcCounts[len(gcCounts)-1] = 4
	gcSnapshot := runtimemetrics.GoRuntimeHistogramSnapshot{
		Kind:      runtimemetrics.GoHistogramKindGCPause,
		Counts:    gcCounts,
		Underflow: 1,
		Overflow:  5,
	}
	scheduleCounts := testPromRuntimeHistogramCounts()
	scheduleCounts[5] = 7
	scheduleSnapshot := runtimemetrics.GoRuntimeHistogramSnapshot{
		Kind:      runtimemetrics.GoHistogramKindSchedLatency,
		Counts:    scheduleCounts,
		Underflow: 2,
	}
	labels := []string{"orders", "production"}
	collector.Update(101, labels, &gcSnapshot)
	collector.Update(101, labels, &scheduleSnapshot)

	gcMetric := gatheredMetric(t, registry, "go_memory_gc_pause_duration_seconds", map[string]string{
		"service_name":      "orders",
		"service_namespace": "production",
	})
	require.NotNil(t, gcMetric)
	gcHistogram := gcMetric.GetHistogram()
	require.NotNil(t, gcHistogram)
	require.Equal(t, uint64(15), gcHistogram.GetSampleCount())
	data, err := gcSnapshot.Data()
	require.NoError(t, err)
	assert.InDelta(t, data.Sum, gcHistogram.GetSampleSum(), 0)

	buckets := gcHistogram.GetBucket()
	require.Len(t, buckets, 161)
	assert.InDelta(t, math.Nextafter(0, math.Inf(-1)), buckets[0].GetUpperBound(), 0)
	assert.InDelta(t, math.Nextafter(64e-9, 0), buckets[1].GetUpperBound(), 0)
	assert.InDelta(t, math.Nextafter(1280e-9, 1024e-9), buckets[13].GetUpperBound(), 0)
	assert.InDelta(
		t,
		math.Nextafter(
			float64(uint64(1)<<47)/1e9,
			float64((uint64(1)<<46)|(uint64(3)<<44))/1e9,
		),
		buckets[160].GetUpperBound(),
		0,
	)
	var cumulative uint64
	for i, bucket := range buckets {
		assert.InDelta(t, data.Bounds[i], bucket.GetUpperBound(), 0, "bucket %d upper bound", i)
		cumulative += data.BucketCounts[i]
		assert.Equal(t, cumulative, bucket.GetCumulativeCount(), "bucket %d cumulative count", i)
	}
	assert.Equal(t, uint64(15), gcHistogram.GetSampleCount(), "implicit +Inf bucket must include overflow")

	scheduleMetric := gatheredMetric(t, registry, "go_schedule_duration_seconds", map[string]string{
		"service_name":      "orders",
		"service_namespace": "production",
	})
	require.NotNil(t, scheduleMetric)
	scheduleHistogram := scheduleMetric.GetHistogram()
	require.NotNil(t, scheduleHistogram)
	assert.Equal(t, uint64(9), scheduleHistogram.GetSampleCount())
	scheduleData, err := scheduleSnapshot.Data()
	require.NoError(t, err)
	assert.InDelta(t, scheduleData.Sum, scheduleHistogram.GetSampleSum(), 0)
}

func TestGoRuntimeHistogramCollectorPreservesCumulativeStateAfterPIDDeletion(t *testing.T) {
	collector := newGoRuntimeHistogramCollector([]string{"service_name"})
	registry := prometheus.NewRegistry()
	registry.MustRegister(collector)
	labels := []string{"orders"}

	firstCounts := testPromRuntimeHistogramCounts()
	firstCounts[0] = 2
	collector.Update(101, labels, &runtimemetrics.GoRuntimeHistogramSnapshot{
		Kind:   runtimemetrics.GoHistogramKindGCPause,
		Counts: firstCounts,
	})
	secondCounts := testPromRuntimeHistogramCounts()
	secondCounts[0] = 3
	collector.Update(202, labels, &runtimemetrics.GoRuntimeHistogramSnapshot{
		Kind:   runtimemetrics.GoHistogramKindGCPause,
		Counts: secondCounts,
	})

	metric := gatheredMetric(t, registry, attributes.GoRuntimeMemoryGCPauseDuration.Prom, map[string]string{
		"service_name": "orders",
	})
	require.NotNil(t, metric)
	histogram := metric.GetHistogram()
	require.NotNil(t, histogram)
	assert.Equal(t, uint64(5), histogram.GetSampleCount())

	collector.DeletePID(101)
	metric = gatheredMetric(t, registry, attributes.GoRuntimeMemoryGCPauseDuration.Prom, map[string]string{
		"service_name": "orders",
	})
	require.NotNil(t, metric)
	histogram = metric.GetHistogram()
	require.NotNil(t, histogram)
	assert.Equal(t, uint64(5), histogram.GetSampleCount())
	require.NotEmpty(t, histogram.GetBucket())
	assert.Equal(t, uint64(5), histogram.GetBucket()[len(histogram.GetBucket())-1].GetCumulativeCount())

	secondCounts[0] = 4
	collector.Update(202, labels, &runtimemetrics.GoRuntimeHistogramSnapshot{
		Kind:   runtimemetrics.GoHistogramKindGCPause,
		Counts: secondCounts,
	})
	metric = gatheredMetric(t, registry, attributes.GoRuntimeMemoryGCPauseDuration.Prom, map[string]string{
		"service_name": "orders",
	})
	require.NotNil(t, metric)
	histogram = metric.GetHistogram()
	require.NotNil(t, histogram)
	assert.Equal(t, uint64(6), histogram.GetSampleCount())
	require.NotEmpty(t, histogram.GetBucket())
	assert.Equal(t, uint64(6), histogram.GetBucket()[len(histogram.GetBucket())-1].GetCumulativeCount())

	collector.Delete(labels)
	assert.Nil(t, gatheredMetric(t, registry, attributes.GoRuntimeMemoryGCPauseDuration.Prom, map[string]string{
		"service_name": "orders",
	}))
}

func TestGoRuntimeHistogramCollectorKeepsStateWhenRetirementOverflows(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*runtimemetrics.GoRuntimeHistogramSnapshot)
	}{
		{
			name: "bucket",
			mutate: func(histogram *runtimemetrics.GoRuntimeHistogramSnapshot) {
				histogram.Underflow = 1
				histogram.Counts[0] = 1
			},
		},
		{
			name: "total population",
			mutate: func(histogram *runtimemetrics.GoRuntimeHistogramSnapshot) {
				histogram.Counts[1] = 1
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collector := newGoRuntimeHistogramCollector([]string{"service_name"})
			labels := []string{"orders"}

			maxCounts := testPromRuntimeHistogramCounts()
			maxCounts[0] = math.MaxUint64
			collector.Update(101, labels, &runtimemetrics.GoRuntimeHistogramSnapshot{
				Kind:   runtimemetrics.GoHistogramKindGCPause,
				Counts: maxCounts,
			})
			collector.DeletePID(101)

			active := runtimemetrics.GoRuntimeHistogramSnapshot{
				Kind:   runtimemetrics.GoHistogramKindGCPause,
				Counts: testPromRuntimeHistogramCounts(),
			}
			test.mutate(&active)
			collector.Update(202, labels, &active)
			collector.DeletePID(202)

			assert.Contains(t, collector.histogramSnapshots, goRuntimeHistogramKey{
				kind:       runtimemetrics.GoHistogramKindGCPause,
				pid:        202,
				labelTuple: runtimeHistogramLabelTuple(labels),
			})
			retired, ok := collector.retiredSnapshots[goRuntimeHistogramSeriesKey{
				kind:       runtimemetrics.GoHistogramKindGCPause,
				labelTuple: runtimeHistogramLabelTuple(labels),
			}]
			require.True(t, ok)
			assert.Zero(t, retired.histogram.Underflow)
			assert.Equal(t, uint64(math.MaxUint64), retired.histogram.Counts[0])
			assert.Zero(t, retired.histogram.Counts[1])
		})
	}
}

func TestGoRuntimeHistogramCollectorOnlyExportsStoredKindAndReplacesSnapshot(t *testing.T) {
	collector := newGoRuntimeHistogramCollector([]string{"service_name"})
	registry := prometheus.NewRegistry()
	registry.MustRegister(collector)

	counts := testPromRuntimeHistogramCounts()
	counts[0] = 2
	first := &runtimemetrics.GoRuntimeHistogramSnapshot{
		Kind:   runtimemetrics.GoHistogramKindSchedLatency,
		Counts: counts,
	}
	labels := []string{"orders"}
	collector.Update(101, labels, first)

	labels[0] = "mutated"
	counts[0] = 99
	first.Underflow = 99
	metric := gatheredMetric(t, registry, attributes.GoRuntimeScheduleDuration.Prom, map[string]string{
		"service_name": "orders",
	})
	require.NotNil(t, metric)
	assert.Equal(t, uint64(2), metric.GetHistogram().GetSampleCount())
	assert.Nil(t, gatheredMetric(t, registry, attributes.GoRuntimeMemoryGCPauseDuration.Prom, map[string]string{
		"service_name": "orders",
	}))

	updatedCounts := testPromRuntimeHistogramCounts()
	updatedCounts[0] = 4
	collector.Update(101, []string{"orders"}, &runtimemetrics.GoRuntimeHistogramSnapshot{
		Kind:   runtimemetrics.GoHistogramKindSchedLatency,
		Counts: updatedCounts,
	})
	metric = gatheredMetric(t, registry, attributes.GoRuntimeScheduleDuration.Prom, map[string]string{
		"service_name": "orders",
	})
	require.NotNil(t, metric)
	assert.Equal(t, uint64(4), metric.GetHistogram().GetSampleCount())
}

func TestGoRuntimeHistogramCollectorSkipsMalformedSnapshots(t *testing.T) {
	tests := []struct {
		name   string
		labels []string
		counts []uint64
	}{
		{name: "invalid population count", labels: []string{"orders", "prod"}, counts: make([]uint64, testPromRuntimeHistogramPopulationCount-1)},
		{name: "invalid label count", labels: []string{"orders"}, counts: testPromRuntimeHistogramCounts()},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collector := newGoRuntimeHistogramCollector([]string{"service_name", "service_namespace"})
			registry := prometheus.NewRegistry()
			registry.MustRegister(collector)
			collector.Update(101, test.labels, &runtimemetrics.GoRuntimeHistogramSnapshot{
				Kind:   runtimemetrics.GoHistogramKindGCPause,
				Counts: test.counts,
			})

			assert.NotPanics(t, func() {
				families, err := registry.Gather()
				require.NoError(t, err)
				assert.Empty(t, families)
			})
		})
	}
}

func TestGoRuntimeHistogramCollectorRejectsInvalidPIDWithoutPoisoningSibling(t *testing.T) {
	tests := []struct {
		name      string
		pid       app.PID
		histogram runtimemetrics.GoRuntimeHistogramSnapshot
	}{
		{
			name: "zero PID",
			histogram: runtimemetrics.GoRuntimeHistogramSnapshot{
				Kind:   runtimemetrics.GoHistogramKindGCPause,
				Counts: testPromRuntimeHistogramCounts(),
			},
		},
		{
			name: "malformed histogram",
			pid:  202,
			histogram: runtimemetrics.GoRuntimeHistogramSnapshot{
				Kind:   runtimemetrics.GoHistogramKindGCPause,
				Counts: make([]uint64, testPromRuntimeHistogramPopulationCount-1),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collector := newGoRuntimeHistogramCollector([]string{"service_name"})
			registry := prometheus.NewRegistry()
			registry.MustRegister(collector)
			healthyCounts := testPromRuntimeHistogramCounts()
			healthyCounts[0] = 2
			collector.Update(101, []string{"orders"}, &runtimemetrics.GoRuntimeHistogramSnapshot{
				Kind:   runtimemetrics.GoHistogramKindGCPause,
				Counts: healthyCounts,
			})
			if test.pid == 0 {
				test.histogram.Counts[0] = 7
			}

			collector.Update(test.pid, []string{"orders"}, &test.histogram)

			metric := gatheredMetric(t, registry, attributes.GoRuntimeMemoryGCPauseDuration.Prom,
				map[string]string{"service_name": "orders"})
			require.NotNil(t, metric)
			assert.Equal(t, uint64(2), metric.GetHistogram().GetSampleCount())
		})
	}
}

func TestDeleteRuntimeMetricsRemovesGoRuntimeHistogramsAndAllowsReAdd(t *testing.T) {
	reporter, registry := newGoRuntimeHistogramTestReporter(t)
	service := svc.Attrs{
		UID:         svc.UID{Name: "orders", Namespace: "production"},
		ProcPID:     101,
		SDKLanguage: svc.InstrumentableGolang,
		Features:    export.FeatureApplicationRuntime,
	}
	reporter.handleProcessEvent(exec.ProcessEvent{
		Type: exec.ProcessEventCreated,
		File: exec.New(exec.Init{Pid: service.ProcPID, Service: service}),
	}, slog.Default())
	gcSnapshot := testPromRuntimeHistogramMetricSnapshot(service, runtimemetrics.GoHistogramKindGCPause, 2)
	scheduleSnapshot := testPromRuntimeHistogramMetricSnapshot(service, runtimemetrics.GoHistogramKindSchedLatency, 3)

	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{gcSnapshot, scheduleSnapshot})
	assertGoRuntimeHistogramReporterMetrics(t, registry, true)

	reporter.deleteMetricsForService(&service)
	assertGoRuntimeHistogramReporterMetrics(t, registry, false)

	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{gcSnapshot, scheduleSnapshot})
	assertGoRuntimeHistogramReporterMetrics(t, registry, true)
}

func TestGoRuntimeHistogramReporterTracksInheritedChildPIDs(t *testing.T) {
	reporter, registry := newGoRuntimeHistogramTestReporter(t)
	service := svc.Attrs{
		UID:         svc.UID{Name: "orders", Namespace: "production"},
		ProcPID:     42,
		SDKLanguage: svc.InstrumentableGolang,
		Features:    export.FeatureApplicationRuntime,
	}
	processEvent := func(pid app.PID, eventType exec.ProcessEventType) exec.ProcessEvent {
		return exec.ProcessEvent{
			Type: eventType,
			File: exec.New(exec.Init{Pid: pid, Service: service}),
		}
	}
	snapshot := func(pid app.PID, population uint64) runtimemetrics.RuntimeMetricSnapshot {
		counts := testPromRuntimeHistogramCounts()
		counts[0] = population
		return runtimemetrics.RuntimeMetricSnapshot{
			PID:     pid,
			Service: service,
			Histogram: &runtimemetrics.GoRuntimeHistogramSnapshot{
				Kind:   runtimemetrics.GoHistogramKindGCPause,
				Counts: counts,
			},
		}
	}
	count := func() uint64 {
		metric := gatheredMetric(
			t,
			registry,
			attributes.GoRuntimeMemoryGCPauseDuration.Prom,
			map[string]string{"service_name": "orders", "service_namespace": "production"},
		)
		require.NotNil(t, metric)
		return metric.GetHistogram().GetSampleCount()
	}

	reporter.handleProcessEvent(processEvent(service.ProcPID, exec.ProcessEventCreated), slog.Default())
	reporter.handleProcessEvent(processEvent(101, exec.ProcessEventCreated), slog.Default())
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{snapshot(101, 2)})
	require.Equal(t, uint64(2), count())

	reporter.handleProcessEvent(processEvent(202, exec.ProcessEventCreated), slog.Default())
	assert.Equal(t, uint64(2), count(), "discovering a sibling must retain the first PID")
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{snapshot(202, 3)})
	require.Equal(t, uint64(5), count())

	reporter.handleProcessEvent(processEvent(101, exec.ProcessEventTerminated), slog.Default())
	assert.Equal(t, uint64(5), count())

	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{snapshot(202, 4)})
	assert.Equal(t, uint64(6), count())

	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{snapshot(101, 7)})
	assert.Equal(t, uint64(6), count(), "a late snapshot must not resurrect a terminated PID")

	reporter.handleProcessEvent(processEvent(202, exec.ProcessEventTerminated), slog.Default())
	assert.Equal(t, uint64(6), count())

	reporter.handleProcessEvent(processEvent(service.ProcPID, exec.ProcessEventTerminated), slog.Default())
	assert.Nil(t, gatheredMetric(
		t,
		registry,
		attributes.GoRuntimeMemoryGCPauseDuration.Prom,
		map[string]string{"service_name": "orders", "service_namespace": "production"},
	))
}

func TestRuntimeReporterAcceptsHistogramsBeforeCreationAndSkipsAfterTermination(t *testing.T) {
	reporter, registry := newGoRuntimeHistogramTestReporter(t)
	untrackedService := svc.Attrs{
		UID:         svc.UID{Name: "untracked", Namespace: "production"},
		ProcPID:     404,
		SDKLanguage: svc.InstrumentableGolang,
		Features:    export.FeatureApplicationRuntime,
	}
	memoryLimit := int64(1024)
	counts := testPromRuntimeHistogramCounts()
	counts[0] = 2
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		PID:     untrackedService.ProcPID,
		Service: untrackedService,
		Go: &runtimemetrics.GoRuntimeMetricSnapshot{
			MemoryLimit: &memoryLimit,
		},
		Histogram: &runtimemetrics.GoRuntimeHistogramSnapshot{
			Kind:   runtimemetrics.GoHistogramKindGCPause,
			Counts: counts,
		},
	}})

	scalar := gatheredMetric(t, registry, attributes.GoRuntimeMemoryLimit.Prom, map[string]string{
		"service_name":      "untracked",
		"service_namespace": "production",
	})
	require.NotNil(t, scalar)
	assert.InDelta(t, float64(memoryLimit), scalar.GetGauge().GetValue(), 0)
	histogram := gatheredMetric(t, registry, attributes.GoRuntimeMemoryGCPauseDuration.Prom,
		map[string]string{"service_name": "untracked", "service_namespace": "production"})
	require.NotNil(t, histogram)
	assert.Equal(t, uint64(2), histogram.GetHistogram().GetSampleCount())

	trackedService := untrackedService
	trackedService.UID.Name = "tracked"
	trackedService.ProcPID = 101
	processEvent := func(eventType exec.ProcessEventType, generation uint64) exec.ProcessEvent {
		file := exec.New(exec.Init{Pid: trackedService.ProcPID, Service: trackedService})
		file.SetRuntimeMetricGeneration(trackedService.ProcPID, generation)
		return exec.ProcessEvent{
			Type: eventType,
			File: file,
		}
	}
	reporter.handleProcessEvent(processEvent(exec.ProcessEventCreated, 1), slog.Default())
	trackedSnapshot := testPromRuntimeHistogramMetricSnapshot(
		trackedService,
		runtimemetrics.GoHistogramKindGCPause,
		3,
	)
	trackedSnapshot.Generation = 1
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{trackedSnapshot})
	require.NotNil(t, gatheredMetric(t, registry, attributes.GoRuntimeMemoryGCPauseDuration.Prom,
		map[string]string{"service_name": "tracked", "service_namespace": "production"}))

	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		<-start
		reporter.handleProcessEvent(processEvent(exec.ProcessEventTerminated, 1), slog.Default())
	}()
	go func() {
		defer waitGroup.Done()
		<-start
		reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{trackedSnapshot})
	}()
	close(start)
	waitGroup.Wait()

	assert.Nil(t, gatheredMetric(t, registry, attributes.GoRuntimeMemoryGCPauseDuration.Prom,
		map[string]string{"service_name": "tracked", "service_namespace": "production"}))

	reusedPIDSnapshot := testPromRuntimeHistogramMetricSnapshot(
		trackedService,
		runtimemetrics.GoHistogramKindGCPause,
		4,
	)
	reusedPIDSnapshot.Generation = 2
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{reusedPIDSnapshot})
	histogram = gatheredMetric(t, registry, attributes.GoRuntimeMemoryGCPauseDuration.Prom,
		map[string]string{"service_name": "tracked", "service_namespace": "production"})
	require.NotNil(t, histogram, "a reused PID must be accepted before its creation event")
	assert.Equal(t, uint64(4), histogram.GetHistogram().GetSampleCount())

	reporter.handleProcessEvent(processEvent(exec.ProcessEventCreated, 2), slog.Default())
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{trackedSnapshot})
	histogram = gatheredMetric(t, registry, attributes.GoRuntimeMemoryGCPauseDuration.Prom,
		map[string]string{"service_name": "tracked", "service_namespace": "production"})
	require.NotNil(t, histogram)
	assert.Equal(t, uint64(4), histogram.GetHistogram().GetSampleCount(),
		"an old in-flight generation must be rejected after PID reuse")
}

func TestGoRuntimeHistogramCollectorSupportsConcurrentUpdateCollectAndDelete(_ *testing.T) {
	collector := newGoRuntimeHistogramCollector([]string{"service_name"})
	const iterations = 500
	var waitGroup sync.WaitGroup
	waitGroup.Add(3)

	go func() {
		defer waitGroup.Done()
		for i := 0; i < iterations; i++ {
			counts := testPromRuntimeHistogramCounts()
			counts[i%len(counts)] = uint64(i)
			collector.Update(101, []string{"orders"}, &runtimemetrics.GoRuntimeHistogramSnapshot{
				Kind:      runtimemetrics.GoHistogramKind(i % 2),
				Counts:    counts,
				Underflow: uint64(i),
				Overflow:  uint64(i),
			})
		}
	}()
	go func() {
		defer waitGroup.Done()
		metrics := make(chan prometheus.Metric)
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			for metric := range metrics {
				_ = metric
			}
		}()
		for i := 0; i < iterations; i++ {
			collector.Collect(metrics)
		}
		close(metrics)
		<-drained
	}()
	go func() {
		defer waitGroup.Done()
		for i := 0; i < iterations; i++ {
			collector.Delete([]string{"orders"})
		}
	}()

	waitGroup.Wait()
}

func newGoRuntimeHistogramTestReporter(t *testing.T) (*metricsReporter, *prometheus.Registry) {
	t.Helper()

	registry := prometheus.NewRegistry()
	reporter, err := newReporter(
		t.Context(),
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&PrometheusConfig{Registry: registry, TTL: time.Minute},
		&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRuntime},
		&attributes.SelectorConfig{SelectionCfg: attributes.Selection{
			attributes.Resource.Section: attributes.InclusionLists{
				Include: []string{"service.name", "service.namespace"},
			},
		}},
		request.UnresolvedNames{},
		nil,
		msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1)),
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, reporter.goRuntimeHistograms)
	return reporter, registry
}

func testPromRuntimeHistogramMetricSnapshot(
	service svc.Attrs,
	kind runtimemetrics.GoHistogramKind,
	population uint64,
) runtimemetrics.RuntimeMetricSnapshot {
	counts := testPromRuntimeHistogramCounts()
	counts[0] = population
	return runtimemetrics.RuntimeMetricSnapshot{
		PID:     service.ProcPID,
		Service: service,
		Histogram: &runtimemetrics.GoRuntimeHistogramSnapshot{
			Kind:   kind,
			Counts: counts,
		},
	}
}

func assertGoRuntimeHistogramReporterMetrics(t *testing.T, registry *prometheus.Registry, present bool) {
	t.Helper()

	labels := map[string]string{
		"service_name":      "orders",
		"service_namespace": "production",
	}
	for _, name := range []string{
		attributes.GoRuntimeMemoryGCPauseDuration.Prom,
		attributes.GoRuntimeScheduleDuration.Prom,
	} {
		metric := gatheredMetric(t, registry, name, labels)
		if present {
			require.NotNil(t, metric, name)
		} else {
			assert.Nil(t, metric, name)
		}
	}
}

func testPromRuntimeHistogramCounts() []uint64 {
	return make([]uint64, testPromRuntimeHistogramPopulationCount)
}
