// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
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
	collector.Update(labels, &gcSnapshot)
	collector.Update(labels, &scheduleSnapshot)

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
	collector.Update(labels, first)

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
	collector.Update([]string{"orders"}, &runtimemetrics.GoRuntimeHistogramSnapshot{
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
			collector.Update(test.labels, &runtimemetrics.GoRuntimeHistogramSnapshot{
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

func TestDeleteRuntimeMetricsRemovesGoRuntimeHistogramsAndAllowsReAdd(t *testing.T) {
	reporter, registry := newGoRuntimeHistogramTestReporter(t)
	service := svc.Attrs{
		UID:         svc.UID{Name: "orders", Namespace: "production"},
		SDKLanguage: svc.InstrumentableGolang,
		Features:    export.FeatureApplicationRuntime,
	}
	gcSnapshot := testPromRuntimeHistogramMetricSnapshot(service, runtimemetrics.GoHistogramKindGCPause, 2)
	scheduleSnapshot := testPromRuntimeHistogramMetricSnapshot(service, runtimemetrics.GoHistogramKindSchedLatency, 3)

	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{gcSnapshot, scheduleSnapshot})
	assertGoRuntimeHistogramReporterMetrics(t, registry, true)

	reporter.deleteRuntimeMetrics(&service)
	assertGoRuntimeHistogramReporterMetrics(t, registry, false)

	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{gcSnapshot, scheduleSnapshot})
	assertGoRuntimeHistogramReporterMetrics(t, registry, true)
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
			collector.Update([]string{"orders"}, &runtimemetrics.GoRuntimeHistogramSnapshot{
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
		&perapp.MetricsConfig{Features: export.FeatureApplicationRuntime},
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
