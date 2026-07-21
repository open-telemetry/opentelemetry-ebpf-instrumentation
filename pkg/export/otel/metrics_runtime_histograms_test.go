// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	metricdata "go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

const testGoRuntimeHistogramBucketCount = 160

func TestGoRuntimeHistogramProducerProducesCumulativeMetrics(t *testing.T) {
	producer := newGoRuntimeHistogramProducer()
	gcTime := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	scheduleTime := gcTime.Add(time.Second)
	gcCounts := testGoRuntimeHistogramCounts()
	gcCounts[0] = 2
	gcCounts[len(gcCounts)-1] = 3
	scheduleCounts := testGoRuntimeHistogramCounts()
	scheduleCounts[12] = 5

	gcSnapshot := testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 101, gcTime, gcCounts, 1, 4,
	)
	scheduleSnapshot := testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindSchedLatency, 101, scheduleTime, scheduleCounts, 6, 7,
	)
	producer.Update(gcSnapshot)
	producer.Update(scheduleSnapshot)

	produced, err := producer.Produce(t.Context())
	require.NoError(t, err)
	metrics := testGoRuntimeHistogramMetricsByName(t, produced)
	require.Len(t, metrics, 2)

	assertProducedHistogram(t, metrics[attributes.GoRuntimeMemoryGCPauseDuration.OTEL], gcSnapshot)
	assertProducedHistogram(t, metrics[attributes.GoRuntimeScheduleDuration.OTEL], scheduleSnapshot)
}

func TestGoRuntimeHistogramProducerOnlyProducesStoredKinds(t *testing.T) {
	producer := newGoRuntimeHistogramProducer()

	produced, err := producer.Produce(t.Context())
	require.NoError(t, err)
	assert.Empty(t, produced)

	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindSchedLatency,
		101,
		time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC),
		testGoRuntimeHistogramCounts(),
		0,
		0,
	))
	produced, err = producer.Produce(t.Context())
	require.NoError(t, err)
	metrics := testGoRuntimeHistogramMetricsByName(t, produced)
	require.Len(t, metrics, 1)
	assert.Contains(t, metrics, attributes.GoRuntimeScheduleDuration.OTEL)
}

func TestGoRuntimeHistogramProducerPreservesStartTimeForMonotonicUpdate(t *testing.T) {
	producer := newGoRuntimeHistogramProducer()
	start := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	counts := testGoRuntimeHistogramCounts()
	counts[3] = 1
	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 101, start, counts, 2, 3,
	))

	counts[3]++
	updatedAt := start.Add(time.Minute)
	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 101, updatedAt, counts, 3, 4,
	))

	point := testProducedHistogramPoint(t, producer, attributes.GoRuntimeMemoryGCPauseDuration.OTEL)
	assert.Equal(t, start, point.StartTime)
	assert.Equal(t, updatedAt, point.Time)
}

func TestGoRuntimeHistogramProducerResetsStartTimeOnPIDChangePerKind(t *testing.T) {
	producer := newGoRuntimeHistogramProducer()
	start := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	counts := testGoRuntimeHistogramCounts()
	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 101, start, counts, 0, 0,
	))
	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindSchedLatency, 101, start, counts, 0, 0,
	))

	resetAt := start.Add(time.Minute)
	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 202, resetAt, counts, 0, 0,
	))

	gcPoint := testProducedHistogramPoint(t, producer, attributes.GoRuntimeMemoryGCPauseDuration.OTEL)
	assert.Equal(t, resetAt, gcPoint.StartTime)
	schedulePoint := testProducedHistogramPoint(t, producer, attributes.GoRuntimeScheduleDuration.OTEL)
	assert.Equal(t, start, schedulePoint.StartTime)
}

func TestGoRuntimeHistogramProducerResetsStartTimeOnPopulationRegression(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*runtimemetrics.GoRuntimeHistogramSnapshot)
	}{
		{
			name: "underflow",
			mutate: func(snapshot *runtimemetrics.GoRuntimeHistogramSnapshot) {
				snapshot.Underflow--
			},
		},
		{
			name: "bucket count",
			mutate: func(snapshot *runtimemetrics.GoRuntimeHistogramSnapshot) {
				snapshot.Counts[73]--
			},
		},
		{
			name: "overflow",
			mutate: func(snapshot *runtimemetrics.GoRuntimeHistogramSnapshot) {
				snapshot.Overflow--
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			producer := newGoRuntimeHistogramProducer()
			start := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
			counts := testGoRuntimeHistogramCounts()
			counts[73] = 2
			first := testGoRuntimeHistogramSnapshot(
				runtimemetrics.GoHistogramKindGCPause, 101, start, counts, 2, 2,
			)
			producer.Update(first)

			resetAt := start.Add(time.Minute)
			regressed := testGoRuntimeHistogramSnapshot(
				runtimemetrics.GoHistogramKindGCPause, 101, resetAt, counts, 2, 2,
			)
			test.mutate(regressed.Histogram)
			producer.Update(regressed)

			point := testProducedHistogramPoint(t, producer, attributes.GoRuntimeMemoryGCPauseDuration.OTEL)
			assert.Equal(t, resetAt, point.StartTime)
		})
	}
}

func TestGoRuntimeHistogramProducerRejectsMalformedUpdate(t *testing.T) {
	tests := []struct {
		name           string
		validKind      runtimemetrics.GoHistogramKind
		expectedMetric string
		histogram      runtimemetrics.GoRuntimeHistogramSnapshot
	}{
		{
			name:           "invalid population count",
			validKind:      runtimemetrics.GoHistogramKindGCPause,
			expectedMetric: attributes.GoRuntimeMemoryGCPauseDuration.OTEL,
			histogram: runtimemetrics.GoRuntimeHistogramSnapshot{
				Kind:   runtimemetrics.GoHistogramKindGCPause,
				Counts: make([]uint64, testGoRuntimeHistogramBucketCount-1),
			},
		},
		{
			name:           "unsupported kind",
			validKind:      runtimemetrics.GoHistogramKindSchedLatency,
			expectedMetric: attributes.GoRuntimeScheduleDuration.OTEL,
			histogram: runtimemetrics.GoRuntimeHistogramSnapshot{
				Kind:   runtimemetrics.GoHistogramKind(2),
				Counts: testGoRuntimeHistogramCounts(),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			producer := newGoRuntimeHistogramProducer()
			validAt := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
			valid := testGoRuntimeHistogramSnapshot(
				test.validKind,
				101,
				validAt,
				testGoRuntimeHistogramCounts(),
				0,
				0,
			)
			producer.Update(valid)
			producer.Update(runtimemetrics.RuntimeMetricSnapshot{
				PID:       101,
				Time:      validAt.Add(time.Minute),
				Histogram: &test.histogram,
			})

			produced, err := producer.Produce(t.Context())

			require.NoError(t, err)
			metrics := testGoRuntimeHistogramMetricsByName(t, produced)
			require.Len(t, metrics, 1)
			assertProducedHistogram(t, metrics[test.expectedMetric], valid)
		})
	}
}

func TestGoRuntimeHistogramProducerCopiesInputAndOutput(t *testing.T) {
	producer := newGoRuntimeHistogramProducer()
	at := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	counts := testGoRuntimeHistogramCounts()
	counts[8] = 9
	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 101, at, counts, 1, 2,
	))
	counts[8] = 99

	first := testProducedHistogramPoint(t, producer, attributes.GoRuntimeMemoryGCPauseDuration.OTEL)
	require.Equal(t, uint64(9), first.BucketCounts[9])
	first.Bounds[0] = 123
	first.BucketCounts[9] = 123

	second := testProducedHistogramPoint(t, producer, attributes.GoRuntimeMemoryGCPauseDuration.OTEL)
	assert.NotEqual(t, float64(123), second.Bounds[0])
	assert.Equal(t, uint64(9), second.BucketCounts[9])
}

func TestGoRuntimeHistogramProducerHonorsCanceledContext(t *testing.T) {
	producer := newGoRuntimeHistogramProducer()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	produced, err := producer.Produce(ctx)
	assert.Nil(t, produced)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestGoRuntimeHistogramProducerSupportsConcurrentUpdateAndProduce(t *testing.T) {
	producer := newGoRuntimeHistogramProducer()
	const iterations = 500
	errCh := make(chan error, iterations)
	var waitGroup sync.WaitGroup

	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		for i := 0; i < iterations; i++ {
			counts := testGoRuntimeHistogramCounts()
			counts[i%len(counts)] = uint64(i)
			producer.Update(testGoRuntimeHistogramSnapshot(
				runtimemetrics.GoHistogramKindGCPause,
				101,
				time.Unix(int64(i), 0),
				counts,
				uint64(i),
				uint64(i),
			))
		}
	}()
	go func() {
		defer waitGroup.Done()
		for i := 0; i < iterations; i++ {
			if _, err := producer.Produce(t.Context()); err != nil {
				errCh <- err
			}
		}
	}()
	waitGroup.Wait()
	close(errCh)

	for err := range errCh {
		assert.NoError(t, err)
	}
}

func TestRecordRuntimeMetricsUpdatesGoHistogramWithoutScalarSnapshot(t *testing.T) {
	producer := newGoRuntimeHistogramProducer()
	metrics := &RuntimeMetrics{goHistogramProducer: producer}
	snapshot := testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause,
		101,
		time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC),
		testGoRuntimeHistogramCounts(),
		0,
		0,
	)
	snapshot.Service.SDKLanguage = svc.InstrumentableGolang

	recordRuntimeMetrics(t.Context(), metrics, snapshot)

	produced, err := producer.Produce(t.Context())
	require.NoError(t, err)
	assert.Contains(t, testGoRuntimeHistogramMetricsByName(t, produced), attributes.GoRuntimeMemoryGCPauseDuration.OTEL)
}

func TestRuntimeMetricsInstanceRegistersGoHistogramProducer(t *testing.T) {
	exporter := &runtimeHistogramNamesExporter{exported: make(chan []string, 1)}
	reporter := RuntimeMetricsReporter{
		ctx:      t.Context(),
		cfg:      &otelcfg.MetricsConfig{Interval: time.Hour},
		exporter: exporter,
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	metrics := reporter.newMetricsInstance(nil)
	t.Cleanup(func() {
		require.NoError(t, metrics.provider.Shutdown(context.Background()))
	})

	snapshot := testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause,
		101,
		time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC),
		testGoRuntimeHistogramCounts(),
		0,
		0,
	)
	snapshot.Service.SDKLanguage = svc.InstrumentableGolang
	recordRuntimeMetrics(t.Context(), &metrics, snapshot)

	require.NoError(t, metrics.provider.ForceFlush(t.Context()))
	assert.Contains(t, <-exporter.exported, attributes.GoRuntimeMemoryGCPauseDuration.OTEL)
}

type runtimeHistogramNamesExporter struct {
	exported chan []string
}

func (*runtimeHistogramNamesExporter) Temporality(sdkmetric.InstrumentKind) metricdata.Temporality {
	return metricdata.CumulativeTemporality
}

func (*runtimeHistogramNamesExporter) Aggregation(sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.AggregationDefault{}
}

func (e *runtimeHistogramNamesExporter) Export(_ context.Context, metrics *metricdata.ResourceMetrics) error {
	var names []string
	for _, scope := range metrics.ScopeMetrics {
		for _, metric := range scope.Metrics {
			names = append(names, metric.Name)
		}
	}
	e.exported <- names
	return nil
}

func (*runtimeHistogramNamesExporter) ForceFlush(context.Context) error { return nil }

func (*runtimeHistogramNamesExporter) Shutdown(context.Context) error { return nil }

func testGoRuntimeHistogramCounts() []uint64 {
	return make([]uint64, testGoRuntimeHistogramBucketCount)
}

func testGoRuntimeHistogramSnapshot(
	kind runtimemetrics.GoHistogramKind,
	pid app.PID,
	at time.Time,
	counts []uint64,
	underflow uint64,
	overflow uint64,
) runtimemetrics.RuntimeMetricSnapshot {
	return runtimemetrics.RuntimeMetricSnapshot{
		PID:  pid,
		Time: at,
		Histogram: &runtimemetrics.GoRuntimeHistogramSnapshot{
			Kind:      kind,
			Counts:    counts,
			Underflow: underflow,
			Overflow:  overflow,
		},
	}
}

func testGoRuntimeHistogramMetricsByName(
	t *testing.T,
	produced []metricdata.ScopeMetrics,
) map[string]metricdata.Metrics {
	t.Helper()
	require.Len(t, produced, 1)

	metrics := make(map[string]metricdata.Metrics, len(produced[0].Metrics))
	for _, metric := range produced[0].Metrics {
		metrics[metric.Name] = metric
	}
	return metrics
}

func assertProducedHistogram(
	t *testing.T,
	metric metricdata.Metrics,
	snapshot runtimemetrics.RuntimeMetricSnapshot,
) {
	t.Helper()
	assert.Equal(t, "s", metric.Unit)
	histogram, ok := metric.Data.(metricdata.Histogram[float64])
	require.True(t, ok)
	assert.Equal(t, metricdata.CumulativeTemporality, histogram.Temporality)
	require.Len(t, histogram.DataPoints, 1)

	data, err := snapshot.Histogram.Data()
	require.NoError(t, err)
	point := histogram.DataPoints[0]
	assert.Empty(t, point.Attributes.ToSlice())
	assert.Equal(t, snapshot.Time, point.StartTime)
	assert.Equal(t, snapshot.Time, point.Time)
	assert.Equal(t, data.Bounds, point.Bounds)
	assert.Equal(t, data.BucketCounts, point.BucketCounts)
	assert.Equal(t, data.Count, point.Count)
	assert.Equal(t, data.Sum, point.Sum)
}

func testProducedHistogramPoint(
	t *testing.T,
	producer *goRuntimeHistogramProducer,
	name string,
) metricdata.HistogramDataPoint[float64] {
	t.Helper()
	produced, err := producer.Produce(t.Context())
	require.NoError(t, err)
	metric, ok := testGoRuntimeHistogramMetricsByName(t, produced)[name]
	require.True(t, ok, "metric %s not found", name)
	histogram, ok := metric.Data.(metricdata.Histogram[float64])
	require.True(t, ok)
	require.Len(t, histogram.DataPoints, 1)
	return histogram.DataPoints[0]
}
