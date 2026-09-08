// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"io"
	"log/slog"
	"math"
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
	producer := newGoRuntimeHistogramProducer(metricdata.CumulativeTemporality)
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

func TestGoRuntimeHistogramProducerAggregatesCumulativeMetricsAcrossPIDs(t *testing.T) {
	producer := newGoRuntimeHistogramProducer(metricdata.CumulativeTemporality)
	at := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	firstCounts := testGoRuntimeHistogramCounts()
	firstCounts[0] = 2
	secondCounts := testGoRuntimeHistogramCounts()
	secondCounts[0] = 3

	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 101, at, firstCounts, 1, 3,
	))
	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 202, at.Add(time.Second), secondCounts, 2, 4,
	))

	point := testProducedHistogramPoint(t, producer, attributes.GoRuntimeMemoryGCPauseDuration.OTEL)
	assert.Equal(t, uint64(15), point.Count)
	assert.Equal(t, uint64(3), point.BucketCounts[0])
	assert.Equal(t, uint64(5), point.BucketCounts[1])
	assert.Equal(t, uint64(7), point.BucketCounts[len(point.BucketCounts)-1])
}

func TestGoRuntimeHistogramProducerProducesDeltaMetrics(t *testing.T) {
	producer := newGoRuntimeHistogramProducer(metricdata.DeltaTemporality)
	start := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	counts := testGoRuntimeHistogramCounts()
	counts[3] = 4
	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 101, start, counts, 2, 1,
	))

	first := testProducedHistogram(
		t, producer, attributes.GoRuntimeMemoryGCPauseDuration.OTEL,
	)
	assert.Equal(t, metricdata.DeltaTemporality, first.Temporality)
	require.Len(t, first.DataPoints, 1)
	assert.Equal(t, uint64(7), first.DataPoints[0].Count)

	updatedAt := start.Add(time.Minute)
	counts[3] = 7
	counts[4] = 2
	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 101, updatedAt, counts, 3, 1,
	))

	second := testProducedHistogram(
		t, producer, attributes.GoRuntimeMemoryGCPauseDuration.OTEL,
	)
	assert.Equal(t, metricdata.DeltaTemporality, second.Temporality)
	require.Len(t, second.DataPoints, 1)
	point := second.DataPoints[0]
	assert.Equal(t, start, point.StartTime)
	assert.Equal(t, updatedAt, point.Time)
	assert.Equal(t, uint64(6), point.Count)
	assert.Equal(t, uint64(1), point.BucketCounts[0])
	assert.Equal(t, uint64(3), point.BucketCounts[4])
	assert.Equal(t, uint64(2), point.BucketCounts[5])

	third, err := producer.Produce(t.Context())
	require.NoError(t, err)
	assert.Empty(t, third)

	finalAt := updatedAt.Add(time.Minute)
	counts[4] = 3
	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 101, finalAt, counts, 3, 1,
	))

	fourth := testProducedHistogram(
		t, producer, attributes.GoRuntimeMemoryGCPauseDuration.OTEL,
	)
	require.Len(t, fourth.DataPoints, 1)
	point = fourth.DataPoints[0]
	assert.Equal(t, updatedAt, point.StartTime)
	assert.Equal(t, finalAt, point.Time)
	assert.Equal(t, uint64(1), point.Count)
	assert.Equal(t, uint64(1), point.BucketCounts[5])
}

func TestGoRuntimeHistogramProducerProducesFinalDeltaAfterDelete(t *testing.T) {
	producer := newGoRuntimeHistogramProducer(metricdata.DeltaTemporality)
	start := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	counts := testGoRuntimeHistogramCounts()
	counts[3] = 4
	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 101, start, counts, 2, 1,
	))
	testProducedHistogramPoint(t, producer, attributes.GoRuntimeMemoryGCPauseDuration.OTEL)

	finalAt := start.Add(time.Minute)
	counts[3] = 7
	counts[4] = 2
	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 101, finalAt, counts, 3, 1,
	))
	producer.Delete(101)
	producer.Delete(101)

	reusedAt := finalAt.Add(time.Minute)
	reusedCounts := testGoRuntimeHistogramCounts()
	reusedCounts[10] = 5
	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 101, reusedAt, reusedCounts, 0, 0,
	))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	produced, err := producer.Produce(ctx)
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, produced)

	final := testProducedHistogramPoint(t, producer, attributes.GoRuntimeMemoryGCPauseDuration.OTEL)
	assert.Equal(t, start, final.StartTime)
	assert.Equal(t, reusedAt, final.Time)
	assert.Equal(t, uint64(11), final.Count)
	assert.Equal(t, uint64(1), final.BucketCounts[0])
	assert.Equal(t, uint64(3), final.BucketCounts[4])
	assert.Equal(t, uint64(2), final.BucketCounts[5])
	assert.Equal(t, uint64(5), final.BucketCounts[11])

	produced, err = producer.Produce(t.Context())
	require.NoError(t, err)
	assert.Empty(t, produced)
}

func TestGoRuntimeHistogramProducerDeleteDoesNotDependOnFinalDeltaAggregation(t *testing.T) {
	producer := newGoRuntimeHistogramProducer(metricdata.DeltaTemporality)
	at := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)

	maxCounts := testGoRuntimeHistogramCounts()
	maxCounts[0] = math.MaxUint64
	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 101, at, maxCounts, 0, 0,
	))
	producer.Delete(101)

	counts := testGoRuntimeHistogramCounts()
	counts[0] = 1
	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 202, at, counts, 0, 0,
	))
	producer.Delete(202)

	assert.NotContains(t, producer.histograms, goRuntimeHistogramKey{
		kind: runtimemetrics.GoHistogramKindGCPause,
		pid:  202,
	})
}

func TestGoRuntimeHistogramProducerCalculatesDeltaPerPIDBeforeAggregating(t *testing.T) {
	producer := newGoRuntimeHistogramProducer(metricdata.DeltaTemporality)
	start := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	firstCounts := testGoRuntimeHistogramCounts()
	firstCounts[0] = 100
	secondCounts := testGoRuntimeHistogramCounts()
	secondCounts[0] = 100

	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 101, start, firstCounts, 0, 0,
	))
	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 202, start, secondCounts, 0, 0,
	))
	first := testProducedHistogramPoint(t, producer, attributes.GoRuntimeMemoryGCPauseDuration.OTEL)
	require.Equal(t, uint64(200), first.Count)

	resetCounts := testGoRuntimeHistogramCounts()
	resetCounts[0] = 5
	secondCounts[0] = 210
	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 101, start.Add(time.Minute), resetCounts, 0, 0,
	))
	producer.Update(testGoRuntimeHistogramSnapshot(
		runtimemetrics.GoHistogramKindGCPause, 202, start.Add(time.Minute), secondCounts, 0, 0,
	))

	second := testProducedHistogramPoint(t, producer, attributes.GoRuntimeMemoryGCPauseDuration.OTEL)
	assert.Equal(t, uint64(115), second.Count)
	assert.Equal(t, uint64(115), second.BucketCounts[1])
}

func TestGoRuntimeHistogramProducerOnlyProducesStoredKinds(t *testing.T) {
	producer := newGoRuntimeHistogramProducer(metricdata.CumulativeTemporality)

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
	producer := newGoRuntimeHistogramProducer(metricdata.CumulativeTemporality)
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

func TestGoRuntimeHistogramProducerUsesEarliestStartTimeAcrossPIDs(t *testing.T) {
	producer := newGoRuntimeHistogramProducer(metricdata.CumulativeTemporality)
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
	assert.Equal(t, start, gcPoint.StartTime)
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
			producer := newGoRuntimeHistogramProducer(metricdata.CumulativeTemporality)
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
			producer := newGoRuntimeHistogramProducer(metricdata.CumulativeTemporality)
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
	producer := newGoRuntimeHistogramProducer(metricdata.CumulativeTemporality)
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
	producer := newGoRuntimeHistogramProducer(metricdata.CumulativeTemporality)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	produced, err := producer.Produce(ctx)
	assert.Nil(t, produced)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestGoRuntimeHistogramProducerSupportsConcurrentUpdateAndProduce(t *testing.T) {
	producer := newGoRuntimeHistogramProducer(metricdata.CumulativeTemporality)
	const iterations = 500
	errCh := make(chan error, iterations)
	var waitGroup sync.WaitGroup

	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		for i := range iterations {
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
		for range iterations {
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
	producer := newGoRuntimeHistogramProducer(metricdata.CumulativeTemporality)
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

func TestRuntimeMetricsInstanceUsesExporterHistogramTemporality(t *testing.T) {
	exporter := &runtimeHistogramNamesExporter{
		exported:            make(chan []string, 2),
		temporality:         metricdata.DeltaTemporality,
		exportedTemporality: make(chan metricdata.Temporality, 2),
	}
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
		1,
		0,
	)
	snapshot.Service.SDKLanguage = svc.InstrumentableGolang
	recordRuntimeMetrics(t.Context(), &metrics, snapshot)

	require.NoError(t, metrics.provider.ForceFlush(t.Context()))
	assert.Equal(t, metricdata.DeltaTemporality, <-exporter.exportedTemporality)
}

type runtimeHistogramNamesExporter struct {
	exported            chan []string
	temporality         metricdata.Temporality
	exportedTemporality chan metricdata.Temporality
}

func (e *runtimeHistogramNamesExporter) Temporality(sdkmetric.InstrumentKind) metricdata.Temporality {
	if e.temporality != metricdata.Temporality(0) {
		return e.temporality
	}
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
			if histogram, ok := metric.Data.(metricdata.Histogram[float64]); ok &&
				e.exportedTemporality != nil {
				e.exportedTemporality <- histogram.Temporality
			}
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
		PID:     pid,
		Time:    at,
		Service: svc.Attrs{ProcPID: pid},
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
	histogram := testProducedHistogram(t, producer, name)
	require.Len(t, histogram.DataPoints, 1)
	return histogram.DataPoints[0]
}

func testProducedHistogram(
	t *testing.T,
	producer *goRuntimeHistogramProducer,
	name string,
) metricdata.Histogram[float64] {
	t.Helper()
	produced, err := producer.Produce(t.Context())
	require.NoError(t, err)
	metric, ok := testGoRuntimeHistogramMetricsByName(t, produced)[name]
	require.True(t, ok, "metric %s not found", name)
	histogram, ok := metric.Data.(metricdata.Histogram[float64])
	require.True(t, ok)
	return histogram
}
