// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	metricdata "go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/internal/test/collector"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/internal/avoidedsvc"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

func TestInternalMetricsReporterBpfProbeStats(t *testing.T) {
	metricRecords := make(chan collector.MetricRecord, 16)
	mcfg := &otelcfg.MetricsConfig{
		Interval:        10 * time.Millisecond,
		MetricsConsumer: testMetricsConsumer(metricRecords),
	}
	ctxInfo := &global.ContextInfo{
		NodeMeta:            meta.NodeMeta{HostID: "test-host"},
		OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: mcfg},
	}

	reporter, err := NewInternalMetricsReporter(
		t.Context(),
		ctxInfo,
		mcfg,
		&imetrics.InternalMetricsConfig{BpfMetricScrapeInterval: time.Millisecond},
	)
	require.NoError(t, err)

	// 3 executions averaging 0.0001s, which the accounting attributes to the 0.0001 bucket
	reporter.BpfProbeStats("7", "kprobe", "tcp_connect", 3, 0.0003, map[float64]uint64{0.0001: 3})

	records := readMetricsByName(t, metricRecords, time.Second,
		attr.VendorPrefix+".bpf.probe.latency",
	)
	require.Len(t, records, 1)

	record := records[0]
	assert.Equal(t, "7", record.Attributes["bpf.probe.id"])
	assert.Equal(t, "kprobe", record.Attributes["bpf.probe.type"])
	assert.Equal(t, "tcp_connect", record.Attributes["bpf.probe.name"])
	assert.Equal(t, 3, record.Count)
	assert.InDelta(t, 0.0003, record.FloatVal, 0.00001)
}

func TestBpfProbeLatencyProducerDeltaTemporality(t *testing.T) {
	bound := imetrics.BpfLatenciesBuckets[0]
	producer := newBpfProbeLatencyProducer(
		attributes.NewInternalMetrics(attr.VendorPrefix).BpfProbeLatency,
		metricdata.DeltaTemporality,
	)

	producer.Update("7", "kprobe", "tcp_connect", 2, 0.5, map[float64]uint64{bound: 2})
	first := produceHistogramPoint(t, producer)
	assert.Equal(t, uint64(2), first.Count)
	assert.InDelta(t, 0.5, first.Sum, 0.0001)

	// the source snapshots are cumulative, so a second interval of 3 more observations
	// arrives as a total of 5 and must be emitted as the delta
	producer.Update("7", "kprobe", "tcp_connect", 3, 0.75, map[float64]uint64{bound: 5})
	second := produceHistogramPoint(t, producer)
	assert.Equal(t, uint64(3), second.Count)
	assert.InDelta(t, 0.75, second.Sum, 0.0001)
	assert.Equal(t, uint64(3), second.BucketCounts[0])
	assert.Equal(t, first.Time, second.StartTime, "delta points must start where the previous one ended")
}

func produceHistogramPoint(t *testing.T, producer *bpfProbeLatencyProducer) metricdata.HistogramDataPoint[float64] {
	t.Helper()

	scopeMetrics, err := producer.Produce(t.Context())
	require.NoError(t, err)
	require.Len(t, scopeMetrics, 1)
	require.Len(t, scopeMetrics[0].Metrics, 1)

	histogram, ok := scopeMetrics[0].Metrics[0].Data.(metricdata.Histogram[float64])
	require.True(t, ok, "expected a float64 histogram")
	require.Len(t, histogram.DataPoints, 1)

	return histogram.DataPoints[0]
}

func TestBpfProbeLatencyProducerBucketCounts(t *testing.T) {
	bounds := imetrics.BpfLatenciesBuckets
	largest := bounds[len(bounds)-1]

	// two observations land in a real bucket, a third exceeds every bound and so was
	// never recorded by the accounting: it must surface in the overflow bucket
	counts := bucketCounts(&bpfProbeLatencyState{
		count:   3,
		sum:     1.5,
		buckets: map[float64]uint64{bounds[0]: 2},
	})

	require.Len(t, counts, len(bounds)+1)
	assert.Equal(t, uint64(2), counts[0])
	assert.Equal(t, uint64(1), counts[len(counts)-1], "observation above %v must land in the overflow bucket", largest)

	var total uint64
	for _, c := range counts {
		total += c
	}
	assert.Equal(t, uint64(3), total, "bucket counts must sum to the observation count")
}

func TestInternalMetricsReporterQueueBufferUtilization(t *testing.T) {
	metricRecords := make(chan collector.MetricRecord, 16)
	mcfg := &otelcfg.MetricsConfig{
		Interval:        10 * time.Millisecond,
		MetricsConsumer: testMetricsConsumer(metricRecords),
	}
	ctxInfo := &global.ContextInfo{
		NodeMeta:            meta.NodeMeta{HostID: "test-host"},
		OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: mcfg},
	}

	reporter, err := NewInternalMetricsReporter(
		t.Context(),
		ctxInfo,
		mcfg,
		&imetrics.InternalMetricsConfig{BpfMetricScrapeInterval: time.Millisecond},
	)
	require.NoError(t, err)

	reporter.QueueBufferUtilization("traces", 0.42)

	records := readMetricsByName(t, metricRecords, time.Second,
		attr.VendorPrefix+".queue.capacity.ratio",
	)
	require.Len(t, records, 1)
	assert.Equal(t, "traces", records[0].Attributes["subscriber"])
	assert.InDelta(t, 0.42, records[0].FloatVal, 0.001)
}

func TestInternalMetricsReporterAvoidedServicesBounded(t *testing.T) {
	metricRecords := make(chan collector.MetricRecord, 16)
	mcfg := &otelcfg.MetricsConfig{
		Interval:        10 * time.Millisecond,
		MetricsConsumer: testMetricsConsumer(metricRecords),
	}
	ctxInfo := &global.ContextInfo{
		NodeMeta:            meta.NodeMeta{HostID: "test-host"},
		OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: mcfg},
	}

	reporter, err := NewInternalMetricsReporter(
		t.Context(),
		ctxInfo,
		mcfg,
		&imetrics.InternalMetricsConfig{
			BpfMetricScrapeInterval: time.Millisecond,
			AvoidedServices:         imetrics.AvoidedServicesConfig{Limit: 3},
		},
	)
	require.NoError(t, err)

	reporter.AvoidInstrumentationMetrics("svc-0", "ns-0", "inst-0")
	reporter.AvoidInstrumentationTraces("svc-0", "ns-0", "inst-0")
	reporter.AvoidInstrumentationMetrics("svc-1", "ns-1", "inst-1")
	reporter.AvoidInstrumentationTraces("svc-1", "ns-1", "inst-1")

	records := readNMetricsByName(t, metricRecords, time.Second, attr.VendorPrefix+".avoided.services", 3)
	require.Len(t, records, 3)

	labelSets := map[string]struct{}{}
	overflowRecords := 0
	for _, record := range records {
		assert.Equal(t, int64(1), record.IntVal)
		if record.Attributes[avoidedsvc.OverflowAttribute] == "true" {
			overflowRecords++
			assert.NotContains(t, record.Attributes, string(attr.ServiceName))
			assert.NotContains(t, record.Attributes, string(attr.ServiceNamespace))
			assert.NotContains(t, record.Attributes, string(attr.ServiceInstanceID))
			assert.NotContains(t, record.Attributes, "telemetry.type")
			continue
		}

		assert.NotContains(t, record.Attributes, avoidedsvc.OverflowAttribute)
		assert.NotContains(t, record.Attributes, string(attr.ServiceInstanceID))
		labelSets[record.Attributes[string(attr.ServiceName)]+"/"+
			record.Attributes[string(attr.ServiceNamespace)]+"/"+
			record.Attributes["telemetry.type"]] = struct{}{}
	}

	assert.Contains(t, labelSets, "svc-0/ns-0/metrics")
	assert.Contains(t, labelSets, "svc-0/ns-0/traces")
	assert.Equal(t, 1, overflowRecords)
}

func TestInternalMetricsReporterAvoidedServicesDisabled(t *testing.T) {
	metricRecords := make(chan collector.MetricRecord, 16)
	mcfg := &otelcfg.MetricsConfig{
		Interval:        10 * time.Millisecond,
		MetricsConsumer: testMetricsConsumer(metricRecords),
	}
	ctxInfo := &global.ContextInfo{
		NodeMeta:            meta.NodeMeta{HostID: "test-host"},
		OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: mcfg},
	}

	reporter, err := NewInternalMetricsReporter(
		t.Context(),
		ctxInfo,
		mcfg,
		&imetrics.InternalMetricsConfig{
			BpfMetricScrapeInterval: time.Millisecond,
			AvoidedServices:         imetrics.AvoidedServicesConfig{Disabled: true},
		},
	)
	require.NoError(t, err)

	assert.Nil(t, reporter.avoidedServices)
	assert.Nil(t, reporter.avoidedServicesLimiter)

	reporter.AvoidInstrumentationMetrics("svc-0", "ns-0", "inst-0")
}

func readNMetricsByName(
	t require.TestingT,
	inCh <-chan collector.MetricRecord,
	timeout time.Duration,
	name string,
	numRecords int,
) []collector.MetricRecord {
	records := []collector.MetricRecord{}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	for len(records) < numRecords {
		select {
		case item := <-inCh:
			if item.Name == name {
				records = append(records, item)
			}
		case <-deadline.C:
			require.Failf(t, "timeout while waiting for metric records", "missing metric: %s", name)
			return records
		}
	}

	return records
}
