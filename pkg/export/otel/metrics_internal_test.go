// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/collector"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
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

	reporter.BpfProbeStats("7", "kprobe", "tcp_connect", 3, 0.75)

	records := readMetricsByName(t, metricRecords, time.Second,
		attr.VendorPrefix+".bpf.probe.executions",
		attr.VendorPrefix+".bpf.probe.latency_seconds_total",
	)
	assert.Len(t, records, 2)

	expected := map[string]collector.MetricRecord{
		attr.VendorPrefix + ".bpf.probe.executions": {
			IntVal: 3,
		},
		attr.VendorPrefix + ".bpf.probe.latency_seconds_total": {
			FloatVal: 0.75,
		},
	}

	for _, record := range records {
		assert.Equal(t, "7", record.Attributes["bpf.probe.id"])
		assert.Equal(t, "kprobe", record.Attributes["bpf.probe.type"])
		assert.Equal(t, "tcp_connect", record.Attributes["bpf.probe.name"])

		want, ok := expected[record.Name]
		require.True(t, ok, "unexpected metric %q", record.Name)
		if record.Name == attr.VendorPrefix+".bpf.probe.executions" {
			assert.Equal(t, want.IntVal, record.IntVal)
		} else {
			assert.Equal(t, want.FloatVal, record.FloatVal)
		}
		delete(expected, record.Name)
	}

	assert.Empty(t, expected)
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
