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
