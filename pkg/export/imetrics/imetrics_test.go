// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package imetrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/avoidedsvc"
)

func TestIsBuiltinNoopReporter(t *testing.T) {
	t.Run("noop reporter value", func(t *testing.T) {
		assert.True(t, IsBuiltinNoopReporter(NoopReporter{}))
	})

	t.Run("noop reporter pointer", func(t *testing.T) {
		assert.True(t, IsBuiltinNoopReporter(&NoopReporter{}))
	})

	t.Run("prometheus reporter", func(t *testing.T) {
		reporter := NewPrometheusReporter(&InternalMetricsConfig{}, nil, prometheus.NewRegistry())
		assert.False(t, IsBuiltinNoopReporter(reporter))
	})

	t.Run("noop embedder is not builtin noop", func(t *testing.T) {
		reporter := &noopEmbeddingReporter{}
		assert.False(t, IsBuiltinNoopReporter(reporter))
	})

	t.Run("nil reporter", func(t *testing.T) {
		assert.False(t, IsBuiltinNoopReporter(nil))
	})
}

func TestPrometheusReporterQueueBufferUtilization(t *testing.T) {
	reporter := NewPrometheusReporter(&InternalMetricsConfig{}, nil, prometheus.NewRegistry())

	gaugeValue := func(subscriber string) float64 {
		var m dto.Metric
		require.NoError(t, reporter.queueCapacityRatio.WithLabelValues(subscriber).Write(&m))
		return m.GetGauge().GetValue()
	}

	reporter.QueueBufferUtilization("traces", 0.42)
	reporter.QueueBufferUtilization("metrics", 0.1)

	assert.InDelta(t, 0.42, gaugeValue("traces"), 0.001)
	assert.InDelta(t, 0.1, gaugeValue("metrics"), 0.001)

	// a later update overwrites the previous value for the same subscriber
	reporter.QueueBufferUtilization("traces", 0.9)
	assert.InDelta(t, 0.9, gaugeValue("traces"), 0.001)
}

type noopEmbeddingReporter struct {
	NoopReporter
}

func (n *noopEmbeddingReporter) BpfProbeStats(_, _, _ string, _ uint64, _ float64) {}

func TestPrometheusReporterAvoidedServicesBounded(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := NewPrometheusReporter(&InternalMetricsConfig{
		AvoidedServices: AvoidedServicesConfig{Limit: 3},
	}, nil, registry)

	reporter.AvoidInstrumentationMetrics("svc-0", "ns-0", "inst-0")
	reporter.AvoidInstrumentationTraces("svc-0", "ns-0", "inst-0")
	reporter.AvoidInstrumentationMetrics("svc-1", "ns-1", "inst-1")
	reporter.AvoidInstrumentationTraces("svc-1", "ns-1", "inst-1")

	metrics := gatherAvoidedServices(t, registry)
	require.Len(t, metrics, 3)

	labelSets := map[string]struct{}{}
	overflowRecords := 0
	for _, metric := range metrics {
		labels := metricLabels(metric)
		if labels[avoidedsvc.PrometheusOverflowLabel] == "true" {
			overflowRecords++
			assert.Empty(t, labels["service_name"])
			assert.Empty(t, labels["service_namespace"])
			assert.Empty(t, labels["telemetry_type"])
			continue
		}

		assert.Equal(t, "false", labels[avoidedsvc.PrometheusOverflowLabel])
		labelSets[labels["service_name"]+"/"+
			labels["service_namespace"]+"/"+
			labels["telemetry_type"]] = struct{}{}
	}

	assert.Contains(t, labelSets, "svc-0/ns-0/metrics")
	assert.Contains(t, labelSets, "svc-0/ns-0/traces")
	assert.Equal(t, 1, overflowRecords)
}

func TestPrometheusReporterAvoidedServicesDisabled(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := NewPrometheusReporter(&InternalMetricsConfig{
		AvoidedServices: AvoidedServicesConfig{Disabled: true},
	}, nil, registry)

	reporter.AvoidInstrumentationMetrics("svc-0", "ns-0", "inst-0")

	mfs, err := registry.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		assert.NotEqual(t, attr.VendorPrefix+"_avoided_services", mf.GetName())
	}
}

func gatherAvoidedServices(t *testing.T, registry *prometheus.Registry) []*dto.Metric {
	t.Helper()

	mfs, err := registry.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == attr.VendorPrefix+"_avoided_services" {
			return mf.GetMetric()
		}
	}
	require.Fail(t, "missing avoided services metric")
	return nil
}

func metricLabels(metric *dto.Metric) map[string]string {
	labels := map[string]string{}
	for _, pair := range metric.GetLabel() {
		labels[pair.GetName()] = pair.GetValue()
	}
	return labels
}
