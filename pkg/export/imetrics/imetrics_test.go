// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package imetrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
