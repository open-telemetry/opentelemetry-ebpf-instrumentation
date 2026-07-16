// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestGoRuntimeCPUTimeCounterDeltaResetAndRemoval(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := newGoRuntimeMetricsCollector(nil)
	registry.MustRegister(collector.cpuTime)

	cpu := &runtimemetrics.GoRuntimeCPUTimeSnapshot{UserTime: 100}
	collector.collectCPUTime(nil, cpu)
	assertGoRuntimeCPUTime(t, registry, 100)

	cpu.UserTime = 250
	collector.collectCPUTime(nil, cpu)
	assertGoRuntimeCPUTime(t, registry, 250)

	cpu.UserTime = 50
	collector.collectCPUTime(nil, cpu)
	assertGoRuntimeCPUTime(t, registry, 50)

	collector.collectCPUTime(nil, nil)
	assert.Nil(t, gatheredMetric(t, registry, attributes.GoRuntimeCPUTime.Prom, map[string]string{
		"go_cpu_state":          "user",
		"go_cpu_detailed_state": "",
	}))
}

func TestGoRuntimeGCCyclesCounterDeltaResetAndRemoval(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := newGoRuntimeMetricsCollector(nil)
	registry.MustRegister(collector.memoryGCCycles)

	for _, value := range []uint64{10, 15, 2} {
		collector.addGCCycles(nil, value)
		metric := gatheredMetric(t, registry, attributes.GoRuntimeMemoryGCCycles.Prom, nil)
		require.NotNil(t, metric)
		assert.InDelta(t, float64(value), metric.GetCounter().GetValue(), 0)
	}

	collector.deleteGCCycles(nil)
	assert.Nil(t, gatheredMetric(t, registry, attributes.GoRuntimeMemoryGCCycles.Prom, nil))
}

func assertGoRuntimeCPUTime(t *testing.T, registry *prometheus.Registry, nanoseconds int64) {
	t.Helper()

	metric := gatheredMetric(t, registry, attributes.GoRuntimeCPUTime.Prom, map[string]string{
		"go_cpu_state":          "user",
		"go_cpu_detailed_state": "",
	})
	require.NotNil(t, metric)
	assert.InDelta(t, float64(nanoseconds)/float64(time.Second), metric.GetCounter().GetValue(), 1e-12)
}
