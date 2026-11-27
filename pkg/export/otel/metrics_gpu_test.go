// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	"go.opentelemetry.io/obi/pkg/internal/gpuolly"
)

func gpuTestReadings() []gpuolly.Reading {
	first := &gpuolly.Device{ID: "GPU-aaaa", Model: "Tesla T4", DriverVersion: "570.86.15"}
	second := &gpuolly.Device{ID: "GPU-bbbb", Model: "Tesla T4", DriverVersion: "570.86.15"}
	process := &gpuolly.Process{
		PID:            4242,
		ExecutableName: "trainer",
		Metadata:       map[attr.Name]string{attr.K8sPodName: "trainer-0"},
	}

	return []gpuolly.Reading{
		{Metric: attributes.HWGPUUtilization, Kind: "general", Value: 0.75, Device: first},
		{Metric: attributes.HWGPUUtilization, Kind: "general", Value: 0.25, Device: second},
		{Metric: attributes.HWEnergy, Value: 100, Device: first},
		{Metric: attributes.HWEnergy, Value: 50, Device: second},
		{Metric: attributes.HWGPUMemoryUsage, Value: 2048, Device: first},
		{Metric: attributes.GPUProcessMemoryUsage, Value: 1024, Device: first, Process: process},
	}
}

func collectGPUMetrics(
	t *testing.T, groups attributes.AttrGroups, selection attributes.Selection, snapshot *gpuolly.Snapshot,
) map[string]metricdata.Metrics {
	t.Helper()

	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })

	attrProv, err := attributes.NewAttrSelector(groups, &attributes.SelectorConfig{SelectionCfg: selection})
	require.NoError(t, err)
	require.NoError(t, observeGPUMetrics(provider.Meter(gpuScopeName), attrProv, snapshot))

	var collected metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &collected))

	byName := map[string]metricdata.Metrics{}
	for _, scope := range collected.ScopeMetrics {
		for _, m := range scope.Metrics {
			byName[m.Name] = m
		}
	}

	return byName
}

func gpuAttr(t *testing.T, point metricdata.DataPoint[float64], key string) attribute.Value {
	t.Helper()

	value, ok := point.Attributes.Value(attribute.Key(key))
	require.True(t, ok, "attribute %s", key)

	return value
}

func TestGPUMetricsReportReadings(t *testing.T) {
	var groups attributes.AttrGroups
	groups.Add(attributes.GroupKubernetes)

	snapshot := &gpuolly.Snapshot{}
	snapshot.Store(gpuTestReadings())

	metrics := collectGPUMetrics(t, groups, attributes.Selection{}, snapshot)

	utilization, ok := metrics["hw.gpu.utilization"].Data.(metricdata.Gauge[float64])
	require.True(t, ok)
	require.Len(t, utilization.DataPoints, 2)
	assert.Equal(t, "1", metrics["hw.gpu.utilization"].Unit)
	for _, point := range utilization.DataPoints {
		assert.Equal(t, "general", gpuAttr(t, point, "hw.gpu.task").AsString())
		assert.Equal(t, "Tesla T4", gpuAttr(t, point, "hw.model").AsString())
	}

	// The metrics that exist for any hardware component say that theirs is a GPU.
	energy, ok := metrics["hw.energy"].Data.(metricdata.Sum[float64])
	require.True(t, ok)
	assert.True(t, energy.IsMonotonic)
	require.Len(t, energy.DataPoints, 2)
	for _, point := range energy.DataPoints {
		assert.Equal(t, "gpu", gpuAttr(t, point, "hw.type").AsString())
	}

	memory, ok := metrics["hw.gpu.memory.usage"].Data.(metricdata.Sum[float64])
	require.True(t, ok)
	assert.False(t, memory.IsMonotonic)
	require.Len(t, memory.DataPoints, 1)
	assert.InDelta(t, 2048.0, memory.DataPoints[0].Value, 1e-9)

	processMemory, ok := metrics["gpu.process.memory.usage"].Data.(metricdata.Sum[float64])
	require.True(t, ok)
	require.Len(t, processMemory.DataPoints, 1)
	assert.Equal(t, int64(4242), gpuAttr(t, processMemory.DataPoints[0], "process.pid").AsInt64())
	assert.Equal(t, "trainer", gpuAttr(t, processMemory.DataPoints[0], "process.executable.name").AsString())
	assert.Equal(t, "trainer-0", gpuAttr(t, processMemory.DataPoints[0], "k8s.pod.name").AsString())
}

// Removing the attribute that identifies the GPU leaves two readings with the
// same attributes, which must be reported as a single data point.
func TestGPUMetricsMergeIndistinguishableReadings(t *testing.T) {
	snapshot := &gpuolly.Snapshot{}
	snapshot.Store(gpuTestReadings())

	metrics := collectGPUMetrics(t, attributes.AttrGroups(0), attributes.Selection{
		attributes.HWGPUUtilization.Section: attributes.InclusionLists{Exclude: []string{"hw.id"}},
		attributes.HWEnergy.Section:         attributes.InclusionLists{Exclude: []string{"hw.id"}},
	}, snapshot)

	utilization, ok := metrics["hw.gpu.utilization"].Data.(metricdata.Gauge[float64])
	require.True(t, ok)
	require.Len(t, utilization.DataPoints, 1)
	assert.InDelta(t, 0.75, utilization.DataPoints[0].Value, 1e-9)

	energy, ok := metrics["hw.energy"].Data.(metricdata.Sum[float64])
	require.True(t, ok)
	require.Len(t, energy.DataPoints, 1)
	assert.InDelta(t, 150.0, energy.DataPoints[0].Value, 1e-9)
}

// The readings of a GPU or a process that went away must stop being reported.
func TestGPUMetricsDropReadingsThatDisappear(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })

	attrProv, err := attributes.NewAttrSelector(attributes.AttrGroups(0), &attributes.SelectorConfig{SelectionCfg: attributes.Selection{}})
	require.NoError(t, err)

	snapshot := &gpuolly.Snapshot{}
	snapshot.Store(gpuTestReadings())
	require.NoError(t, observeGPUMetrics(provider.Meter(gpuScopeName), attrProv, snapshot))

	points := func() int {
		var collected metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(t.Context(), &collected))

		count := 0
		for _, scope := range collected.ScopeMetrics {
			for _, m := range scope.Metrics {
				if gauge, ok := m.Data.(metricdata.Gauge[float64]); ok && m.Name == "hw.gpu.utilization" {
					count += len(gauge.DataPoints)
				}
			}
		}

		return count
	}

	assert.Equal(t, 2, points())

	snapshot.Store(gpuTestReadings()[:1])
	assert.Equal(t, 1, points())

	snapshot.Store(nil)
	assert.Equal(t, 0, points())
}
