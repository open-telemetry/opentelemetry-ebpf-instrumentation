// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/gpuolly"
)

func gpuTestReadings() []gpuolly.Reading {
	first := &gpuolly.Device{ID: "GPU-aaaa", Model: "Tesla T4", DriverVersion: "570.86.15"}
	second := &gpuolly.Device{ID: "GPU-bbbb", Model: "Tesla T4", DriverVersion: "570.86.15"}
	process := &gpuolly.Process{
		PID:            4242,
		ExecutableName: "trainer",
		Metadata:       map[attr.Name]string{attr.K8sPodName: "trainer-0", attr.K8sNamespaceName: "ml"},
	}

	return []gpuolly.Reading{
		{Metric: attributes.HWGPUUtilization, Kind: "general", Value: 0.75, Device: first},
		{Metric: attributes.HWGPUUtilization, Kind: "general", Value: 0.25, Device: second},
		{Metric: attributes.HWEnergy, Value: 100, Device: first},
		{Metric: attributes.HWEnergy, Value: 50, Device: second},
		{Metric: attributes.GPUProcessMemoryUsage, Value: 1024, Device: first, Process: process},
	}
}

func gatherGPUMetrics(t *testing.T, groups attributes.AttrGroups, selection attributes.Selection) map[string]*dto.MetricFamily {
	t.Helper()

	snapshot := &gpuolly.Snapshot{}
	snapshot.Store(gpuTestReadings())

	collector, err := newGPUCollector(groups, &attributes.SelectorConfig{SelectionCfg: selection}, snapshot)
	require.NoError(t, err)

	registry := prometheus.NewRegistry()
	require.NoError(t, registry.Register(collector))

	families, err := registry.Gather()
	require.NoError(t, err)

	byName := make(map[string]*dto.MetricFamily, len(families))
	for _, family := range families {
		byName[family.GetName()] = family
	}

	return byName
}

func gpuLabels(m *dto.Metric) map[string]string {
	labels := make(map[string]string, len(m.GetLabel()))
	for _, label := range m.GetLabel() {
		labels[label.GetName()] = label.GetValue()
	}

	return labels
}

func TestGPUCollectorReportsReadings(t *testing.T) {
	var groups attributes.AttrGroups
	groups.Add(attributes.GroupKubernetes)

	families := gatherGPUMetrics(t, groups, attributes.Selection{})

	utilization := families["hw_gpu_utilization_ratio"]
	require.NotNil(t, utilization)
	assert.Equal(t, dto.MetricType_GAUGE, utilization.GetType())
	require.Len(t, utilization.GetMetric(), 2)
	for _, m := range utilization.GetMetric() {
		labels := gpuLabels(m)
		assert.Equal(t, "Tesla T4", labels["hw_model"])
		assert.Equal(t, "general", labels["hw_gpu_task"])
		assert.Contains(t, []string{"GPU-aaaa", "GPU-bbbb"}, labels["hw_id"])
	}

	energy := families["hw_energy_joules_total"]
	require.NotNil(t, energy)
	assert.Equal(t, dto.MetricType_COUNTER, energy.GetType())
	require.Len(t, energy.GetMetric(), 2)
	// The metrics that exist for any hardware component say that theirs is a GPU.
	for _, m := range energy.GetMetric() {
		assert.Equal(t, "gpu", gpuLabels(m)["hw_type"])
	}

	memory := families["gpu_process_memory_usage_bytes"]
	require.NotNil(t, memory)
	require.Len(t, memory.GetMetric(), 1)
	labels := gpuLabels(memory.GetMetric()[0])
	assert.Equal(t, "4242", labels["process_pid"])
	assert.Equal(t, "trainer", labels["process_executable_name"])
	assert.Equal(t, "trainer-0", labels["k8s_pod_name"])
	assert.Equal(t, "ml", labels["k8s_namespace_name"])
	assert.InDelta(t, 1024.0, memory.GetMetric()[0].GetGauge().GetValue(), 1e-9)
}

func TestGPUCollectorOmitsKubernetesLabelsOutsideKubernetes(t *testing.T) {
	families := gatherGPUMetrics(t, attributes.AttrGroups(0), attributes.Selection{})

	memory := families["gpu_process_memory_usage_bytes"]
	require.NotNil(t, memory)
	require.Len(t, memory.GetMetric(), 1)
	assert.NotContains(t, gpuLabels(memory.GetMetric()[0]), "k8s_pod_name")
}

// Removing the label that identifies the GPU leaves two readings with the same
// labels, which must be reported as a single series.
func TestGPUCollectorMergesIndistinguishableReadings(t *testing.T) {
	families := gatherGPUMetrics(t, attributes.AttrGroups(0), attributes.Selection{
		attributes.HWGPUUtilization.Section: attributes.InclusionLists{Exclude: []string{"hw.id"}},
		attributes.HWEnergy.Section:         attributes.InclusionLists{Exclude: []string{"hw.id"}},
	})

	utilization := families["hw_gpu_utilization_ratio"]
	require.NotNil(t, utilization)
	require.Len(t, utilization.GetMetric(), 1)
	assert.InDelta(t, 0.75, utilization.GetMetric()[0].GetGauge().GetValue(), 1e-9)

	energy := families["hw_energy_joules_total"]
	require.NotNil(t, energy)
	require.Len(t, energy.GetMetric(), 1)
	assert.InDelta(t, 150.0, energy.GetMetric()[0].GetCounter().GetValue(), 1e-9)
}

func TestGPUCollectorReportsNothingWithoutReadings(t *testing.T) {
	collector, err := newGPUCollector(attributes.AttrGroups(0), &attributes.SelectorConfig{SelectionCfg: attributes.Selection{}}, &gpuolly.Snapshot{})
	require.NoError(t, err)

	registry := prometheus.NewRegistry()
	require.NoError(t, registry.Register(collector))

	families, err := registry.Gather()
	require.NoError(t, err)
	assert.Empty(t, families)
}
