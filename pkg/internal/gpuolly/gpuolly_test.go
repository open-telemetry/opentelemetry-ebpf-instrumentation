// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpuolly

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/nvml/sample"
)

func testSample() *sample.Sample {
	return &sample.Sample{
		DriverVersion: "570.86.15",
		Devices: []sample.Device{{
			UUID: "GPU-aaaa",
			Name: "Tesla T4",
			Values: []sample.Value{
				{Metric: "hw.power", Value: 68.5},
				{Metric: "hw.gpu.utilization", Kind: "general", Value: 0.75},
				{Metric: "some.future.metric", Value: 1},
			},
			Processes: []sample.Process{{PID: 4242, Values: []sample.Value{{Metric: "gpu.process.memory.usage", Value: 1024}}}},
		}},
	}
}

func testResolve(pid uint32) *Process {
	return &Process{PID: pid, ExecutableName: "trainer", Metadata: map[attr.Name]string{attr.K8sPodName: "trainer-0"}}
}

func TestConvert(t *testing.T) {
	readings := Convert(testSample(), testResolve)

	// A metric that OBI does not know is dropped.
	require.Len(t, readings, 3)

	device := &Device{ID: "GPU-aaaa", Model: "Tesla T4", DriverVersion: "570.86.15"}
	assert.Equal(t, Reading{Metric: attributes.HWPower, Value: 68.5, Device: device}, readings[0])
	assert.Equal(t, Reading{Metric: attributes.HWGPUUtilization, Value: 0.75, Device: device, Kind: "general"}, readings[1])
	assert.Equal(t, Reading{Metric: attributes.GPUProcessMemoryUsage, Value: 1024, Device: device, Process: testResolve(4242)}, readings[2])

	assert.Empty(t, Convert(&sample.Sample{}, testResolve))
}

func TestGroup(t *testing.T) {
	readings := []Reading{
		{Metric: attributes.HWGPUUtilization, Value: 0.2},
		{Metric: attributes.HWEnergy, Value: 100},
		{Metric: attributes.HWGPUUtilization, Value: 0.8},
		{Metric: attributes.HWEnergy, Value: 50},
		{Metric: attributes.HWEnergy, Value: 7, Kind: "other"},
	}

	points := Group(readings, func(r *Reading) string { return r.Kind })
	require.Len(t, points, 3)

	// Gauges keep the highest value, the other instruments add up, and the
	// readings of different metrics or keys stay apart.
	assert.InDelta(t, 0.8, points[0].Value, 1e-9)
	assert.InDelta(t, 150.0, points[1].Value, 1e-9)
	assert.InDelta(t, 7.0, points[2].Value, 1e-9)
	assert.Same(t, &readings[0], points[0].Reading)
}

func TestSnapshot(t *testing.T) {
	snapshot := &Snapshot{}
	assert.Empty(t, snapshot.Load())

	snapshot.Store([]Reading{{Metric: attributes.HWPower, Value: 1}})
	assert.Len(t, snapshot.Load(), 1)

	snapshot.Store(nil)
	assert.Empty(t, snapshot.Load())
}

func TestGetters(t *testing.T) {
	readings := Convert(testSample(), testResolve)
	device, process := &readings[1], &readings[2]

	for name, expected := range map[attr.Name]string{
		attr.HWID:                  "GPU-aaaa",
		attr.HWType:                "gpu",
		attr.HWModel:               "Tesla T4",
		attr.HWVendor:              "nvidia",
		attr.HWDriverVersion:       "570.86.15",
		attr.HWGPUTask:             "general",
		attr.ProcessExecutableName: "",
		attr.K8sPodName:            "",
	} {
		get, ok := StringGetters(name)
		require.True(t, ok)
		assert.Equal(t, expected, get(device), "attribute %s of a device reading", name)
	}

	for name, expected := range map[attr.Name]string{
		attr.ProcessPID:            "4242",
		attr.ProcessExecutableName: "trainer",
		attr.K8sPodName:            "trainer-0",
	} {
		get, ok := StringGetters(name)
		require.True(t, ok)
		assert.Equal(t, expected, get(process), "attribute %s of a process reading", name)
	}

	pid, ok := Getters(attr.ProcessPID)
	require.True(t, ok)
	assert.Equal(t, int64(4242), pid(process).Value.AsInt64())
}
