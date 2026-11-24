// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package gpuolly turns the samples of the NVML helper into the readings that
// the metric exporters report for the NVIDIA GPUs of the host.
package gpuolly // import "go.opentelemetry.io/obi/pkg/internal/gpuolly"

import (
	"sync/atomic"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/nvml/sample"
)

// Metric describes one of the GPU device metrics.
type Metric struct {
	Name        attributes.Name
	Description string
}

// Metrics lists every GPU device metric that OBI can report.
var Metrics = []Metric{
	{attributes.HWGPUUtilization, "Fraction of time the GPU spent on a task"},
	{attributes.HWGPUMemoryUsage, "GPU memory in use"},
	{attributes.HWGPUMemoryLimit, "Size of the GPU memory"},
	{attributes.HWGPUMemoryUtilization, "Fraction of the GPU memory in use"},
	{attributes.HWPower, "Power that the GPU is drawing"},
	{attributes.HWEnergy, "Energy that the GPU consumed since the driver was loaded"},
	{attributes.HWTemperature, "Temperature of the GPU and of its memory"},
	{attributes.HWTemperatureLimit, "Temperature at which the GPU slows down or shuts down"},
	{attributes.HWErrors, "Memory errors of the GPU during its lifetime"},
	{attributes.HWStatus, "Whether the GPU is in each of its possible states"},
	{attributes.GPUClockFrequency, "Frequency of a clock of the GPU"},
	{attributes.GPUClockThrottled, "Whether a reason is currently limiting the clocks of the GPU"},
	{attributes.GPUMemoryRemappedRows, "Memory rows that the GPU replaced with spare ones"},
	{attributes.GPUMemoryActivity, "Fraction of time the GPU memory was being read or written"},
	{attributes.GPUMemoryReserved, "GPU memory that the driver reserves for itself"},
	{attributes.GPUPCIeReplays, "PCIe packets that the GPU link had to send again"},
	{attributes.GPUXidErrors, "Xid errors that the GPU driver reported since OBI started reading the GPU"},
	{attributes.GPUProcessMemoryUsage, "GPU memory that a process is using"},
	{attributes.GPUProcessUtilization, "Fraction of time the GPU spent on a task of a process"},
}

var metricsByName = func() map[string]attributes.Name {
	byName := make(map[string]attributes.Name, len(Metrics))
	for _, m := range Metrics {
		byName[m.Name.OTEL] = m.Name
	}
	return byName
}()

// Reading is one value of one GPU metric.
type Reading struct {
	Metric attributes.Name
	Value  float64
	Device *Device
	// Kind is the value of the attribute that tells apart the readings of one
	// metric, such as the task of a utilization reading.
	Kind string
	// Process is nil for the readings that describe a whole GPU.
	Process *Process
}

// Device identifies the GPU that a reading belongs to.
type Device struct {
	// ID is the NVML identifier of the GPU, such as "GPU-4dd8a2f9-...".
	ID            string
	Model         string
	DriverVersion string
}

// Process identifies the process that a reading belongs to.
type Process struct {
	PID            uint32
	ExecutableName string
	// Metadata holds the Kubernetes attributes of the process, if any.
	Metadata map[attr.Name]string
}

// Convert turns a sample into readings. resolve identifies the process with a host PID.
func Convert(s *sample.Sample, resolve func(pid uint32) *Process) []Reading {
	var readings []Reading
	for _, dev := range s.Devices {
		device := &Device{ID: dev.UUID, Model: dev.Name, DriverVersion: s.DriverVersion}
		readings = appendReadings(readings, dev.Values, device, nil)
		for _, p := range dev.Processes {
			readings = appendReadings(readings, p.Values, device, resolve(p.PID))
		}
	}
	return readings
}

func appendReadings(readings []Reading, values []sample.Value, device *Device, process *Process) []Reading {
	for _, v := range values {
		if metric, ok := metricsByName[v.Metric]; ok {
			readings = append(readings, Reading{Metric: metric, Value: v.Value, Device: device, Kind: v.Kind, Process: process})
		}
	}
	return readings
}

// Point is the value that an exporter reports for one or more readings.
type Point struct {
	// Reading is the first of the readings that the point merges.
	Reading *Reading
	Value   float64
}

// Group merges the readings of each metric that key maps to the same value,
// because an attribute selection can drop the attributes that tell two
// readings apart. Gauges keep the highest value and the others add up.
func Group[K comparable](readings []Reading, key func(*Reading) K) []Point {
	type groupKey struct {
		section attributes.Section
		key     K
	}

	index := map[groupKey]int{}
	var points []Point
	for i := range readings {
		r := &readings[i]
		k := groupKey{section: r.Metric.Section, key: key(r)}

		at, ok := index[k]
		switch {
		case !ok:
			index[k] = len(points)
			points = append(points, Point{Reading: r, Value: r.Value})
		case r.Metric.Type == attributes.InstrumentGauge:
			points[at].Value = max(points[at].Value, r.Value)
		default:
			points[at].Value += r.Value
		}
	}
	return points
}

// Snapshot holds the readings of the most recent sample, so that exporters can
// report them whenever they are collected.
type Snapshot struct {
	readings atomic.Pointer[[]Reading]
}

func (s *Snapshot) Store(readings []Reading) {
	s.readings.Store(&readings)
}

func (s *Snapshot) Load() []Reading {
	if readings := s.readings.Load(); readings != nil {
		return *readings
	}
	return nil
}
