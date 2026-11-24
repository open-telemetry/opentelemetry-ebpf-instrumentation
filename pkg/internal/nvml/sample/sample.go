// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package sample defines what the NVML helper process sends to OBI: one JSON
// encoded Sample per line on its standard output.
package sample // import "go.opentelemetry.io/obi/pkg/internal/nvml/sample"

// ExitNoLibrary is the exit status of the helper when the host has no NVML library.
const ExitNoLibrary = 2

// Sample is the state of every NVIDIA GPU of the host at one point in time.
type Sample struct {
	DriverVersion string   `json:"driver_version,omitempty"`
	Devices       []Device `json:"devices"`
}

// Device holds the metric values of one GPU and of the processes that use it.
type Device struct {
	// UUID is the NVML device identifier, including its "GPU-" prefix.
	UUID      string    `json:"uuid"`
	Name      string    `json:"name,omitempty"`
	Values    []Value   `json:"values,omitempty"`
	Processes []Process `json:"processes,omitempty"`
}

// Process holds the metric values of one process, identified by its host PID.
type Process struct {
	PID    uint32  `json:"pid"`
	Values []Value `json:"values,omitempty"`
}

// Value is one value of one metric, in the unit of the metric.
type Value struct {
	// Metric is the OpenTelemetry name of the metric, such as "hw.power".
	Metric string `json:"metric"`
	// Kind is the value of the attribute that tells apart the values of one
	// metric, such as the task of a utilization. It is empty for metrics without one.
	Kind  string  `json:"kind,omitempty"`
	Value float64 `json:"value"`
}
