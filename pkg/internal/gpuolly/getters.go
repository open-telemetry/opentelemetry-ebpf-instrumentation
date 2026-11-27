// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpuolly // import "go.opentelemetry.io/obi/pkg/internal/gpuolly"

import (
	"strconv"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

const (
	hardwareTypeGPU = "gpu"
	vendorNVIDIA    = "nvidia"
)

// StringGetters returns the function that reads the given attribute of a
// Reading as a string, for the Prometheus exporter.
func StringGetters(name attr.Name) (attributes.Getter[*Reading, string], bool) {
	switch name {
	case attr.HWID:
		return func(r *Reading) string { return r.Device.ID }, true
	case attr.HWType:
		return func(*Reading) string { return hardwareTypeGPU }, true
	case attr.HWModel:
		return func(r *Reading) string { return r.Device.Model }, true
	case attr.HWVendor:
		return func(*Reading) string { return vendorNVIDIA }, true
	case attr.HWDriverVersion:
		return func(r *Reading) string { return r.Device.DriverVersion }, true
	case attr.HWGPUTask, attr.HWState, attr.HWLimitType, attr.HWSensorLocation, attr.ErrorType,
		attr.GPUClockType, attr.GPUClockThrottleReason, attr.GPUXidCode:
		return func(r *Reading) string { return r.Kind }, true
	case attr.ProcessPID:
		return func(r *Reading) string { return strconv.FormatUint(uint64(r.process().PID), 10) }, true
	case attr.ProcessExecutableName:
		return func(r *Reading) string { return r.process().ExecutableName }, true
	default:
		return func(r *Reading) string { return r.process().Metadata[name] }, true
	}
}

// Getters returns the function that reads the given attribute of a Reading,
// for the OpenTelemetry exporter.
func Getters(name attr.Name) (attributes.Getter[*Reading, attribute.KeyValue], bool) {
	key := name.OTEL()

	if name == attr.ProcessPID {
		return func(r *Reading) attribute.KeyValue { return key.Int64(int64(r.process().PID)) }, true
	}

	get, ok := StringGetters(name)

	return func(r *Reading) attribute.KeyValue { return key.String(get(r)) }, ok
}

var noProcess = &Process{}

func (r *Reading) process() *Process {
	if r.Process == nil {
		return noProcess
	}

	return r.Process
}
