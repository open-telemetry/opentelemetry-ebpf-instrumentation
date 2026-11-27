// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"

	"github.com/ebitengine/purego"
)

const (
	libraryName = "libnvidia-ml.so.1"

	// Host path where the NVIDIA GPU Operator exposes the driver files, which the loader does not search.
	operatorDriverRoot = "/run/nvidia/driver"
)

var errNoLibrary = errors.New("loading " + libraryName)

// NVML return codes, from nvmlReturn_t.
const (
	nvmlSuccess          = 0
	nvmlNotSupported     = 3
	nvmlNotFound         = 6
	nvmlInsufficientSize = 7
)

type nvmlUtilization struct {
	gpu    uint32
	memory uint32
}

type nvmlMemory struct {
	total uint64
	_     uint64
	used  uint64
}

type nvmlMemoryV2 struct {
	version  uint32
	_        uint32
	total    uint64
	reserved uint64
	_        uint64
	used     uint64
}

type nvmlProcessInfo struct {
	pid           uint32
	_             uint32
	usedGPUMemory uint64
	_             [2]uint32
}

type nvmlProcessUtilization struct {
	pid       uint32
	_         uint32
	timestamp uint64
	smUtil    uint32
	_         uint32
	encUtil   uint32
	decUtil   uint32
}

type nvmlFieldValue struct {
	fieldID    uint32
	_          uint32
	_          [2]int64
	valueType  uint32
	nvmlReturn int32
	value      uint64
}

type nvmlEventData struct {
	device    uintptr
	eventType uint64
	eventData uint64
	_         [2]uint32
}

// library holds the NVML functions the helper calls. The nvml tag of each
// function lists the symbols that implement it, newest first. Old drivers lack
// some optional functions, which then report that NVML does not support them.
type library struct {
	Init         func() int32                                         `nvml:"nvmlInit_v2" required:"true"`
	Shutdown     func() int32                                         `nvml:"nvmlShutdown" required:"true"`
	ErrorString  func(code int32) string                              `nvml:"nvmlErrorString" required:"true"`
	DeviceCount  func(count *uint32) int32                            `nvml:"nvmlDeviceGetCount_v2" required:"true"`
	DeviceHandle func(index uint32, device *uintptr) int32            `nvml:"nvmlDeviceGetHandleByIndex_v2" required:"true"`
	DeviceUUID   func(device uintptr, buf *byte, length uint32) int32 `nvml:"nvmlDeviceGetUUID" required:"true"`

	DriverVersion        func(buf *byte, length uint32) int32                                                     `nvml:"nvmlSystemGetDriverVersion"`
	DeviceName           func(device uintptr, buf *byte, length uint32) int32                                     `nvml:"nvmlDeviceGetName"`
	UtilizationRates     func(device uintptr, utilization *nvmlUtilization) int32                                 `nvml:"nvmlDeviceGetUtilizationRates"`
	EncoderUtilization   func(device uintptr, utilization, samplingPeriod *uint32) int32                          `nvml:"nvmlDeviceGetEncoderUtilization"`
	DecoderUtilization   func(device uintptr, utilization, samplingPeriod *uint32) int32                          `nvml:"nvmlDeviceGetDecoderUtilization"`
	MemoryInfo           func(device uintptr, memory *nvmlMemory) int32                                           `nvml:"nvmlDeviceGetMemoryInfo"`
	MemoryInfoV2         func(device uintptr, memory *nvmlMemoryV2) int32                                         `nvml:"nvmlDeviceGetMemoryInfo_v2"`
	PowerUsage           func(device uintptr, milliwatts *uint32) int32                                           `nvml:"nvmlDeviceGetPowerUsage"`
	TotalEnergy          func(device uintptr, millijoules *uint64) int32                                          `nvml:"nvmlDeviceGetTotalEnergyConsumption"`
	Temperature          func(device uintptr, sensor int32, celsius *uint32) int32                                `nvml:"nvmlDeviceGetTemperature"`
	TemperatureThreshold func(device uintptr, threshold int32, celsius *uint32) int32                             `nvml:"nvmlDeviceGetTemperatureThreshold"`
	ClockInfo            func(device uintptr, clock int32, megahertz *uint32) int32                               `nvml:"nvmlDeviceGetClockInfo"`
	ThrottleReasons      func(device uintptr, reasons *uint64) int32                                              `nvml:"nvmlDeviceGetCurrentClocksEventReasons,nvmlDeviceGetCurrentClocksThrottleReasons"`
	ECCErrors            func(device uintptr, errorType, counterType int32, count *uint64) int32                  `nvml:"nvmlDeviceGetTotalEccErrors"`
	PCIeReplays          func(device uintptr, count *uint32) int32                                                `nvml:"nvmlDeviceGetPcieReplayCounter"`
	FieldValues          func(device uintptr, count int32, values *nvmlFieldValue) int32                          `nvml:"nvmlDeviceGetFieldValues"`
	RemappedRows         func(device uintptr, corrected, uncorrected, pending, failed *uint32) int32              `nvml:"nvmlDeviceGetRemappedRows"`
	ComputeProcesses     func(device uintptr, count *uint32, infos *nvmlProcessInfo) int32                        `nvml:"nvmlDeviceGetComputeRunningProcesses_v3,nvmlDeviceGetComputeRunningProcesses_v2"`
	ProcessUtilization   func(device uintptr, samples *nvmlProcessUtilization, count *uint32, since uint64) int32 `nvml:"nvmlDeviceGetProcessUtilization"`
	EventSetCreate       func(set *uintptr) int32                                                                 `nvml:"nvmlEventSetCreate"`
	RegisterEvents       func(device uintptr, eventTypes uint64, set uintptr) int32                               `nvml:"nvmlDeviceRegisterEvents"`
	EventSetWait         func(set uintptr, data *nvmlEventData, timeoutMillis uint32) int32                       `nvml:"nvmlEventSetWait_v2"`
}

// openLibrary looks in the loader search path first, then in the driver files of the NVIDIA GPU Operator.
func openLibrary() (*library, error) {
	multiarch := "x86_64-linux-gnu"
	if runtime.GOARCH == "arm64" {
		multiarch = "aarch64-linux-gnu"
	}

	var errs []error
	for _, path := range []string{
		libraryName,
		operatorDriverRoot + "/usr/lib/" + multiarch + "/" + libraryName,
		operatorDriverRoot + "/usr/lib64/" + libraryName,
	} {
		handle, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err == nil {
			return bindLibrary(func(symbol string) uintptr {
				addr, _ := purego.Dlsym(handle, symbol)
				return addr
			})
		}
		errs = append(errs, err)
	}

	return nil, fmt.Errorf("%w: %w", errNoLibrary, errors.Join(errs...))
}

// bindLibrary points each function to the first of its symbols that lookup finds.
func bindLibrary(lookup func(symbol string) uintptr) (*library, error) {
	lib := &library{}

	for spec, field := range reflect.ValueOf(lib).Elem().Fields() {
		for symbol := range strings.SplitSeq(spec.Tag.Get("nvml"), ",") {
			if addr := lookup(symbol); addr != 0 {
				purego.RegisterFunc(field.Addr().Interface(), addr)
				break
			}
		}

		if field.IsNil() && spec.Tag.Get("required") != "" {
			return nil, fmt.Errorf("%s does not export %s", libraryName, spec.Tag.Get("nvml"))
		}
	}

	stubMissing(lib)

	return lib, nil
}

// stubMissing makes each function that the library lacks report that NVML does not support it.
func stubMissing(lib *library) {
	notSupported := []reflect.Value{reflect.ValueOf(int32(nvmlNotSupported))}

	for _, field := range reflect.ValueOf(lib).Elem().Fields() {
		if field.IsNil() {
			field.Set(reflect.MakeFunc(field.Type(), func([]reflect.Value) []reflect.Value { return notSupported }))
		}
	}
}

func (l *library) check(operation string, code int32) error {
	if code == nvmlSuccess {
		return nil
	}

	return fmt.Errorf("%s: %s", operation, l.ErrorString(code))
}
