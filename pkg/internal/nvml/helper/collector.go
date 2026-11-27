// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"math"
	"strconv"
	"time"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/internal/nvml/sample"
)

const (
	// Sizes of NVML_DEVICE_UUID_V2_BUFFER_SIZE and NVML_SYSTEM_DRIVER_VERSION_BUFFER_SIZE.
	identityBufferSize      = 96
	driverVersionBufferSize = 80

	// Bounds the Xid events read per sample, so an error storm cannot stall it.
	maxEventsPerSample = 1024

	// NVML reports this instead of a size when the value is not available.
	valueNotAvailable = math.MaxUint64

	memoryInfoV2Version = 2
	structVersionShift  = 24

	// NVML_FI_DEV_MEMORY_TEMP, read through the field values call.
	fieldMemoryTemperature = 82

	eventTypeXidCriticalError = 0x8
)

// NVML enumeration values used as call arguments, and the nvmlValueType_t values the helper reads.
const (
	valueTypeDouble           = 0
	valueTypeUnsignedInt      = 1
	valueTypeUnsignedLongLong = 3
	valueTypeSignedInt        = 5

	temperatureSensorGPU         = 0
	temperatureThresholdShutdown = 0
	temperatureThresholdSlowdown = 1
	clockProcessor               = 1
	clockMemory                  = 2
	memoryErrorCorrected         = 0
	memoryErrorUncorrected       = 1
	eccCounterAggregate          = 1
)

// Factors that convert NVML values to the units of the metrics.
const (
	fromPercent = 0.01
	fromMilli   = 0.001
	fromMHz     = 1e6
	unchanged   = 1
)

// throttleReasons names the NVML clock event reasons that slow a GPU down.
var throttleReasons = []struct {
	mask uint64
	name string
}{
	{0x4, "sw_power_cap"},
	{0x8, "hw_slowdown"},
	{0x10, "sync_boost"},
	{0x20, "sw_thermal_slowdown"},
	{0x40, "hw_thermal_slowdown"},
	{0x80, "hw_power_brake_slowdown"},
}

type device struct {
	handle uintptr
	uuid   string
	name   string
}

type xidKey struct {
	device uintptr
	code   uint64
}

type collector struct {
	lib           *library
	driverVersion string
	devices       []device
	eventSet      uintptr
	// NVML reports Xid errors as events, so the helper counts them.
	xidErrors  map[xidKey]uint64
	lastSample time.Time
}

func newCollector(lib *library) (*collector, error) {
	var count uint32
	if err := lib.check("counting devices", lib.DeviceCount(&count)); err != nil {
		return nil, err
	}

	c := &collector{
		lib:           lib,
		driverVersion: readString(driverVersionBufferSize, lib.DriverVersion),
		xidErrors:     map[xidKey]uint64{},
		lastSample:    time.Now(),
	}
	for index := range count {
		var handle uintptr
		if err := lib.check("opening device", lib.DeviceHandle(index, &handle)); err != nil {
			return nil, err
		}

		dev := device{
			handle: handle,
			uuid:   readString(identityBufferSize, func(b *byte, n uint32) int32 { return lib.DeviceUUID(handle, b, n) }),
			name:   readString(identityBufferSize, func(b *byte, n uint32) int32 { return lib.DeviceName(handle, b, n) }),
		}
		if dev.uuid == "" {
			return nil, fmt.Errorf("reading the UUID of GPU %d", index)
		}
		c.devices = append(c.devices, dev)
	}

	// Without a subscription, no Xid error is counted.
	if lib.EventSetCreate(&c.eventSet) == nvmlSuccess {
		for _, dev := range c.devices {
			lib.RegisterEvents(dev.handle, eventTypeXidCriticalError, c.eventSet)
		}
	}

	return c, nil
}

func (c *collector) sample() sample.Sample {
	now := time.Now()
	c.countXidErrors()

	out := sample.Sample{DriverVersion: c.driverVersion}
	for _, dev := range c.devices {
		out.Devices = append(out.Devices, c.sampleDevice(dev))
	}

	c.lastSample = now

	return out
}

func (c *collector) sampleDevice(dev device) sample.Device {
	lib, h := c.lib, dev.handle
	out := sample.Device{UUID: dev.uuid, Name: dev.name, Processes: c.processes(h)}
	add := appender(&out.Values)

	var (
		utilization                         nvmlUtilization
		encoder, decoder, period            uint32
		power, temperature, slowdown, limit uint32
		replays                             uint32
		processorClock, memoryClock         uint32
		energy, reasons, corrected, uncorr  uint64
	)
	rates := lib.UtilizationRates(h, &utilization)
	add("hw.gpu.utilization", "general", scaled(rates, &utilization.gpu, fromPercent))
	add("gpu.memory.activity", "", scaled(rates, &utilization.memory, fromPercent))
	add("hw.gpu.utilization", "encoder", scaled(lib.EncoderUtilization(h, &encoder, &period), &encoder, fromPercent))
	add("hw.gpu.utilization", "decoder", scaled(lib.DecoderUtilization(h, &decoder, &period), &decoder, fromPercent))

	used, reserved, total := c.memory(h)
	add("hw.gpu.memory.usage", "", used)
	add("gpu.memory.reserved", "", reserved)
	add("hw.gpu.memory.limit", "", total)
	if used != nil && *total > 0 {
		add("hw.gpu.memory.utilization", "", new(*used / *total))
	}

	add("hw.power", "", scaled(lib.PowerUsage(h, &power), &power, fromMilli))
	add("hw.energy", "", scaled(lib.TotalEnergy(h, &energy), &energy, fromMilli))
	add("hw.temperature", "gpu", scaled(lib.Temperature(h, temperatureSensorGPU, &temperature), &temperature, unchanged))
	add("hw.temperature", "memory", c.memoryTemperature(h))
	add("hw.temperature.limit", "high.degraded", scaled(lib.TemperatureThreshold(h, temperatureThresholdSlowdown, &slowdown), &slowdown, unchanged))
	add("hw.temperature.limit", "high.critical", scaled(lib.TemperatureThreshold(h, temperatureThresholdShutdown, &limit), &limit, unchanged))
	add("gpu.clock.frequency", "processor", scaled(lib.ClockInfo(h, clockProcessor, &processorClock), &processorClock, fromMHz))
	add("gpu.clock.frequency", "memory", scaled(lib.ClockInfo(h, clockMemory, &memoryClock), &memoryClock, fromMHz))

	if lib.ThrottleReasons(h, &reasons) == nvmlSuccess {
		for _, reason := range throttleReasons {
			add("gpu.clock.throttled", reason.name, state(reasons&reason.mask != 0))
		}
	}

	add("hw.errors", "corrected", scaled(lib.ECCErrors(h, memoryErrorCorrected, eccCounterAggregate, &corrected), &corrected, unchanged))
	add("hw.errors", "uncorrected", scaled(lib.ECCErrors(h, memoryErrorUncorrected, eccCounterAggregate, &uncorr), &uncorr, unchanged))
	add("gpu.pcie.replays", "", scaled(lib.PCIeReplays(h, &replays), &replays, unchanged))

	// A GPU that does not remap rows has no known memory fault, so it is reported as healthy.
	var rowsCorrected, rowsUncorrected, pending, failed uint32
	rows := lib.RemappedRows(h, &rowsCorrected, &rowsUncorrected, &pending, &failed)
	add("gpu.memory.remapped_rows", "corrected", scaled(rows, &rowsCorrected, unchanged))
	add("gpu.memory.remapped_rows", "uncorrected", scaled(rows, &rowsUncorrected, unchanged))
	add("hw.status", "failed", state(failed != 0))
	add("hw.status", "predicted_failure", state(pending != 0 && failed == 0))
	add("hw.status", "ok", state(pending == 0 && failed == 0))

	for key, count := range c.xidErrors {
		if key.device == h {
			add("gpu.xid.errors", strconv.FormatUint(key.code, 10), new(float64(count)))
		}
	}

	return out
}

// memory prefers the newer call because the older one counts the memory the
// driver reserves for itself as used, and does not report the reserved memory.
func (c *collector) memory(h uintptr) (used, reserved, total *float64) {
	v2 := nvmlMemoryV2{version: uint32(unsafe.Sizeof(nvmlMemoryV2{})) | memoryInfoV2Version<<structVersionShift}
	if code := c.lib.MemoryInfoV2(h, &v2); code == nvmlSuccess {
		return scaled(code, &v2.used, unchanged), scaled(code, &v2.reserved, unchanged), scaled(code, &v2.total, unchanged)
	}

	var v1 nvmlMemory
	code := c.lib.MemoryInfo(h, &v1)

	return scaled(code, &v1.used, unchanged), nil, scaled(code, &v1.total, unchanged)
}

// memoryTemperature returns nil for GPUs that do not report it, such as most GPUs with GDDR memory.
func (c *collector) memoryTemperature(h uintptr) *float64 {
	field := nvmlFieldValue{fieldID: fieldMemoryTemperature}
	if c.lib.FieldValues(h, 1, &field) != nvmlSuccess || field.nvmlReturn != nvmlSuccess {
		return nil
	}

	// nvmlValue_t is a union whose member the value type selects.
	switch field.valueType {
	case valueTypeUnsignedInt:
		return new(float64(uint32(field.value)))
	case valueTypeSignedInt:
		return new(float64(int32(uint32(field.value))))
	case valueTypeUnsignedLongLong:
		return new(float64(field.value))
	case valueTypeDouble:
		return new(math.Float64frombits(field.value))
	default:
		return nil
	}
}

func (c *collector) processes(h uintptr) []sample.Process {
	utilizations, perProcess := c.processUtilizations(h)

	var out []sample.Process
	for _, info := range c.processInfos(h) {
		process := sample.Process{PID: info.pid}
		add := appender(&process.Values)

		if info.usedGPUMemory != valueNotAvailable {
			add("gpu.process.memory.usage", "", new(float64(info.usedGPUMemory)))
		}

		// A process without a utilization entry did not use the GPU since the previous sample.
		if perProcess {
			u := utilizations[info.pid]
			add("gpu.process.utilization", "general", new(float64(u.smUtil)*fromPercent))
			add("gpu.process.utilization", "encoder", new(float64(u.encUtil)*fromPercent))
			add("gpu.process.utilization", "decoder", new(float64(u.decUtil)*fromPercent))
		}

		out = append(out, process)
	}

	return out
}

func (c *collector) processInfos(h uintptr) []nvmlProcessInfo {
	var count uint32
	if c.lib.ComputeProcesses(h, &count, nil) != nvmlInsufficientSize {
		return nil
	}

	// Leaves room for the processes that start between the two calls.
	count *= 2
	infos := make([]nvmlProcessInfo, count)
	if c.lib.ComputeProcesses(h, &count, &infos[0]) != nvmlSuccess {
		return nil
	}

	return infos[:count]
}

// processUtilizations returns the utilization of the processes that used the
// GPU since the previous sample, and false when the GPU does not report it.
func (c *collector) processUtilizations(h uintptr) (map[uint32]nvmlProcessUtilization, bool) {
	since := uint64(c.lastSample.UnixMicro())

	var count uint32
	code := c.lib.ProcessUtilization(h, nil, &count, since)

	var samples []nvmlProcessUtilization
	if code == nvmlInsufficientSize && count > 0 {
		samples = make([]nvmlProcessUtilization, count)
		code = c.lib.ProcessUtilization(h, &samples[0], &count, since)
		samples = samples[:min(count, uint32(len(samples)))]
	}

	if code == nvmlNotFound {
		samples = nil
	} else if code != nvmlSuccess {
		return nil, false
	}

	latest := make(map[uint32]nvmlProcessUtilization, len(samples))
	for _, s := range samples {
		if previous, ok := latest[s.pid]; !ok || s.timestamp > previous.timestamp {
			latest[s.pid] = s
		}
	}

	return latest, true
}

func (c *collector) countXidErrors() {
	for range maxEventsPerSample {
		var data nvmlEventData
		if c.lib.EventSetWait(c.eventSet, &data, 0) != nvmlSuccess {
			return
		}

		if data.eventType&eventTypeXidCriticalError != 0 {
			c.xidErrors[xidKey{device: data.device, code: data.eventData}]++
		}
	}
}

// appender returns a function that adds a value to values, unless it is nil.
func appender(values *[]sample.Value) func(metric, kind string, value *float64) {
	return func(metric, kind string, value *float64) {
		if value != nil {
			*values = append(*values, sample.Value{Metric: metric, Kind: kind, Value: *value})
		}
	}
}

// scaled returns the value that an NVML call wrote, converted to the unit of
// its metric, or nil when the call failed.
func scaled[T uint32 | uint64](code int32, value *T, factor float64) *float64 {
	if code != nvmlSuccess {
		return nil
	}

	return new(float64(*value) * factor)
}

// state reports whether a condition holds as 1 or 0.
func state(active bool) *float64 {
	if active {
		return new(1.0)
	}

	return new(0.0)
}

// readString returns the text that an NVML call wrote, or "" when the call failed.
func readString(size uint32, call func(buf *byte, length uint32) int32) string {
	buf := make([]byte, size)
	if call(&buf[0], size) != nvmlSuccess {
		return ""
	}

	text, _, _ := bytes.Cut(buf, []byte{0})

	return string(text)
}
