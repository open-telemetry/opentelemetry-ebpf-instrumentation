// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"math"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/gpuolly"
	"go.opentelemetry.io/obi/pkg/internal/nvml/sample"
)

const gib = 1 << 30

func write(buf *byte, length uint32, text string) {
	copy(unsafe.Slice(buf, length), text+"\x00")
}

// requiredOnly is an NVML library that has none of the optional functions.
func requiredOnly() *library {
	lib := &library{
		Init:         func() int32 { return nvmlSuccess },
		Shutdown:     func() int32 { return nvmlSuccess },
		ErrorString:  func(int32) string { return "fake error" },
		DeviceCount:  func(count *uint32) int32 { *count = 1; return nvmlSuccess },
		DeviceHandle: func(index uint32, device *uintptr) int32 { *device = uintptr(index) + 1; return nvmlSuccess },
		DeviceUUID: func(_ uintptr, buf *byte, length uint32) int32 {
			write(buf, length, "GPU-fake")
			return nvmlSuccess
		},
	}
	stubMissing(lib)
	return lib
}

// fakeLibrary is an NVML library with one GPU and two processes, one of
// which hides its memory usage.
func fakeLibrary() *library {
	lib := requiredOnly()

	lib.DriverVersion = func(buf *byte, length uint32) int32 { write(buf, length, "570.86.15"); return nvmlSuccess }
	lib.DeviceName = func(_ uintptr, buf *byte, length uint32) int32 { write(buf, length, "Tesla T4"); return nvmlSuccess }
	lib.UtilizationRates = func(_ uintptr, u *nvmlUtilization) int32 { u.gpu, u.memory = 75, 33; return nvmlSuccess }
	lib.EncoderUtilization = func(_ uintptr, u, _ *uint32) int32 { *u = 10; return nvmlSuccess }
	lib.DecoderUtilization = func(_ uintptr, u, _ *uint32) int32 { *u = 5; return nvmlSuccess }
	lib.MemoryInfoV2 = func(_ uintptr, m *nvmlMemoryV2) int32 {
		m.used, m.reserved, m.total = 4*gib, gib, 16*gib
		return nvmlSuccess
	}
	lib.PCIeReplays = func(_ uintptr, count *uint32) int32 { *count = 4; return nvmlSuccess }
	lib.FieldValues = func(_ uintptr, _ int32, field *nvmlFieldValue) int32 {
		field.valueType, field.value = valueTypeUnsignedInt, 70
		return nvmlSuccess
	}
	lib.PowerUsage = func(_ uintptr, mw *uint32) int32 { *mw = 68500; return nvmlSuccess }
	lib.TotalEnergy = func(_ uintptr, mj *uint64) int32 { *mj = 1234500; return nvmlSuccess }
	lib.Temperature = func(_ uintptr, _ int32, c *uint32) int32 { *c = 61; return nvmlSuccess }
	lib.TemperatureThreshold = func(_ uintptr, threshold int32, c *uint32) int32 {
		*c = map[int32]uint32{temperatureThresholdSlowdown: 85, temperatureThresholdShutdown: 96}[threshold]
		return nvmlSuccess
	}
	lib.ClockInfo = func(_ uintptr, clock int32, mhz *uint32) int32 {
		*mhz = map[int32]uint32{clockProcessor: 1590, clockMemory: 5001}[clock]
		return nvmlSuccess
	}
	lib.ThrottleReasons = func(_ uintptr, reasons *uint64) int32 { *reasons = 0x20; return nvmlSuccess }
	lib.ECCErrors = func(_ uintptr, errorType, _ int32, count *uint64) int32 {
		*count = map[int32]uint64{memoryErrorCorrected: 3, memoryErrorUncorrected: 1}[errorType]
		return nvmlSuccess
	}
	lib.RemappedRows = func(_ uintptr, corrected, uncorrected, pending, _ *uint32) int32 {
		*corrected, *uncorrected, *pending = 2, 1, 1
		return nvmlSuccess
	}
	lib.ComputeProcesses = func(_ uintptr, count *uint32, infos *nvmlProcessInfo) int32 {
		if *count < 2 {
			*count = 2
			return nvmlInsufficientSize
		}
		processes := unsafe.Slice(infos, *count)
		processes[0] = nvmlProcessInfo{pid: 4242, usedGPUMemory: gib}
		processes[1] = nvmlProcessInfo{pid: 4243, usedGPUMemory: valueNotAvailable}
		*count = 2
		return nvmlSuccess
	}
	lib.ProcessUtilization = func(_ uintptr, samples *nvmlProcessUtilization, count *uint32, _ uint64) int32 {
		if samples == nil {
			*count = 1
			return nvmlInsufficientSize
		}
		*samples = nvmlProcessUtilization{pid: 4242, smUtil: 50, encUtil: 7, decUtil: 9}
		*count = 1
		return nvmlSuccess
	}
	lib.EventSetCreate = func(set *uintptr) int32 { *set = 1; return nvmlSuccess }
	lib.RegisterEvents = func(uintptr, uint64, uintptr) int32 { return nvmlSuccess }

	pending := 2
	lib.EventSetWait = func(_ uintptr, data *nvmlEventData, _ uint32) int32 {
		if pending == 0 {
			return nvmlNotFound
		}
		pending--
		*data = nvmlEventData{device: 1, eventType: eventTypeXidCriticalError, eventData: 79}
		return nvmlSuccess
	}

	return lib
}

func valuesOf(values []sample.Value) map[string]float64 {
	out := map[string]float64{}
	for _, v := range values {
		out[v.Metric+"/"+v.Kind] = v.Value
	}
	return out
}

func TestSample(t *testing.T) {
	c, err := newCollector(fakeLibrary())
	require.NoError(t, err)

	s := c.sample()
	assert.Equal(t, "570.86.15", s.DriverVersion)
	require.Len(t, s.Devices, 1)

	dev := s.Devices[0]
	assert.Equal(t, "GPU-fake", dev.UUID)
	assert.Equal(t, "Tesla T4", dev.Name)

	values := valuesOf(dev.Values)
	for metric, expected := range map[string]float64{
		"hw.gpu.utilization/general":              0.75,
		"hw.gpu.utilization/encoder":              0.10,
		"hw.gpu.utilization/decoder":              0.05,
		"hw.gpu.memory.usage/":                    4 * gib,
		"hw.gpu.memory.limit/":                    16 * gib,
		"hw.gpu.memory.utilization/":              0.25,
		"gpu.memory.activity/":                    0.33,
		"gpu.memory.reserved/":                    gib,
		"gpu.pcie.replays/":                       4,
		"hw.temperature/memory":                   70,
		"hw.power/":                               68.5,
		"hw.energy/":                              1234.5,
		"hw.temperature/gpu":                      61,
		"hw.temperature.limit/high.degraded":      85,
		"hw.temperature.limit/high.critical":      96,
		"gpu.clock.frequency/processor":           1.59e9,
		"gpu.clock.frequency/memory":              5.001e9,
		"gpu.clock.throttled/sw_thermal_slowdown": 1,
		"gpu.clock.throttled/hw_slowdown":         0,
		"hw.errors/corrected":                     3,
		"hw.errors/uncorrected":                   1,
		"gpu.memory.remapped_rows/corrected":      2,
		"gpu.memory.remapped_rows/uncorrected":    1,
		"hw.status/ok":                            0,
		"hw.status/predicted_failure":             1,
		"hw.status/failed":                        0,
		"gpu.xid.errors/79":                       2,
	} {
		assert.InDelta(t, expected, values[metric], 1e-3, metric)
	}

	require.Len(t, dev.Processes, 2)
	assert.Equal(t, map[string]float64{
		"gpu.process.memory.usage/":       gib,
		"gpu.process.utilization/general": 0.5,
		"gpu.process.utilization/encoder": 0.07,
		"gpu.process.utilization/decoder": 0.09,
	}, valuesOf(dev.Processes[0].Values))

	// A process without memory usage or utilization samples did not use the GPU since the previous sample.
	assert.Equal(t, map[string]float64{
		"gpu.process.utilization/general": 0,
		"gpu.process.utilization/encoder": 0,
		"gpu.process.utilization/decoder": 0,
	}, valuesOf(dev.Processes[1].Values))

	// The Xid errors are counted since the helper started.
	assert.InDelta(t, 2.0, valuesOf(c.sample().Devices[0].Values)["gpu.xid.errors/79"], 1e-9)
}

// Every metric that the helper writes is one that OBI reports, and the other way around.
func TestSampleWritesEveryMetric(t *testing.T) {
	c, err := newCollector(fakeLibrary())
	require.NoError(t, err)

	s := c.sample()
	written := map[string]bool{}
	for _, v := range s.Devices[0].Values {
		written[v.Metric] = true
	}
	for _, v := range s.Devices[0].Processes[0].Values {
		written[v.Metric] = true
	}

	reported := map[string]bool{}
	for _, m := range gpuolly.Metrics {
		reported[m.Name.OTEL] = true
	}
	assert.Equal(t, reported, written)
}

func TestSampleWithoutOptionalFunctions(t *testing.T) {
	c, err := newCollector(requiredOnly())
	require.NoError(t, err)

	s := c.sample()
	require.Len(t, s.Devices, 1)
	assert.Empty(t, s.Devices[0].Processes)

	// A GPU that reports nothing else is still listed, as healthy.
	assert.Equal(t, map[string]float64{"hw.status/ok": 1, "hw.status/predicted_failure": 0, "hw.status/failed": 0},
		valuesOf(s.Devices[0].Values))
}

func TestBindLibrary(t *testing.T) {
	_, err := bindLibrary(func(string) uintptr { return 0 })
	require.ErrorContains(t, err, "nvmlInit_v2")

	required := map[string]bool{
		"nvmlInit_v2": true, "nvmlShutdown": true, "nvmlErrorString": true,
		"nvmlDeviceGetCount_v2": true, "nvmlDeviceGetHandleByIndex_v2": true, "nvmlDeviceGetUUID": true,
	}
	lib, err := bindLibrary(func(symbol string) uintptr {
		if required[symbol] {
			return 1
		}
		return 0
	})
	require.NoError(t, err)

	// The library is never called here: the required functions point to a fake address.
	var power uint32
	assert.Equal(t, int32(nvmlNotSupported), lib.PowerUsage(1, &power))
	assert.Equal(t, int32(nvmlNotSupported), lib.ComputeProcesses(1, &power, nil))
}

func TestMemoryTemperatureValueTypes(t *testing.T) {
	for _, test := range []struct {
		field    nvmlFieldValue
		expected *float64
	}{
		{nvmlFieldValue{valueType: valueTypeUnsignedInt, value: 70}, new(70.0)},
		{nvmlFieldValue{valueType: valueTypeSignedInt, value: uint64(uint32(0xFFFFFFFF))}, new(-1.0)},
		{nvmlFieldValue{valueType: valueTypeUnsignedLongLong, value: 71}, new(71.0)},
		{nvmlFieldValue{valueType: valueTypeDouble, value: math.Float64bits(72.5)}, new(72.5)},
		{nvmlFieldValue{valueType: valueTypeUnsignedInt, nvmlReturn: nvmlNotSupported}, nil},
	} {
		lib := requiredOnly()
		lib.FieldValues = func(_ uintptr, _ int32, field *nvmlFieldValue) int32 {
			*field = test.field
			return nvmlSuccess
		}

		c := &collector{lib: lib}
		assert.Equal(t, test.expected, c.memoryTemperature(1))
	}
}
