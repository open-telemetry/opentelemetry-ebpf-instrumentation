// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"context"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestBitPositionCalculation(t *testing.T) {
	for _, v := range [][4]uint32{
		{0, 1, 0, 1},
		{0, 2, 0, 2},
		{0, 65, 1, 1},
		{0, 66, 1, 2},
		{0, primeHash, 0, 0},
		{0, primeHash + 1, 0, 1},
	} {
		k := makeKey(v[0], v[1])
		segment, bit := pidSegmentBit(k)
		assert.Equal(t, segment, v[2])
		assert.Equal(t, bit, v[3])
	}
}

func makeKey(first, second uint32) uint64 {
	return (uint64(first) << 32) | uint64(second)
}

func TestParseJVMMemoryPoolRecordDecoratesServiceByPIDNamespace(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "orders", Namespace: "prod"}}
	currentPIDsCalls := 0
	tracer := &Tracer{
		pidsFilter: fakeServiceFilter{
			current: map[uint32]map[app.PID]svc.Attrs{
				7:  {1234: {UID: svc.UID{Name: "wrong"}}},
				42: {1234: service},
			},
			currentPIDsCalls: &currentPIDsCalls,
		},
	}

	events, ignore, err := tracer.parseJVMMemoryPoolRecord(&ringbuf.Record{
		RawSample: rawMemoryPoolPayload(t, BpfJvmMemPoolGcEvent{
			Timestamp:  123,
			NsPid:      1234,
			PidNsId:    42,
			GcWhenType: uint32(jvmruntime.RawJVMGCWhenAfter),
			Used:       100,
			Committed:  200,
			MaxSize:    300,
			Pool:       rawJVMString("G1 Eden Space"),
		}),
	})

	require.NoError(t, err)
	require.False(t, ignore)
	require.Len(t, events, 4)
	for _, event := range events {
		assert.Equal(t, service, event.Service)
	}
	assert.Equal(t, 1, currentPIDsCalls)
	assert.Equal(t, jvmruntime.JVMMetricMemoryUsed, events[0].Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryCommitted, events[1].Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryLimit, events[2].Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryUsedAfterLastGC, events[3].Kind)
}

func TestParseJVMMemoryPoolRecordIgnoresUnknownPID(t *testing.T) {
	tracer := &Tracer{
		pidsFilter: fakeServiceFilter{
			current: map[uint32]map[app.PID]svc.Attrs{
				42: {1234: {UID: svc.UID{Name: "orders"}}},
			},
		},
	}

	events, ignore, err := tracer.parseJVMMemoryPoolRecord(&ringbuf.Record{
		RawSample: rawMemoryPoolPayload(t, BpfJvmMemPoolGcEvent{
			NsPid:      9999,
			PidNsId:    42,
			GcWhenType: uint32(jvmruntime.RawJVMGCWhenAfter),
			Used:       100,
			Committed:  200,
			Pool:       rawJVMString("G1 Eden Space"),
		}),
	})

	require.NoError(t, err)
	assert.True(t, ignore)
	assert.Empty(t, events)
}

func TestProcessSharedRingbufRecordConsumesJVMRuntimeMetricRecordsWithoutForwarding(t *testing.T) {
	for _, tt := range []struct {
		name    string
		enabled bool
	}{
		{name: "metrics disabled"},
		{name: "queue missing", enabled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tracer := &Tracer{cfg: &obi.Config{}}
			if tt.enabled {
				tracer.cfg.Metrics.Features = export.FeatureApplicationRuntime
			}

			span, ignore, err := tracer.processSharedRingbufRecord(context.Background(), nil, &tracer.cfg.EBPF, &ringbuf.Record{
				RawSample: []byte{ebpfcommon.EventTypeJVMMemoryPoolGC},
			})

			require.NoError(t, err)
			assert.True(t, ignore)
			assert.Empty(t, span)
		})
	}
}

func TestProcessSharedRingbufRecordDispatchesJVMMemoryPoolRecord(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "orders", Namespace: "prod"}}
	runtimeMetrics := msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](msg.ChannelBufferLen(1))
	received := runtimeMetrics.Subscribe(msg.SubscriberName("jvm-test"))
	tracer := &Tracer{
		cfg: &obi.Config{},
		pidsFilter: fakeServiceFilter{
			current: map[uint32]map[app.PID]svc.Attrs{
				42: {1234: service},
			},
		},
		eventCtx: &ebpfcommon.EBPFEventContext{RuntimeMetrics: runtimemetrics.NewQueueSender(runtimeMetrics)},
	}
	tracer.cfg.Metrics.Features = export.FeatureApplicationRuntime

	span, ignore, err := tracer.processSharedRingbufRecord(context.Background(), nil, &tracer.cfg.EBPF, &ringbuf.Record{
		RawSample: rawMemoryPoolPayload(t, BpfJvmMemPoolGcEvent{
			Type:       ebpfcommon.EventTypeJVMMemoryPoolGC,
			Timestamp:  100,
			NsPid:      1234,
			PidNsId:    42,
			GcWhenType: uint32(jvmruntime.RawJVMGCWhenAfter),
			Used:       100,
			Committed:  200,
			MaxSize:    300,
			Pool:       rawJVMString("G1 Eden Space"),
		}),
	})

	require.NoError(t, err)
	assert.True(t, ignore)
	assert.Empty(t, span)

	batch := readJVMTestBatch(t, received)
	require.Len(t, batch, 4)
	for _, snapshot := range batch {
		assert.Equal(t, service, snapshot.Service)
		require.NotNil(t, snapshot.JVM)
	}
	assert.Equal(t, jvmruntime.JVMMetricMemoryUsed, batch[0].JVM.Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryCommitted, batch[1].JVM.Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryLimit, batch[2].JVM.Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryUsedAfterLastGC, batch[3].JVM.Kind)
}

func TestJVMBPFMapsAreInternallyPinnedAndUseSharedEventsRingBuffer(t *testing.T) {
	spec, err := LoadBpf()
	require.NoError(t, err)

	require.NotContains(t, spec.Maps, "jvm_gc_heap_summary_events")
	require.NotContains(t, spec.Maps, "jvm_mem_pool_gc_events")
	require.NotContains(t, spec.Maps, "jvm_heap_summary_samples")

	for _, name := range []string{
		"jvm_mem_pool_samples",
		"obi_usdt_specs",
		"obi_usdt_ip_to_spec_id",
	} {
		require.Contains(t, spec.Maps, name)
		assert.Equal(t, ebpfconvenience.PinInternal, spec.Maps[name].Pinning)
	}
	assert.Equal(t, ebpf.LRUHash, spec.Maps["obi_usdt_ip_to_spec_id"].Type)
}

func TestJVMRuntimeMetricsExposeHotSpotUSDTProbes(t *testing.T) {
	tracer := Tracer{cfg: &obi.Config{}}
	assert.Empty(t, tracer.USDTProbes())

	tracer.cfg.Metrics.Features = export.FeatureApplicationRuntime
	assert.NotContains(t, tracer.UProbes(), "libjvm.so")

	probes := tracer.USDTProbes()

	require.Contains(t, probes, "libjvm.so")
	require.Len(t, probes["libjvm.so"], 2)
	assert.Equal(t, "hotspot", probes["libjvm.so"][0].Provider)
	assert.Equal(t, "mem__pool__gc__begin", probes["libjvm.so"][0].Name)
	assert.Equal(t, "hotspot", probes["libjvm.so"][1].Provider)
	assert.Equal(t, "mem__pool__gc__end", probes["libjvm.so"][1].Name)
}

func TestJVMRuntimeMetricsConstantOverridesUseApplicationRuntimeAsFeatureGate(t *testing.T) {
	for _, tt := range []struct {
		name             string
		configure        func(*obi.Config)
		samplingInterval time.Duration
		expectedInterval uint64
	}{
		{name: "disabled", samplingInterval: time.Second},
		{
			name: "enabled globally",
			configure: func(cfg *obi.Config) {
				cfg.Metrics.Features = export.FeatureApplicationRuntime
			},
			samplingInterval: 250 * time.Millisecond,
			expectedInterval: uint64((250 * time.Millisecond).Nanoseconds()),
		},
		{
			name: "enabled for instrument selector",
			configure: func(cfg *obi.Config) {
				cfg.Discovery.Instrument = services.GlobDefinitionCriteria{
					{Metrics: perapp.SvcMetricsConfig{Features: export.FeatureApplicationRuntime}},
				}
			},
			samplingInterval: 500 * time.Millisecond,
			expectedInterval: uint64((500 * time.Millisecond).Nanoseconds()),
		},
		{
			name: "enabled for deprecated services selector",
			configure: func(cfg *obi.Config) {
				cfg.Discovery.Services = services.RegexDefinitionCriteria{
					{Metrics: perapp.SvcMetricsConfig{Features: export.FeatureApplicationRuntime}},
				}
			},
			samplingInterval: 750 * time.Millisecond,
			expectedInterval: uint64((750 * time.Millisecond).Nanoseconds()),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tracer := Tracer{cfg: &obi.Config{}}
			if tt.configure != nil {
				tt.configure(tracer.cfg)
			}
			tracer.cfg.JVMRuntimeMetrics.SamplingInterval = tt.samplingInterval

			overrides := tracer.constants()

			assert.Equal(t, tt.expectedInterval, overrides["jvm_sampling_interval_ns"])
		})
	}
}

func TestRawJVMEventLayoutsUseGeneratedBPFStructs(t *testing.T) {
	assert.Equal(t, 200, int(unsafe.Sizeof(BpfJvmMemPoolGcEvent{})))
}

func rawMemoryPoolPayload(t *testing.T, raw BpfJvmMemPoolGcEvent) []byte {
	t.Helper()

	return rawPayload(raw)
}

func rawPayload[T any](raw T) []byte {
	size := int(unsafe.Sizeof(raw))
	out := make([]byte, size)
	copy(out, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), size))
	return out
}

func rawJVMString(value string) [jvmruntime.JVMRawStringLen]byte {
	var raw [jvmruntime.JVMRawStringLen]byte
	copy(raw[:], []byte(value))
	return raw
}

func readJVMTestBatch(t *testing.T, events <-chan []runtimemetrics.RuntimeMetricSnapshot) []runtimemetrics.RuntimeMetricSnapshot {
	t.Helper()

	select {
	case batch := <-events:
		return batch
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for JVM runtime events")
		return nil
	}
}

type fakeServiceFilter struct {
	current          map[uint32]map[app.PID]svc.Attrs
	currentPIDsCalls *int
}

func (f fakeServiceFilter) AllowPID(app.PID, uint32, *exec.FileInfo, ebpfcommon.PIDType) {}
func (f fakeServiceFilter) BlockPID(app.PID, uint32)                                     {}
func (f fakeServiceFilter) ValidPID(app.PID, uint32, ebpfcommon.PIDType) bool            { return false }
func (f fakeServiceFilter) Filter(inputSpans []request.Span) []request.Span              { return inputSpans }
func (f fakeServiceFilter) CurrentPIDs(ebpfcommon.PIDType) map[uint32]map[app.PID]svc.Attrs {
	if f.currentPIDsCalls != nil {
		(*f.currentPIDsCalls)++
	}
	return f.current
}
