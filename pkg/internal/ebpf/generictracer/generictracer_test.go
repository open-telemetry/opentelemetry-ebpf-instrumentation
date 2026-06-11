// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
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

func TestParseJVMGCHeapSummaryRecordDecoratesServiceByPID(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "orders", Namespace: "prod"}}
	tracer := &Tracer{
		pidsFilter: fakeServiceFilter{
			current: map[uint32]map[app.PID]svc.Attrs{
				7:  {11: {UID: svc.UID{Name: "other"}}},
				42: {1234: service},
			},
		},
	}

	event, ignore, err := tracer.parseJVMGCHeapSummaryRecord(&ringbuf.Record{
		RawSample: rawHeapSummaryPayload(t, jvmruntime.RawJVMGCHeapSummaryEvent{
			Timestamp:      100,
			GlobalPID:      5678,
			NsPID:          1234,
			PIDNamespaceID: 42,
			GCWhenType:     jvmruntime.RawJVMGCWhenAfter,
			Used:           2048,
		}),
	})

	require.NoError(t, err)
	require.False(t, ignore)
	assert.Equal(t, app.PID(1234), event.PID)
	assert.Equal(t, service, event.Service)
	assert.NotEqual(t, time.Unix(0, 100), event.Time)
	assert.Equal(t, jvmruntime.JVMMetricBeylaHeapUsed, event.Kind)
	assert.Equal(t, jvmruntime.JVMGCPhaseAfter, event.GCPhase)
	assert.Equal(t, uint64(2048), event.ValueBytes)
}

func TestParseJVMGCHeapSummaryRecordDecoratesServiceByPIDNamespace(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "orders", Namespace: "prod"}}
	tracer := &Tracer{
		pidsFilter: fakeServiceFilter{
			current: map[uint32]map[app.PID]svc.Attrs{
				7:  {1234: {UID: svc.UID{Name: "wrong"}}},
				42: {1234: service},
			},
		},
	}

	event, ignore, err := tracer.parseJVMGCHeapSummaryRecord(&ringbuf.Record{
		RawSample: rawHeapSummaryPayload(t, jvmruntime.RawJVMGCHeapSummaryEvent{
			NsPID:          1234,
			PIDNamespaceID: 42,
			GCWhenType:     jvmruntime.RawJVMGCWhenAfter,
		}),
	})

	require.NoError(t, err)
	require.False(t, ignore)
	assert.Equal(t, service, event.Service)
}

func TestParseJVMMemoryPoolRecordDecoratesServiceByPIDNamespace(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "orders", Namespace: "prod"}}
	tracer := &Tracer{
		pidsFilter: fakeServiceFilter{
			current: map[uint32]map[app.PID]svc.Attrs{
				7:  {1234: {UID: svc.UID{Name: "wrong"}}},
				42: {1234: service},
			},
		},
	}

	events, ignore, err := tracer.parseJVMMemoryPoolRecord(&ringbuf.Record{
		RawSample: rawMemoryPoolPayload(t, jvmruntime.RawJVMMemoryPoolEvent{
			Timestamp:      123,
			NsPID:          1234,
			PIDNamespaceID: 42,
			GCWhenType:     jvmruntime.RawJVMGCWhenAfter,
			Used:           100,
			Committed:      200,
			MaxSize:        300,
			Pool:           rawJVMString("G1 Eden Space"),
		}),
	})

	require.NoError(t, err)
	require.False(t, ignore)
	require.Len(t, events, 4)
	for _, event := range events {
		assert.Equal(t, service, event.Service)
	}
	assert.Equal(t, jvmruntime.JVMMetricMemoryUsed, events[0].Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryCommitted, events[1].Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryLimit, events[2].Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryUsedAfterLastGC, events[3].Kind)
}

func TestParseJVMGCHeapSummaryRecordConvertsMonotonicTimestamp(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "orders"}}
	tracer := &Tracer{
		pidsFilter: fakeServiceFilter{
			current: map[uint32]map[app.PID]svc.Attrs{
				42: {1234: service},
			},
		},
	}
	monotonicTimestamp := uint64(timing.MonoTimeNow() - 2*time.Second)

	event, ignore, err := tracer.parseJVMGCHeapSummaryRecord(&ringbuf.Record{
		RawSample: rawHeapSummaryPayload(t, jvmruntime.RawJVMGCHeapSummaryEvent{
			Timestamp:      monotonicTimestamp,
			GlobalPID:      5678,
			NsPID:          1234,
			PIDNamespaceID: 42,
			GCWhenType:     jvmruntime.RawJVMGCWhenAfter,
			Used:           2048,
		}),
	})

	require.NoError(t, err)
	require.False(t, ignore)
	assert.WithinDuration(t, time.Now().Add(-2*time.Second), event.Time, 5*time.Second)
	assert.NotEqual(t, time.Unix(0, int64(monotonicTimestamp)), event.Time)
}

func TestParseJVMGCHeapSummaryRecordIgnoresUnknownPID(t *testing.T) {
	tracer := &Tracer{
		pidsFilter: fakeServiceFilter{
			current: map[uint32]map[app.PID]svc.Attrs{
				42: {1234: {UID: svc.UID{Name: "orders"}}},
			},
		},
	}

	event, ignore, err := tracer.parseJVMGCHeapSummaryRecord(&ringbuf.Record{
		RawSample: rawHeapSummaryPayload(t, jvmruntime.RawJVMGCHeapSummaryEvent{
			GlobalPID:      1234,
			NsPID:          9999,
			PIDNamespaceID: 42,
			GCWhenType:     jvmruntime.RawJVMGCWhenBefore,
		}),
	})

	require.NoError(t, err)
	assert.True(t, ignore)
	assert.Empty(t, event.Service)
}

func TestShouldReadJVMRuntimeEventsRequiresEnabledConfigQueueAndMap(t *testing.T) {
	tracer := &Tracer{cfg: &obi.Config{}}

	assert.False(t, tracer.shouldReadJVMRuntimeEvents())

	tracer.cfg.JVMRuntimeMetrics.Enabled = true
	assert.False(t, tracer.shouldReadJVMRuntimeEvents())

	tracer.SetJVMRuntimeEvents(msg.NewQueue[[]jvmruntime.JVMRuntimeEvent]())
	assert.False(t, tracer.shouldReadJVMRuntimeEvents())
}

func TestJVMHeapSummaryBPFMapsAreInternallyPinned(t *testing.T) {
	spec, err := LoadBpf()
	require.NoError(t, err)

	for _, name := range []string{
		"jvm_gc_heap_summary_events",
		"jvm_heap_summary_samples",
		"jvm_mem_pool_gc_events",
		"jvm_mem_pool_samples",
		"obi_usdt_specs",
		"obi_usdt_ip_to_spec_id",
	} {
		require.Contains(t, spec.Maps, name)
		assert.Equal(t, ebpfconvenience.PinInternal, spec.Maps[name].Pinning)
	}
}

func TestJVMRuntimeMetricsExposeHotSpotUSDTProbes(t *testing.T) {
	tracer := Tracer{cfg: &obi.Config{}}
	assert.Empty(t, tracer.USDTProbes())

	tracer.cfg.JVMRuntimeMetrics.Enabled = true
	probes := tracer.USDTProbes()

	require.Contains(t, probes, "libjvm.so")
	require.Len(t, probes["libjvm.so"], 2)
	assert.Equal(t, "hotspot", probes["libjvm.so"][0].Provider)
	assert.Equal(t, "mem__pool__gc__begin", probes["libjvm.so"][0].Name)
	assert.Equal(t, "hotspot", probes["libjvm.so"][1].Provider)
	assert.Equal(t, "mem__pool__gc__end", probes["libjvm.so"][1].Name)
}

func rawHeapSummaryPayload(t *testing.T, raw jvmruntime.RawJVMGCHeapSummaryEvent) []byte {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, raw))
	return buf.Bytes()
}

func rawMemoryPoolPayload(t *testing.T, raw jvmruntime.RawJVMMemoryPoolEvent) []byte {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, raw))
	return buf.Bytes()
}

func rawJVMString(value string) [jvmruntime.JVMRawStringLen]byte {
	var raw [jvmruntime.JVMRawStringLen]byte
	copy(raw[:], []byte(value))
	return raw
}

type fakeServiceFilter struct {
	current map[uint32]map[app.PID]svc.Attrs
}

func (f fakeServiceFilter) AllowPID(app.PID, uint32, *exec.FileInfo, ebpfcommon.PIDType) {}
func (f fakeServiceFilter) BlockPID(app.PID, uint32)                                     {}
func (f fakeServiceFilter) ValidPID(app.PID, uint32, ebpfcommon.PIDType) bool            { return false }
func (f fakeServiceFilter) Filter(inputSpans []request.Span) []request.Span              { return inputSpans }
func (f fakeServiceFilter) CurrentPIDs(ebpfcommon.PIDType) map[uint32]map[app.PID]svc.Attrs {
	return f.current
}
