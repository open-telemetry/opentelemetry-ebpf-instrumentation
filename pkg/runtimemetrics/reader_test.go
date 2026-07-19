// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestGoRuntimeMetricRawABI(t *testing.T) {
	var event goRuntimeMetricRawEvent
	var snapshot goRuntimeMetricRawSnapshot

	require.Equal(t, uintptr(144), unsafe.Sizeof(event))
	require.Equal(t, uintptr(16), unsafe.Offsetof(event.Snapshot))
	require.Equal(t, uintptr(128), unsafe.Sizeof(snapshot))
	require.Equal(t, uintptr(0), unsafe.Offsetof(snapshot.ValidMask))
	require.Equal(t, uintptr(8), unsafe.Offsetof(snapshot.NumGC))
	require.Equal(t, uintptr(12), unsafe.Offsetof(snapshot.Pad))
	require.Equal(t, uintptr(16), unsafe.Offsetof(snapshot.GOMAXPROCS))
	require.Equal(t, uintptr(20), unsafe.Offsetof(snapshot.GCPercent))
	require.Equal(t, uintptr(24), unsafe.Offsetof(snapshot.MemoryLimit))
	require.Equal(t, uintptr(32), unsafe.Offsetof(snapshot.CPUGCAssistTime))
	require.Equal(t, uintptr(40), unsafe.Offsetof(snapshot.CPUGCDedicatedTime))
	require.Equal(t, uintptr(48), unsafe.Offsetof(snapshot.CPUGCIdleTime))
	require.Equal(t, uintptr(56), unsafe.Offsetof(snapshot.CPUGCPauseTime))
	require.Equal(t, uintptr(64), unsafe.Offsetof(snapshot.CPUScavengeAssistTime))
	require.Equal(t, uintptr(72), unsafe.Offsetof(snapshot.CPUScavengeBgTime))
	require.Equal(t, uintptr(80), unsafe.Offsetof(snapshot.CPUIdleTime))
	require.Equal(t, uintptr(88), unsafe.Offsetof(snapshot.CPUUserTime))
	require.Equal(t, uintptr(96), unsafe.Offsetof(snapshot.MemoryUsedStack))
	require.Equal(t, uintptr(104), unsafe.Offsetof(snapshot.MemoryUsedOther))
	require.Equal(t, uintptr(112), unsafe.Offsetof(snapshot.MemoryAllocated))
	require.Equal(t, uintptr(120), unsafe.Offsetof(snapshot.MemoryAllocations))
}

func TestGoRuntimeMetricValidMaskABI(t *testing.T) {
	require.Equal(t, goRuntimeMetricValidGCCycles, uint64(1<<0))
	require.Equal(t, goRuntimeMetricValidMemoryLimit, uint64(1<<1))
	require.Equal(t, goRuntimeMetricValidProcessorLimit, uint64(1<<2))
	require.Equal(t, goRuntimeMetricValidGOGC, uint64(1<<3))
	require.Equal(t, goRuntimeMetricValidCPUTime, uint64(1<<4))
	require.Equal(t, goRuntimeMetricValidMemoryUsed, uint64(1<<5))
	require.Equal(t, goRuntimeMetricValidMemoryAllocs, uint64(1<<6))
}

func TestConvertGoRuntimeMetricSnapshot(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "svc"}}

	snapshot := convertGoRuntimeMetricSnapshot(service, app.PID(123), goRuntimeMetricRawSnapshot{
		ValidMask:   goRuntimeMetricValidGCCycles | goRuntimeMetricValidMemoryLimit | goRuntimeMetricValidProcessorLimit | goRuntimeMetricValidGOGC,
		NumGC:       10,
		GOMAXPROCS:  4,
		GCPercent:   100,
		MemoryLimit: 1024,
	})
	require.NotNil(t, snapshot.Go)
	require.Equal(t, uint64(10), *snapshot.Go.GCCycles)
	require.Equal(t, int64(4), *snapshot.Go.ProcessorLimit)
	require.Equal(t, int64(100), *snapshot.Go.GOGC)
	require.Equal(t, int64(1024), *snapshot.Go.MemoryLimit)
	require.Nil(t, snapshot.Go.CPUTime)
	require.Nil(t, snapshot.JVM)
}

func TestConvertGoRuntimeMetricSnapshotSuppressesUnavailableValues(t *testing.T) {
	snapshot := convertGoRuntimeMetricSnapshot(svc.Attrs{}, app.PID(123), goRuntimeMetricRawSnapshot{
		ValidMask:   goRuntimeMetricValidGCCycles | goRuntimeMetricValidMemoryLimit | goRuntimeMetricValidGOGC,
		NumGC:       1,
		GCPercent:   -1,
		MemoryLimit: math.MaxInt64,
	})
	require.NotNil(t, snapshot.Go)
	require.Nil(t, snapshot.Go.GOGC)
	require.Nil(t, snapshot.Go.MemoryLimit)
}

func TestConvertGoRuntimeMetricSnapshotUsesTotalGCCycles(t *testing.T) {
	snapshot := convertGoRuntimeMetricSnapshot(svc.Attrs{}, app.PID(123), goRuntimeMetricRawSnapshot{
		ValidMask:  goRuntimeMetricValidGCCycles | goRuntimeMetricValidProcessorLimit,
		NumGC:      1,
		GOMAXPROCS: 4,
	})
	require.NotNil(t, snapshot.Go)
	require.Equal(t, uint64(1), *snapshot.Go.GCCycles)
	require.NotNil(t, snapshot.Go.ProcessorLimit)
}

func TestConvertGoRuntimeMetricSnapshotSuppressesInvalidProcessorLimit(t *testing.T) {
	snapshot := convertGoRuntimeMetricSnapshot(svc.Attrs{}, app.PID(123), goRuntimeMetricRawSnapshot{
		ValidMask:  goRuntimeMetricValidGCCycles | goRuntimeMetricValidProcessorLimit,
		NumGC:      1,
		GOMAXPROCS: 0,
	})
	require.NotNil(t, snapshot.Go)
	require.Nil(t, snapshot.Go.ProcessorLimit)
}

func TestConvertGoRuntimeMetricSnapshotIncludesValidCPUZeroValues(t *testing.T) {
	snapshot := convertGoRuntimeMetricSnapshot(svc.Attrs{}, app.PID(123), goRuntimeMetricRawSnapshot{
		ValidMask:             goRuntimeMetricValidGCCycles | goRuntimeMetricValidCPUTime,
		CPUGCAssistTime:       0,
		CPUGCDedicatedTime:    1,
		CPUGCIdleTime:         2,
		CPUGCPauseTime:        3,
		CPUScavengeAssistTime: 4,
		CPUScavengeBgTime:     5,
		CPUIdleTime:           6,
		CPUUserTime:           7,
	})

	require.NotNil(t, snapshot.Go)
	require.Equal(t, uint64(0), *snapshot.Go.GCCycles)
	require.NotNil(t, snapshot.Go.CPUTime)
	require.Equal(t, int64(0), snapshot.Go.CPUTime.GCAssistTime)
	require.Equal(t, int64(7), snapshot.Go.CPUTime.UserTime)
}

func TestConvertGoRuntimeMetricSnapshotIncludesValidMemoryZeroValues(t *testing.T) {
	snapshot := convertGoRuntimeMetricSnapshot(svc.Attrs{}, app.PID(123), goRuntimeMetricRawSnapshot{
		ValidMask:         goRuntimeMetricValidMemoryUsed | goRuntimeMetricValidMemoryAllocs,
		MemoryUsedStack:   0,
		MemoryUsedOther:   2048,
		MemoryAllocated:   0,
		MemoryAllocations: 0,
	})

	require.NotNil(t, snapshot.Go)
	require.Equal(t, int64(0), *snapshot.Go.MemoryUsedStack)
	require.Equal(t, int64(2048), *snapshot.Go.MemoryUsedOther)
	require.Equal(t, uint64(0), *snapshot.Go.MemoryAllocated)
	require.Equal(t, uint64(0), *snapshot.Go.MemoryAllocations)
}

func TestConvertGoRuntimeMetricSnapshotSuppressesInvalidMemoryUsed(t *testing.T) {
	snapshot := convertGoRuntimeMetricSnapshot(svc.Attrs{}, app.PID(123), goRuntimeMetricRawSnapshot{
		ValidMask:       goRuntimeMetricValidMemoryUsed,
		MemoryUsedStack: -1,
		MemoryUsedOther: 2048,
	})

	require.NotNil(t, snapshot.Go)
	require.Nil(t, snapshot.Go.MemoryUsedStack)
	require.Nil(t, snapshot.Go.MemoryUsedOther)
}

func TestConvertGoRuntimeMetricSnapshotSuppressesNegativeCPUTime(t *testing.T) {
	snapshot := convertGoRuntimeMetricSnapshot(svc.Attrs{}, app.PID(123), goRuntimeMetricRawSnapshot{
		ValidMask:   goRuntimeMetricValidCPUTime,
		CPUUserTime: -1,
	})

	require.NotNil(t, snapshot.Go)
	require.Nil(t, snapshot.Go.CPUTime)
}

func TestRuntimeMetricServiceRequiresRuntimeMetricsFeature(t *testing.T) {
	service := svc.Attrs{
		Features: export.FeatureApplicationRuntime,
	}
	currentPIDs := map[uint32]map[app.PID]svc.Attrs{
		33: {
			123: service,
			456: {SDKLanguage: svc.InstrumentableGolang},
		},
	}

	got, ok := runtimeMetricService(currentPIDs, goRuntimeMetricRawKey{UserPID: 123, Ns: 33})
	require.True(t, ok)
	require.Equal(t, service, got)

	_, ok = runtimeMetricService(currentPIDs, goRuntimeMetricRawKey{UserPID: 456, Ns: 33})
	require.False(t, ok)

	_, ok = runtimeMetricService(currentPIDs, goRuntimeMetricRawKey{UserPID: 789, Ns: 33})
	require.False(t, ok)
}

func TestSnapshotFromRingbuf(t *testing.T) {
	service := svc.Attrs{
		SDKLanguage: svc.InstrumentableGolang,
		Features:    export.FeatureApplicationRuntime,
	}
	var record bytes.Buffer
	require.NoError(t, binary.Write(&record, binary.LittleEndian, goRuntimeMetricRawEvent{
		Type: EventTypeGoRuntimeMetric,
		PID: goRuntimeMetricRawKey{
			HostPID: 1000,
			UserPID: 123,
			Ns:      33,
		},
		Snapshot: goRuntimeMetricRawSnapshot{
			ValidMask: goRuntimeMetricValidGCCycles | goRuntimeMetricValidMemoryLimit |
				goRuntimeMetricValidProcessorLimit | goRuntimeMetricValidGOGC |
				goRuntimeMetricValidMemoryUsed | goRuntimeMetricValidMemoryAllocs,
			NumGC:             10,
			GOMAXPROCS:        4,
			GCPercent:         100,
			MemoryLimit:       1024,
			MemoryUsedStack:   2048,
			MemoryUsedOther:   4096,
			MemoryAllocated:   8192,
			MemoryAllocations: 64,
		},
	}))

	snapshot, ignore, err := SnapshotFromRingbuf(&ringbuf.Record{RawSample: record.Bytes()}, runtimeMetricFilter{
		current: map[uint32]map[app.PID]svc.Attrs{
			33: {
				123: service,
			},
		},
	})

	require.NoError(t, err)
	require.False(t, ignore)
	require.Equal(t, app.PID(123), snapshot.PID)
	require.Equal(t, service, snapshot.Service)
	require.NotNil(t, snapshot.Go)
	require.Equal(t, int64(1024), *snapshot.Go.MemoryLimit)
	require.Equal(t, int64(2048), *snapshot.Go.MemoryUsedStack)
	require.Equal(t, int64(4096), *snapshot.Go.MemoryUsedOther)
	require.Equal(t, uint64(8192), *snapshot.Go.MemoryAllocated)
	require.Equal(t, uint64(64), *snapshot.Go.MemoryAllocations)
	require.Nil(t, snapshot.JVM)
}

func TestSnapshotFromJVMRuntimeEvent(t *testing.T) {
	timestamp := time.Unix(123, 456)
	service := svc.Attrs{
		UID:         svc.UID{Name: "orders", Namespace: "prod"},
		SDKLanguage: svc.InstrumentableJava,
		Features:    export.FeatureApplicationRuntime,
	}

	snapshot := SnapshotFromJVMRuntimeEvent(jvmruntime.JVMRuntimeEvent{
		PID:        app.PID(123),
		Service:    service,
		Time:       timestamp,
		Kind:       jvmruntime.JVMMetricMemoryUsed,
		PoolName:   "G1 Eden Space",
		MemoryType: jvmruntime.JVMMemoryTypeHeap,
		GCPhase:    jvmruntime.JVMGCPhaseAfter,
		ValueBytes: 2048,
	})

	require.Equal(t, service, snapshot.Service)
	require.Equal(t, app.PID(123), snapshot.PID)
	require.Equal(t, timestamp, snapshot.Time)
	require.Nil(t, snapshot.Go)
	require.NotNil(t, snapshot.JVM)
	require.Equal(t, jvmruntime.JVMMetricMemoryUsed, snapshot.JVM.Kind)
	require.Equal(t, "G1 Eden Space", snapshot.JVM.PoolName)
	require.Equal(t, jvmruntime.JVMMemoryTypeHeap, snapshot.JVM.MemoryType)
	require.Equal(t, jvmruntime.JVMGCPhaseAfter, snapshot.JVM.GCPhase)
	require.Equal(t, uint64(2048), snapshot.JVM.ValueBytes)
}

func TestQueueSenderSendsJVMRuntimeSnapshots(t *testing.T) {
	service := svc.Attrs{
		UID:         svc.UID{Name: "orders", Namespace: "prod"},
		SDKLanguage: svc.InstrumentableJava,
		Features:    export.FeatureApplicationRuntime,
	}
	queue := msg.NewQueue[[]RuntimeMetricSnapshot](msg.ChannelBufferLen(1))
	received := queue.Subscribe(msg.SubscriberName("runtimemetrics-test"))

	NewQueueSender(queue).SendJVMRuntimeMetrics(t.Context(), []jvmruntime.JVMRuntimeEvent{{
		PID:        app.PID(123),
		Service:    service,
		Kind:       jvmruntime.JVMMetricMemoryUsed,
		GCPhase:    jvmruntime.JVMGCPhaseAfter,
		ValueBytes: 4096,
	}})

	batch := <-received
	require.Len(t, batch, 1)
	require.Equal(t, service, batch[0].Service)
	require.NotNil(t, batch[0].JVM)
	require.Equal(t, jvmruntime.JVMMetricMemoryUsed, batch[0].JVM.Kind)
	require.Equal(t, uint64(4096), batch[0].JVM.ValueBytes)
}

func TestQueueSenderSendsGoRuntimeSnapshots(t *testing.T) {
	service := svc.Attrs{
		SDKLanguage: svc.InstrumentableGolang,
		Features:    export.FeatureApplicationRuntime,
	}
	var record bytes.Buffer
	require.NoError(t, binary.Write(&record, binary.LittleEndian, goRuntimeMetricRawEvent{
		Type: EventTypeGoRuntimeMetric,
		PID: goRuntimeMetricRawKey{
			UserPID: 123,
			Ns:      33,
		},
		Snapshot: goRuntimeMetricRawSnapshot{
			ValidMask:   goRuntimeMetricValidGCCycles | goRuntimeMetricValidMemoryLimit | goRuntimeMetricValidProcessorLimit | goRuntimeMetricValidGOGC,
			NumGC:       10,
			GOMAXPROCS:  4,
			GCPercent:   100,
			MemoryLimit: 1024,
		},
	}))

	queue := msg.NewQueue[[]RuntimeMetricSnapshot](msg.ChannelBufferLen(1))
	received := queue.Subscribe(msg.SubscriberName("runtimemetrics-test"))

	err := NewQueueSender(queue).SendGoRuntimeMetricRecord(t.Context(), &ringbuf.Record{RawSample: record.Bytes()}, runtimeMetricFilter{
		current: map[uint32]map[app.PID]svc.Attrs{
			33: {123: service},
		},
	})
	require.NoError(t, err)

	batch := <-received
	require.Len(t, batch, 1)
	require.Equal(t, service, batch[0].Service)
	require.NotNil(t, batch[0].Go)
	require.Equal(t, int64(1024), *batch[0].Go.MemoryLimit)
}

type runtimeMetricFilter struct {
	current map[uint32]map[app.PID]svc.Attrs
}

func (f runtimeMetricFilter) AllowPID(app.PID, uint32, *exec.FileInfo, ebpfcommon.PIDType) {}
func (f runtimeMetricFilter) BlockPID(app.PID, uint32)                                     {}
func (f runtimeMetricFilter) ValidPID(app.PID, uint32, ebpfcommon.PIDType) bool            { return false }
func (f runtimeMetricFilter) Filter(spans []request.Span) []request.Span                   { return spans }
func (f runtimeMetricFilter) CurrentPIDs(ebpfcommon.PIDType) map[uint32]map[app.PID]svc.Attrs {
	return f.current
}
