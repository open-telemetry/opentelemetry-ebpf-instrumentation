// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
	"time"

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

func TestConvertGoRuntimeMetricSnapshot(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "svc"}}

	snapshot := convertGoRuntimeMetricSnapshot(service, app.PID(123), goRuntimeMetricRawSnapshot{
		NumGC:       10,
		NumForcedGC: 3,
		GOMAXPROCS:  4,
		GCPercent:   100,
		MemoryLimit: 1024,
	})
	require.NotNil(t, snapshot.Go)
	require.Equal(t, uint64(10), *snapshot.Go.GCCycles)
	require.Equal(t, int64(4), *snapshot.Go.ProcessorLimit)
	require.Equal(t, int64(100), *snapshot.Go.GOGC)
	require.Equal(t, int64(1024), *snapshot.Go.MemoryLimit)
	require.Nil(t, snapshot.JVM)
}

func TestConvertGoRuntimeMetricSnapshotSuppressesUnavailableValues(t *testing.T) {
	snapshot := convertGoRuntimeMetricSnapshot(svc.Attrs{}, app.PID(123), goRuntimeMetricRawSnapshot{
		NumGC:       1,
		NumForcedGC: 1,
		GCPercent:   -1,
		MemoryLimit: math.MaxInt64,
	})
	require.NotNil(t, snapshot.Go)
	require.Nil(t, snapshot.Go.GOGC)
	require.Nil(t, snapshot.Go.MemoryLimit)
}

func TestConvertGoRuntimeMetricSnapshotUsesTotalGCCycles(t *testing.T) {
	snapshot := convertGoRuntimeMetricSnapshot(svc.Attrs{}, app.PID(123), goRuntimeMetricRawSnapshot{
		NumGC:       1,
		NumForcedGC: 2,
		GOMAXPROCS:  4,
	})
	require.NotNil(t, snapshot.Go)
	require.Equal(t, uint64(1), *snapshot.Go.GCCycles)
	require.NotNil(t, snapshot.Go.ProcessorLimit)
}

func TestConvertGoRuntimeMetricSnapshotSuppressesInvalidProcessorLimit(t *testing.T) {
	snapshot := convertGoRuntimeMetricSnapshot(svc.Attrs{}, app.PID(123), goRuntimeMetricRawSnapshot{
		NumGC:       1,
		NumForcedGC: 1,
		GOMAXPROCS:  0,
	})
	require.NotNil(t, snapshot.Go)
	require.Nil(t, snapshot.Go.ProcessorLimit)
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
			NumGC:       10,
			NumForcedGC: 3,
			GOMAXPROCS:  4,
			GCPercent:   100,
			MemoryLimit: 1024,
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
	require.Nil(t, snapshot.JVM)
}

func TestSnapshotFromJVMRuntimeEvent(t *testing.T) {
	timestamp := time.Unix(123, 456)
	service := svc.Attrs{
		UID:         svc.UID{Name: "orders", Namespace: "prod"},
		SDKLanguage: svc.InstrumentableJava,
		Features:    export.FeatureApplicationJVM,
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
		Features:    export.FeatureApplicationJVM,
	}
	queue := msg.NewQueue[[]RuntimeMetricSnapshot](msg.ChannelBufferLen(1))
	received := queue.Subscribe(msg.SubscriberName("runtimemetrics-test"))

	NewQueueSender(queue).SendJVMRuntimeMetrics(t.Context(), []jvmruntime.JVMRuntimeEvent{{
		PID:        app.PID(123),
		Service:    service,
		Kind:       jvmruntime.JVMMetricObiHeapUsed,
		GCPhase:    jvmruntime.JVMGCPhaseAfter,
		ValueBytes: 4096,
	}})

	batch := <-received
	require.Len(t, batch, 1)
	require.Equal(t, service, batch[0].Service)
	require.NotNil(t, batch[0].JVM)
	require.Equal(t, jvmruntime.JVMMetricObiHeapUsed, batch[0].JVM.Kind)
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
