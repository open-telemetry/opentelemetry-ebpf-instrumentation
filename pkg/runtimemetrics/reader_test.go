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
	appruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
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

	require.Equal(t, uintptr(168), unsafe.Sizeof(event))
	require.Equal(t, uintptr(16), unsafe.Offsetof(event.Generation))
	require.Equal(t, uintptr(24), unsafe.Offsetof(event.Snapshot))
	require.Equal(t, uintptr(144), unsafe.Sizeof(snapshot))
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
	require.Equal(t, uintptr(128), unsafe.Offsetof(snapshot.GoroutineCount))
	require.Equal(t, uintptr(136), unsafe.Offsetof(snapshot.MemoryGCGoal))
}

func TestPythonRuntimeMetricRawABI(t *testing.T) {
	var event pythonRuntimeMetricRawEvent
	var snapshot pythonRuntimeMetricRawSnapshot

	require.Equal(t, byte(29), byte(EventTypePythonRuntimeMetric))
	require.Equal(t, uintptr(96), unsafe.Sizeof(event))
	require.Equal(t, uintptr(4), unsafe.Offsetof(event.PID))
	require.Equal(t, uintptr(16), unsafe.Offsetof(event.Snapshot))
	require.Equal(t, uintptr(80), unsafe.Sizeof(snapshot))
	require.Equal(t, uintptr(8), unsafe.Offsetof(snapshot.Generations))
}

func TestGoRuntimeHistogramRawABI(t *testing.T) {
	var event goRuntimeHistogramRawEvent

	require.Equal(t, byte(21), byte(EventTypeGoRuntimeHistogram))
	require.Equal(t, GoHistogramKindGCPause, GoHistogramKind(0))
	require.Equal(t, GoHistogramKindSchedLatency, GoHistogramKind(1))
	require.Equal(t, uintptr(1328), unsafe.Sizeof(event))
	require.Equal(t, uintptr(0), unsafe.Offsetof(event.Type))
	require.Equal(t, uintptr(1), unsafe.Offsetof(event.Kind))
	require.Equal(t, uintptr(2), unsafe.Offsetof(event.Pad))
	require.Equal(t, uintptr(4), unsafe.Offsetof(event.PID))
	require.Equal(t, uintptr(16), unsafe.Offsetof(event.BucketCount))
	require.Equal(t, uintptr(20), unsafe.Offsetof(event.Pad2))
	require.Equal(t, uintptr(24), unsafe.Offsetof(event.Underflow))
	require.Equal(t, uintptr(32), unsafe.Offsetof(event.Overflow))
	require.Equal(t, uintptr(40), unsafe.Offsetof(event.Generation))
	require.Equal(t, uintptr(48), unsafe.Offsetof(event.Counts))
}

func TestGoRuntimeMetricValidMaskABI(t *testing.T) {
	require.Equal(t, goRuntimeMetricValidGCCycles, uint64(1<<0))
	require.Equal(t, goRuntimeMetricValidMemoryLimit, uint64(1<<1))
	require.Equal(t, goRuntimeMetricValidProcessorLimit, uint64(1<<2))
	require.Equal(t, goRuntimeMetricValidGOGC, uint64(1<<3))
	require.Equal(t, goRuntimeMetricValidCPUTime, uint64(1<<4))
	require.Equal(t, goRuntimeMetricValidMemoryUsed, uint64(1<<5))
	require.Equal(t, goRuntimeMetricValidMemoryAllocs, uint64(1<<6))
	require.Equal(t, goRuntimeMetricValidGoroutineCount, uint64(1<<9))
	require.Equal(t, goRuntimeMetricValidMemoryGCGoal, uint64(1<<10))
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

func TestConvertGoRuntimeMetricSnapshotIncludesPositiveGoroutineCount(t *testing.T) {
	snapshot := convertGoRuntimeMetricSnapshot(svc.Attrs{}, app.PID(123), goRuntimeMetricRawSnapshot{
		ValidMask:      goRuntimeMetricValidGoroutineCount,
		GoroutineCount: 17,
	})

	require.NotNil(t, snapshot.Go)
	require.NotNil(t, snapshot.Go.GoroutineCount)
	require.Equal(t, int64(17), *snapshot.Go.GoroutineCount)
}

func TestConvertGoRuntimeMetricSnapshotSuppressesInvalidGoroutineCount(t *testing.T) {
	for _, raw := range []goRuntimeMetricRawSnapshot{
		{GoroutineCount: 17},
		{ValidMask: goRuntimeMetricValidGoroutineCount},
		{ValidMask: goRuntimeMetricValidGoroutineCount, GoroutineCount: -1},
	} {
		snapshot := convertGoRuntimeMetricSnapshot(svc.Attrs{}, app.PID(123), raw)
		require.NotNil(t, snapshot.Go)
		require.Nil(t, snapshot.Go.GoroutineCount)
	}
}

func TestConvertGoRuntimeMetricSnapshotIncludesExactGCGoal(t *testing.T) {
	snapshot := convertGoRuntimeMetricSnapshot(svc.Attrs{}, app.PID(123), goRuntimeMetricRawSnapshot{
		ValidMask:    goRuntimeMetricValidMemoryGCGoal,
		MemoryGCGoal: 123456789,
	})

	require.NotNil(t, snapshot.Go.MemoryGCGoal)
	require.Equal(t, int64(123456789), *snapshot.Go.MemoryGCGoal)
}

func TestConvertGoRuntimeMetricSnapshotSuppressesInvalidGCGoal(t *testing.T) {
	for _, raw := range []goRuntimeMetricRawSnapshot{
		{MemoryGCGoal: 1024},
		{ValidMask: goRuntimeMetricValidMemoryGCGoal},
		{ValidMask: goRuntimeMetricValidMemoryGCGoal, MemoryGCGoal: uint64(math.MaxInt64) + 1},
	} {
		snapshot := convertGoRuntimeMetricSnapshot(svc.Attrs{}, app.PID(123), raw)
		require.Nil(t, snapshot.Go.MemoryGCGoal)
	}
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
		Type:       EventTypeGoRuntimeMetric,
		Generation: 17,
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
	require.Equal(t, app.PID(1000), snapshot.PID)
	require.Equal(t, uint64(17), snapshot.Generation)
	require.Equal(t, service, snapshot.Service)
	require.NotNil(t, snapshot.Go)
	require.Equal(t, int64(1024), *snapshot.Go.MemoryLimit)
	require.Equal(t, int64(2048), *snapshot.Go.MemoryUsedStack)
	require.Equal(t, int64(4096), *snapshot.Go.MemoryUsedOther)
	require.Equal(t, uint64(8192), *snapshot.Go.MemoryAllocated)
	require.Equal(t, uint64(64), *snapshot.Go.MemoryAllocations)
	require.Nil(t, snapshot.JVM)
}

func TestSnapshotFromRingbufDecodesHistogramAndCopiesCounts(t *testing.T) {
	service := svc.Attrs{
		SDKLanguage: svc.InstrumentableGolang,
		Features:    export.FeatureApplicationRuntime,
	}
	event := goRuntimeHistogramRawEvent{
		Type:       EventTypeGoRuntimeHistogram,
		Kind:       GoHistogramKindSchedLatency,
		Generation: 23,
		PID: goRuntimeMetricRawKey{
			HostPID: 1000,
			UserPID: 123,
			Ns:      33,
		},
		BucketCount: goRuntimeHistogramMaxBuckets,
		Underflow:   4,
		Overflow:    5,
		Counts:      [goRuntimeHistogramMaxBuckets]uint64{10, 20, 30, 40},
	}
	record := histogramRecord(t, event)
	before := time.Now()

	snapshot, ignore, err := SnapshotFromRingbuf(record, runtimeMetricFilter{
		current: map[uint32]map[app.PID]svc.Attrs{33: {123: service}},
	})
	after := time.Now()

	require.NoError(t, err)
	require.False(t, ignore)
	require.Equal(t, service, snapshot.Service)
	require.Equal(t, app.PID(1000), snapshot.PID)
	require.Equal(t, uint64(23), snapshot.Generation)
	require.False(t, snapshot.Time.Before(before))
	require.False(t, snapshot.Time.After(after))
	require.Nil(t, snapshot.Go)
	require.Nil(t, snapshot.JVM)
	require.NotNil(t, snapshot.Histogram)
	require.Equal(t, GoHistogramKindSchedLatency, snapshot.Histogram.Kind)
	require.Len(t, snapshot.Histogram.Counts, goRuntimeHistogramMaxBuckets)
	require.Equal(t, []uint64{10, 20, 30, 40}, snapshot.Histogram.Counts[:4])
	require.Zero(t, snapshot.Histogram.Counts[4])
	require.Equal(t, uint64(4), snapshot.Histogram.Underflow)
	require.Equal(t, uint64(5), snapshot.Histogram.Overflow)

	binary.LittleEndian.PutUint64(record.RawSample[unsafe.Offsetof(event.Counts):], 99)
	require.Equal(t, []uint64{10, 20, 30, 40}, snapshot.Histogram.Counts[:4])
}

func TestSnapshotFromRingbufRejectsMalformedHistogram(t *testing.T) {
	filter := runtimeMetricFilter{current: map[uint32]map[app.PID]svc.Attrs{
		33: {123: {Features: export.FeatureApplicationRuntime}},
	}}

	for _, tc := range []struct {
		name    string
		event   goRuntimeHistogramRawEvent
		wantErr string
	}{
		{
			name: "zero bucket count",
			event: goRuntimeHistogramRawEvent{
				Type: EventTypeGoRuntimeHistogram, Kind: GoHistogramKindGCPause,
				PID: goRuntimeMetricRawKey{UserPID: 123, Ns: 33},
			},
			wantErr: "bucket count 0",
		},
		{
			name: "short bucket count",
			event: goRuntimeHistogramRawEvent{
				Type: EventTypeGoRuntimeHistogram, Kind: GoHistogramKindGCPause,
				PID: goRuntimeMetricRawKey{UserPID: 123, Ns: 33}, BucketCount: goRuntimeHistogramMaxBuckets - 1,
			},
			wantErr: "bucket count 159",
		},
		{
			name: "excessive bucket count",
			event: goRuntimeHistogramRawEvent{
				Type: EventTypeGoRuntimeHistogram, Kind: GoHistogramKindGCPause,
				PID: goRuntimeMetricRawKey{UserPID: 123, Ns: 33}, BucketCount: goRuntimeHistogramMaxBuckets + 1,
			},
			wantErr: "bucket count 161",
		},
		{
			name: "unsupported kind",
			event: goRuntimeHistogramRawEvent{
				Type: EventTypeGoRuntimeHistogram, Kind: GoHistogramKind(2),
				PID: goRuntimeMetricRawKey{UserPID: 123, Ns: 33}, BucketCount: goRuntimeHistogramMaxBuckets,
			},
			wantErr: "histogram kind 2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ignore, err := SnapshotFromRingbuf(histogramRecord(t, tc.event), filter)

			require.ErrorContains(t, err, tc.wantErr)
			require.True(t, ignore)
		})
	}
}

func TestSnapshotFromRingbufRejectsTruncatedHistogram(t *testing.T) {
	_, ignore, err := SnapshotFromRingbuf(&ringbuf.Record{
		RawSample: []byte{EventTypeGoRuntimeHistogram},
	}, nil)

	require.ErrorContains(t, err, "decode Go runtime histogram event: byte slice too short")
	require.True(t, ignore)
}

func TestSnapshotFromJVMGCEvent(t *testing.T) {
	timestamp := time.Unix(123, 456)
	service := svc.Attrs{
		UID:         svc.UID{Name: "orders", Namespace: "prod"},
		SDKLanguage: svc.InstrumentableJava,
		Features:    export.FeatureApplicationRuntime,
	}

	snapshot := SnapshotFromJVMGCEvent(appruntime.JVMGCEvent{
		PID:        app.PID(123),
		Service:    service,
		Time:       timestamp,
		Kind:       appruntime.JVMMetricMemoryUsed,
		PoolName:   "G1 Eden Space",
		MemoryType: appruntime.JVMMemoryTypeHeap,
		GCPhase:    appruntime.JVMGCPhaseAfter,
		ValueBytes: 2048,
	})

	require.Equal(t, service, snapshot.Service)
	require.Equal(t, app.PID(123), snapshot.PID)
	require.Equal(t, timestamp, snapshot.Time)
	require.Nil(t, snapshot.Go)
	require.NotNil(t, snapshot.JVM)
	require.Equal(t, appruntime.JVMMetricMemoryUsed, snapshot.JVM.Kind)
	require.Equal(t, "G1 Eden Space", snapshot.JVM.PoolName)
	require.Equal(t, appruntime.JVMMemoryTypeHeap, snapshot.JVM.MemoryType)
	require.Equal(t, appruntime.JVMGCPhaseAfter, snapshot.JVM.GCPhase)
	require.Equal(t, uint64(2048), snapshot.JVM.ValueBytes)
}

func TestSnapshotFromJVMRuntimeEvent(t *testing.T) {
	values := appruntime.JVMRuntimeValues{
		LoadedClassCount:     11,
		ProcessCPUTimeNS:     12,
		RecentCPUUtilization: 0.25,
	}
	event := appruntime.JVMRuntimeEvent{
		PID:        app.PID(123),
		Generation: 17,
		Service:    svc.Attrs{UID: svc.UID{Name: "orders"}},
		Time:       time.Unix(123, 456),
		Values:     values,
	}

	snapshot := SnapshotFromJVMRuntimeEvent(event)

	require.Equal(t, event.Service, snapshot.Service)
	require.Equal(t, event.PID, snapshot.PID)
	require.Equal(t, event.Generation, snapshot.Generation)
	require.Equal(t, event.Time, snapshot.Time)
	require.NotNil(t, snapshot.JVM)
	require.Equal(t, values, *snapshot.JVM.RuntimeValues)
}

func TestSnapshotFromJVMGCDurationEvent(t *testing.T) {
	event := appruntime.JVMGCEvent{
		PID:        app.PID(123),
		Service:    svc.Attrs{UID: svc.UID{Name: "orders"}},
		Time:       time.Unix(123, 456),
		Kind:       appruntime.JVMMetricGCDuration,
		GCName:     "G1 Young Generation",
		GCAction:   "end of minor GC",
		DurationNS: 25_000_000,
	}

	snapshot := SnapshotFromJVMGCEvent(event)

	require.Equal(t, event.Service, snapshot.Service)
	require.Equal(t, event.PID, snapshot.PID)
	require.Equal(t, event.Time, snapshot.Time)
	require.NotNil(t, snapshot.JVM)
	require.Equal(t, appruntime.JVMMetricGCDuration, snapshot.JVM.Kind)
	require.Equal(t, "G1 Young Generation", snapshot.JVM.GCName)
	require.Equal(t, "end of minor GC", snapshot.JVM.GCAction)
	require.Equal(t, uint64(25_000_000), snapshot.JVM.DurationNS)
}

func TestQueueSenderSendsJVMRuntimeSnapshots(t *testing.T) {
	service := svc.Attrs{
		UID:         svc.UID{Name: "orders", Namespace: "prod"},
		SDKLanguage: svc.InstrumentableJava,
		Features:    export.FeatureApplicationRuntime,
	}
	queue := msg.NewQueue[[]RuntimeMetricSnapshot](msg.ChannelBufferLen(1))
	received := queue.Subscribe(msg.SubscriberName("runtimemetrics-test"))

	NewQueueSender(queue).SendJVMGCMetrics(t.Context(), []appruntime.JVMGCEvent{{
		PID:        app.PID(123),
		Service:    service,
		Kind:       appruntime.JVMMetricMemoryUsed,
		GCPhase:    appruntime.JVMGCPhaseAfter,
		ValueBytes: 4096,
	}})

	batch := <-received
	require.Len(t, batch, 1)
	require.Equal(t, service, batch[0].Service)
	require.NotNil(t, batch[0].JVM)
	require.Equal(t, appruntime.JVMMetricMemoryUsed, batch[0].JVM.Kind)
	require.Equal(t, uint64(4096), batch[0].JVM.ValueBytes)
}

func TestQueueSenderSendsJVMRuntimeMetrics(t *testing.T) {
	queue := msg.NewQueue[[]RuntimeMetricSnapshot](msg.ChannelBufferLen(1))
	received := queue.Subscribe(msg.SubscriberName("jvm-runtime-metrics-test"))
	values := appruntime.JVMRuntimeValues{LoadedClassCount: 11}

	NewQueueSender(queue).SendJVMRuntimeMetrics(t.Context(), []appruntime.JVMRuntimeEvent{{
		PID:        app.PID(123),
		Generation: 17,
		Values:     values,
	}})

	batch := <-received
	require.Len(t, batch, 1)
	require.Equal(t, uint64(17), batch[0].Generation)
	require.Equal(t, values, *batch[0].JVM.RuntimeValues)
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

func TestQueueSenderSendsGoRuntimeHistogramSnapshots(t *testing.T) {
	service := svc.Attrs{
		SDKLanguage: svc.InstrumentableGolang,
		Features:    export.FeatureApplicationRuntime,
	}
	record := histogramRecord(t, goRuntimeHistogramRawEvent{
		Type:        EventTypeGoRuntimeHistogram,
		Kind:        GoHistogramKindGCPause,
		PID:         goRuntimeMetricRawKey{UserPID: 123, Ns: 33},
		BucketCount: goRuntimeHistogramMaxBuckets,
		Counts:      [goRuntimeHistogramMaxBuckets]uint64{7, 8},
	})
	queue := msg.NewQueue[[]RuntimeMetricSnapshot](msg.ChannelBufferLen(1))
	received := queue.Subscribe(msg.SubscriberName("runtimemetrics-histogram-test"))

	err := NewQueueSender(queue).SendGoRuntimeMetricRecord(t.Context(), record, runtimeMetricFilter{
		current: map[uint32]map[app.PID]svc.Attrs{33: {123: service}},
	})
	require.NoError(t, err)

	batch := <-received
	require.Len(t, batch, 1)
	require.Equal(t, service, batch[0].Service)
	require.NotNil(t, batch[0].Histogram)
	require.Len(t, batch[0].Histogram.Counts, goRuntimeHistogramMaxBuckets)
	require.Equal(t, []uint64{7, 8}, batch[0].Histogram.Counts[:2])
}

func histogramRecord(t *testing.T, event goRuntimeHistogramRawEvent) *ringbuf.Record {
	t.Helper()

	var raw bytes.Buffer
	require.NoError(t, binary.Write(&raw, binary.LittleEndian, event))
	return &ringbuf.Record{RawSample: raw.Bytes()}
}

func TestPythonRuntimeMetricSnapshotContainsEveryGeneration(t *testing.T) {
	snapshot := PythonRuntimeMetricSnapshot{
		Generations: [3]PythonGCGenerationMetrics{
			{Collections: 1, CollectedObjects: 2, UncollectableObjects: 3},
			{Collections: 4, CollectedObjects: 5, UncollectableObjects: 6},
			{Collections: 7, CollectedObjects: 8, UncollectableObjects: 9},
		},
	}

	require.Equal(t, uint64(1), snapshot.Generations[0].Collections)
	require.Equal(t, uint64(5), snapshot.Generations[1].CollectedObjects)
	require.Equal(t, uint64(9), snapshot.Generations[2].UncollectableObjects)
}

func TestPythonRuntimeMetricRecordConvertsEveryGeneration(t *testing.T) {
	service := svc.Attrs{
		UID: svc.UID{Name: "python"}, Features: export.FeatureApplicationRuntime,
	}
	event := pythonRuntimeMetricRawEvent{
		Type: EventTypePythonRuntimeMetric,
		PID:  goRuntimeMetricRawKey{HostPID: 123, UserPID: 23, Ns: 42},
		Snapshot: pythonRuntimeMetricRawSnapshot{
			Generation: 9,
			Generations: [3]pythonGCGenerationRawMetrics{
				{Collections: 1, Collected: 2, Uncollectable: 3},
				{Collections: 4, Collected: 5, Uncollectable: 6},
				{Collections: 7, Collected: 8, Uncollectable: 9},
			},
		},
	}
	var raw bytes.Buffer
	require.NoError(t, binary.Write(&raw, binary.LittleEndian, event))

	snapshot, ignore, err := pythonSnapshotFromRingbuf(
		&ringbuf.Record{RawSample: raw.Bytes()},
		runtimeMetricFilter{current: map[uint32]map[app.PID]svc.Attrs{42: {23: service}}},
	)

	require.NoError(t, err)
	require.False(t, ignore)
	require.NotNil(t, snapshot.Python)
	require.Equal(t, app.PID(123), snapshot.PID)
	require.Equal(t, uint64(9), snapshot.Generation)
	require.Equal(t, app.PID(123), snapshot.Service.ProcPID)
	require.Equal(t, uint64(1), snapshot.Python.Generations[0].Collections)
	require.Equal(t, uint64(5), snapshot.Python.Generations[1].CollectedObjects)
	require.Equal(t, uint64(9), snapshot.Python.Generations[2].UncollectableObjects)
}

func TestPythonRuntimeMetricsFromTerminationOrdersFinalBeforeTombstone(t *testing.T) {
	fileInfo := exec.New(exec.Init{Service: svc.Attrs{
		UID: svc.UID{Name: "python"}, Features: export.FeatureApplicationRuntime,
	}})
	event := exec.ProcessEvent{
		Type: exec.ProcessEventTerminated,
		File: fileInfo,
		FinalPythonRuntimeMetrics: []appruntime.PythonRuntimeMetricFinal{{
			PID: 123, Generation: 7, Time: time.Unix(1, 0), HasValue: true,
			Generations: [3]appruntime.PythonGCGenerationMetrics{{Collections: 12}},
		}},
	}

	snapshots := PythonRuntimeMetricsFromProcessEvent(event)
	require.Len(t, snapshots, 2)
	require.NotNil(t, snapshots[0].Python)
	require.False(t, snapshots[0].Removed)
	require.Equal(t, uint64(12), snapshots[0].Python.Generations[0].Collections)
	require.True(t, snapshots[1].Removed)
	require.Equal(t, uint64(7), snapshots[1].Generation)
}

type runtimeMetricFilter struct {
	current map[uint32]map[app.PID]svc.Attrs
}

func (f runtimeMetricFilter) AllowPID(app.PID, uint32, *exec.FileInfo, ebpfcommon.PIDType) {}
func (f runtimeMetricFilter) BlockPID(app.PID, uint32)                                     {}
func (f runtimeMetricFilter) ValidPID(app.PID, uint32, ebpfcommon.PIDType) bool            { return false }

func (f runtimeMetricFilter) Filter(spans []request.Span) []request.Span { return spans }

func (f runtimeMetricFilter) CurrentPIDs(ebpfcommon.PIDType) map[uint32]map[app.PID]svc.Attrs {
	return f.current
}
