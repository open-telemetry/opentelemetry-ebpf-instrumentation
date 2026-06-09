// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/export"
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
	require.NotNil(t, snapshot.GCCycles)
	require.Equal(t, uint64(10), *snapshot.GCCycles)
	require.NotNil(t, snapshot.ProcessorLimit)
	require.Equal(t, int64(4), *snapshot.ProcessorLimit)
	require.NotNil(t, snapshot.GOGC)
	require.Equal(t, int64(100), *snapshot.GOGC)
	require.NotNil(t, snapshot.MemoryLimit)
	require.Equal(t, int64(1024), *snapshot.MemoryLimit)
}

func TestConvertGoRuntimeMetricSnapshotSuppressesUnavailableValues(t *testing.T) {
	snapshot := convertGoRuntimeMetricSnapshot(svc.Attrs{}, app.PID(123), goRuntimeMetricRawSnapshot{
		NumGC:       1,
		NumForcedGC: 1,
		GCPercent:   -1,
		MemoryLimit: math.MaxInt64,
	})
	require.Nil(t, snapshot.GOGC)
	require.Nil(t, snapshot.MemoryLimit)
}

func TestConvertGoRuntimeMetricSnapshotUsesTotalGCCycles(t *testing.T) {
	snapshot := convertGoRuntimeMetricSnapshot(svc.Attrs{}, app.PID(123), goRuntimeMetricRawSnapshot{
		NumGC:       1,
		NumForcedGC: 2,
		GOMAXPROCS:  4,
	})
	require.NotNil(t, snapshot.GCCycles)
	require.Equal(t, uint64(1), *snapshot.GCCycles)
	require.NotNil(t, snapshot.ProcessorLimit)
}

func TestConvertGoRuntimeMetricSnapshotSuppressesInvalidProcessorLimit(t *testing.T) {
	snapshot := convertGoRuntimeMetricSnapshot(svc.Attrs{}, app.PID(123), goRuntimeMetricRawSnapshot{
		NumGC:       1,
		NumForcedGC: 1,
		GOMAXPROCS:  0,
	})
	require.Nil(t, snapshot.ProcessorLimit)
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
	require.NotNil(t, snapshot.MemoryLimit)
	require.Equal(t, int64(1024), *snapshot.MemoryLimit)
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
