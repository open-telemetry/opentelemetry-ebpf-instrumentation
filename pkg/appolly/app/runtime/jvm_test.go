// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
)

func TestParseJVMMemoryPoolEventMapsPoolCounters(t *testing.T) {
	const ktime = 2 * 3600 * 1_000_000_000 // 2h since boot

	events, err := ParseJVMMemoryPoolEvent(
		ktime,
		4321,
		9001,
		RawJVMGCWhenBefore,
		2048,
		4096,
		8192,
		rawJVMString("G1 Eden Space"),
	)
	require.NoError(t, err)
	requireJVMEvents(t, ktime, events, []JVMRuntimeEvent{
		{
			PID:            app.PID(4321),
			PIDNamespaceID: 9001,
			Kind:           JVMMetricMemoryUsed,
			PoolName:       "G1 Eden Space",
			MemoryType:     JVMMemoryTypeHeap,
			GCPhase:        JVMGCPhaseBefore,
			ValueBytes:     2048,
		},
		{
			PID:            app.PID(4321),
			PIDNamespaceID: 9001,
			Kind:           JVMMetricMemoryCommitted,
			PoolName:       "G1 Eden Space",
			MemoryType:     JVMMemoryTypeHeap,
			GCPhase:        JVMGCPhaseBefore,
			ValueBytes:     4096,
		},
		{
			PID:            app.PID(4321),
			PIDNamespaceID: 9001,
			Kind:           JVMMetricMemoryLimit,
			PoolName:       "G1 Eden Space",
			MemoryType:     JVMMemoryTypeHeap,
			GCPhase:        JVMGCPhaseBefore,
			ValueBytes:     8192,
		},
	})
}

func TestParseJVMMemoryPoolEventAddsUsedAfterLastGCForEndEvents(t *testing.T) {
	const ktime = 90 * 60 * 1_000_000_000 // 90min since boot

	events, err := ParseJVMMemoryPoolEvent(
		ktime,
		2,
		43,
		RawJVMGCWhenAfter,
		300,
		400,
		math.MaxUint64,
		rawJVMString("Metaspace"),
	)
	require.NoError(t, err)
	requireJVMEvents(t, ktime, events, []JVMRuntimeEvent{
		{
			PID:            app.PID(2),
			PIDNamespaceID: 43,
			Kind:           JVMMetricMemoryUsed,
			PoolName:       "Metaspace",
			MemoryType:     JVMMemoryTypeNonHeap,
			GCPhase:        JVMGCPhaseAfter,
			ValueBytes:     300,
		},
		{
			PID:            app.PID(2),
			PIDNamespaceID: 43,
			Kind:           JVMMetricMemoryCommitted,
			PoolName:       "Metaspace",
			MemoryType:     JVMMemoryTypeNonHeap,
			GCPhase:        JVMGCPhaseAfter,
			ValueBytes:     400,
		},
		{
			PID:            app.PID(2),
			PIDNamespaceID: 43,
			Kind:           JVMMetricMemoryUsedAfterLastGC,
			PoolName:       "Metaspace",
			MemoryType:     JVMMemoryTypeNonHeap,
			GCPhase:        JVMGCPhaseAfter,
			ValueBytes:     300,
		},
	})
}

func TestRawJVMStringTrimsAtNULAndHonorsFixedBound(t *testing.T) {
	var raw [JVMRawStringLen]byte
	copy(raw[:], []byte("abc\x00ignored"))

	require.Equal(t, "abc", DecodeJVMRawString(raw))

	var long [JVMRawStringLen]byte
	for i := range long {
		long[i] = 'x'
	}
	require.Len(t, DecodeJVMRawString(long), JVMRawStringLen)
}

func TestInferJVMMemoryTypeRecognizesModernHotSpotHeapPools(t *testing.T) {
	for _, pool := range []string{
		"ZHeap",
		"Shenandoah",
		"Epsilon Heap",
		"G1 Humongous Space",
	} {
		require.Equal(t, JVMMemoryTypeHeap, InferJVMMemoryType(pool), pool)
	}
}

func TestInferJVMMemoryTypeKeepsCodeHeapNonHeap(t *testing.T) {
	require.Equal(t, JVMMemoryTypeNonHeap, InferJVMMemoryType("CodeHeap 'non-nmethods'"))
}

func TestInferJVMMemoryTypeReturnsUnknownForUnrecognizedPool(t *testing.T) {
	require.Equal(t, JVMMemoryTypeUnknown, InferJVMMemoryType("vendor-specific pool"))
}

func TestParseJVMMemoryPoolEventRejectsUnsupportedPhase(t *testing.T) {
	_, err := ParseJVMMemoryPoolEvent(0, 0, 0, RawJVMGCWhenEndSentinel, 0, 0, 0, rawJVMString("G1 Eden Space"))
	require.ErrorContains(t, err, "unsupported JVM GC phase")
}

func rawJVMString(value string) [JVMRawStringLen]byte {
	var raw [JVMRawStringLen]byte
	copy(raw[:], []byte(value))
	return raw
}

// requireJVMEvents compares the parsed events, checking Time separately: the
// parser stamps it from the current clocks, so it cannot equal a value the
// test computes microseconds later.
func requireJVMEvents(t *testing.T, ktime uint64, got, want []JVMRuntimeEvent) {
	t.Helper()
	require.Len(t, got, len(want))

	// The tolerance only absorbs the scheduling gap between the parser's
	// conversion and this one (measured worst case ~15µs; 100ms leaves room
	// for a CPU-throttled CI runner), not elapsed time: both clocks advance
	// together, so the wait cancels out. Keep it as tight as the machine
	// allows — it is the smallest stamping error the test can detect.
	const tolerance = 100 * time.Millisecond

	expected := timing.KernelTime(ktime)
	first := got[0].Time
	for i := range got {
		require.WithinDuration(t, expected, got[i].Time, tolerance)
		require.Equal(t, first, got[i].Time, "all events of a batch share one timestamp")
		got[i].Time = time.Time{}
	}
	require.Equal(t, want, got)
}
