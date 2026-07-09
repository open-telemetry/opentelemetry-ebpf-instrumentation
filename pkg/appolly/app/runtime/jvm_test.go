// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func TestParseJVMMemoryPoolEventMapsPoolCounters(t *testing.T) {
	eventTime := setJVMTestClocks(t)

	events, err := ParseJVMMemoryPoolEvent(
		123456789,
		4321,
		9001,
		RawJVMGCWhenBefore,
		2048,
		4096,
		8192,
		rawJVMString("G1 Eden Space"),
	)
	require.NoError(t, err)
	require.Equal(t, []JVMRuntimeEvent{
		{
			PID:            app.PID(4321),
			PIDNamespaceID: 9001,
			Time:           eventTime(123456789),
			Kind:           JVMMetricMemoryUsed,
			PoolName:       "G1 Eden Space",
			MemoryType:     JVMMemoryTypeHeap,
			GCPhase:        JVMGCPhaseBefore,
			ValueBytes:     2048,
		},
		{
			PID:            app.PID(4321),
			PIDNamespaceID: 9001,
			Time:           eventTime(123456789),
			Kind:           JVMMetricMemoryCommitted,
			PoolName:       "G1 Eden Space",
			MemoryType:     JVMMemoryTypeHeap,
			GCPhase:        JVMGCPhaseBefore,
			ValueBytes:     4096,
		},
		{
			PID:            app.PID(4321),
			PIDNamespaceID: 9001,
			Time:           eventTime(123456789),
			Kind:           JVMMetricMemoryLimit,
			PoolName:       "G1 Eden Space",
			MemoryType:     JVMMemoryTypeHeap,
			GCPhase:        JVMGCPhaseBefore,
			ValueBytes:     8192,
		},
	}, events)
}

func TestParseJVMMemoryPoolEventAddsUsedAfterLastGCForEndEvents(t *testing.T) {
	eventTime := setJVMTestClocks(t)

	events, err := ParseJVMMemoryPoolEvent(
		500,
		2,
		43,
		RawJVMGCWhenAfter,
		300,
		400,
		math.MaxUint64,
		rawJVMString("Metaspace"),
	)
	require.NoError(t, err)
	require.Equal(t, []JVMRuntimeEvent{
		{
			PID:            app.PID(2),
			PIDNamespaceID: 43,
			Time:           eventTime(500),
			Kind:           JVMMetricMemoryUsed,
			PoolName:       "Metaspace",
			MemoryType:     JVMMemoryTypeNonHeap,
			GCPhase:        JVMGCPhaseAfter,
			ValueBytes:     300,
		},
		{
			PID:            app.PID(2),
			PIDNamespaceID: 43,
			Time:           eventTime(500),
			Kind:           JVMMetricMemoryCommitted,
			PoolName:       "Metaspace",
			MemoryType:     JVMMemoryTypeNonHeap,
			GCPhase:        JVMGCPhaseAfter,
			ValueBytes:     400,
		},
		{
			PID:            app.PID(2),
			PIDNamespaceID: 43,
			Time:           eventTime(500),
			Kind:           JVMMetricMemoryUsedAfterLastGC,
			PoolName:       "Metaspace",
			MemoryType:     JVMMemoryTypeNonHeap,
			GCPhase:        JVMGCPhaseAfter,
			ValueBytes:     300,
		},
	}, events)
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

func setJVMTestClocks(t *testing.T) func(uint64) time.Time {
	t.Helper()

	wallNow := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	monoNow := 10 * time.Second
	oldClocks := jvmClocks
	jvmClocks = jvmRuntimeClocks{
		clock:     func() time.Time { return wallNow },
		monoClock: func() time.Duration { return monoNow },
	}
	t.Cleanup(func() { jvmClocks = oldClocks })

	return func(timestamp uint64) time.Time {
		return wallNow.Add(-(monoNow - time.Duration(timestamp)))
	}
}
