// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func TestParseJVMMemoryPoolEventMapsPoolCounters(t *testing.T) {
	eventTime := setJVMTestClocks(t)
	raw := RawJVMMemoryPoolEvent{
		Timestamp:      123456789,
		GlobalPID:      1234,
		GlobalTID:      1235,
		NsPID:          4321,
		NsTID:          4322,
		PIDNamespaceID: 9001,
		GCWhenType:     RawJVMGCWhenBefore,
		InitSize:       1024,
		Used:           2048,
		Committed:      4096,
		MaxSize:        8192,
		Pool:           rawJVMString("G1 Eden Space"),
	}

	events, err := ParseJVMMemoryPoolEvent(raw)
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
	raw := RawJVMMemoryPoolEvent{
		Timestamp:      500,
		GlobalPID:      222,
		NsPID:          2,
		PIDNamespaceID: 43,
		GCWhenType:     RawJVMGCWhenAfter,
		Used:           300,
		Committed:      400,
		MaxSize:        math.MaxUint64,
		Pool:           rawJVMString("Metaspace"),
	}

	events, err := ParseJVMMemoryPoolEvent(raw)
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

func TestParseJVMGCHeapSummaryEventMapsAggregateHeapUsed(t *testing.T) {
	eventTime := setJVMTestClocks(t)
	raw := RawJVMGCHeapSummaryEvent{
		Timestamp:      900,
		GlobalPID:      333,
		NsPID:          1,
		PIDNamespaceID: 42,
		GCWhenType:     RawJVMGCWhenAfter,
		Used:           700,
	}

	event, err := ParseJVMGCHeapSummaryEvent(raw)
	require.NoError(t, err)
	require.Equal(t, JVMRuntimeEvent{
		PID:            app.PID(1),
		PIDNamespaceID: 42,
		Time:           eventTime(900),
		Kind:           JVMMetricBeylaHeapUsed,
		GCPhase:        JVMGCPhaseAfter,
		ValueBytes:     700,
	}, event)
}

func TestParseJVMGCHeapSummaryEventConvertsMonotonicTimestamp(t *testing.T) {
	eventTime := setJVMTestClocks(t)
	raw := RawJVMGCHeapSummaryEvent{
		Timestamp:  uint64(8 * time.Second),
		GlobalPID:  333,
		NsPID:      1,
		GCWhenType: RawJVMGCWhenAfter,
		Used:       700,
	}

	event, err := ParseJVMGCHeapSummaryEvent(raw)
	require.NoError(t, err)

	require.Equal(t, eventTime(raw.Timestamp), event.Time)
	require.NotEqual(t, time.Unix(0, int64(raw.Timestamp)), event.Time)
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

func TestDecodeRawJVMEventsFromBinaryPayloads(t *testing.T) {
	poolPayload := binaryPayload(t, RawJVMMemoryPoolEvent{
		Timestamp:  42,
		GlobalPID:  44,
		NsPID:      4,
		GCWhenType: RawJVMGCWhenBefore,
		Used:       50,
		Committed:  60,
		MaxSize:    70,
		Pool:       rawJVMString("Tenured Gen"),
	})
	poolEvents, err := DecodeJVMMemoryPoolEvent(poolPayload)
	require.NoError(t, err)
	require.Equal(t, JVMMetricMemoryUsed, poolEvents[0].Kind)
	require.Equal(t, "Tenured Gen", poolEvents[0].PoolName)
	require.Equal(t, JVMMemoryTypeHeap, poolEvents[0].MemoryType)

	heapPayload := binaryPayload(t, RawJVMGCHeapSummaryEvent{
		Timestamp:  52,
		GlobalPID:  54,
		NsPID:      1,
		GCWhenType: RawJVMGCWhenBefore,
		Used:       80,
	})
	heapEvent, err := DecodeJVMGCHeapSummaryEvent(heapPayload)
	require.NoError(t, err)
	require.Equal(t, JVMMetricBeylaHeapUsed, heapEvent.Kind)
	require.Equal(t, JVMGCPhaseBefore, heapEvent.GCPhase)
}

func TestRawJVMPayloadSizesMatchPoCShapes(t *testing.T) {
	require.Equal(t, 192, binary.Size(RawJVMMemoryPoolEvent{}))
	require.Equal(t, 40, binary.Size(RawJVMGCHeapSummaryEvent{}))
}

func TestDecodeRawJVMPayloadRejectsShortPayload(t *testing.T) {
	_, err := DecodeJVMMemoryPoolEvent(make([]byte, binary.Size(RawJVMMemoryPoolEvent{})-1))
	require.ErrorContains(t, err, "raw JVM payload too short")

	_, err = DecodeJVMGCHeapSummaryEvent(make([]byte, binary.Size(RawJVMGCHeapSummaryEvent{})-1))
	require.ErrorContains(t, err, "raw JVM payload too short")
}

func TestParseJVMGCHeapSummaryEventRejectsUnsupportedPhase(t *testing.T) {
	_, err := ParseJVMGCHeapSummaryEvent(RawJVMGCHeapSummaryEvent{
		GCWhenType: RawJVMGCWhenEndSentinel,
	})
	require.ErrorContains(t, err, "unsupported JVM GC phase")
}

func rawJVMString(value string) [JVMRawStringLen]byte {
	var raw [JVMRawStringLen]byte
	copy(raw[:], []byte(value))
	return raw
}

func binaryPayload(t *testing.T, value any) []byte {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, value))
	return buf.Bytes()
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
