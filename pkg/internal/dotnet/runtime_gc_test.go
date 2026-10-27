// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeCLRGCCollectionEvents(t *testing.T) {
	for _, test := range []struct {
		name   string
		decode func(*bytes.Reader) (gcCollectionEvent, error)
		start  bool
	}{
		{name: "start", decode: decodeCLRGCStart, start: true},
		{name: "end", decode: decodeCLRGCEnd},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := func(depth uint32) []byte {
				data := binary.LittleEndian.AppendUint32(nil, 42)
				data = binary.LittleEndian.AppendUint32(data, depth)
				if test.start {
					data = binary.LittleEndian.AppendUint32(data, 7) // Reason.
					data = binary.LittleEndian.AppendUint32(data, 1) // Advertised background type.
				}
				data = binary.LittleEndian.AppendUint16(data, 3)
				if test.start {
					data = binary.LittleEndian.AppendUint64(data, 99) // Client sequence number.
				}
				return data
			}
			for depth := range uint32(3) {
				got, err := test.decode(bytes.NewReader(payload(depth)))
				require.NoError(t, err)
				require.Equal(t, gcCollectionEvent{count: 42, depth: depth, clrInstanceID: 3}, got)
			}
			valid := payload(2)
			for size := range len(valid) {
				_, err := test.decode(bytes.NewReader(valid[:size]))
				require.Error(t, err, "truncated payload size %d", size)
			}
			_, err := test.decode(bytes.NewReader(append(valid, 0)))
			require.Error(t, err, "trailing payload byte")
			_, err = test.decode(bytes.NewReader(payload(3)))
			require.Error(t, err, "unsupported generation depth")
		})
	}
}

func TestDecodeCLRGCGlobalHeapHistory(t *testing.T) {
	// Captured GCGlobalHeapHistory_V4 from .NET 8 server GC with two heaps.
	payload, err := hex.DecodeString("0000000000000000020000000200000000000000040000001500000000000100000026000000000000000000000005000000000000003E000000020000000E00000003000000")
	require.NoError(t, err)
	reader := bytes.NewReader(payload)
	got, err := decodeCLRGCGlobalHeapHistory(reader)
	require.NoError(t, err)
	require.Equal(t, gcGlobalHeapHistory{depth: 2, heapCount: 2, clrInstanceID: 0}, got)
	require.Zero(t, reader.Len())
	for size := range len(payload) {
		_, err := decodeCLRGCGlobalHeapHistory(bytes.NewReader(payload[:size]))
		require.Error(t, err, "truncated payload size %d", size)
	}
	_, err = decodeCLRGCGlobalHeapHistory(bytes.NewReader(append(bytes.Clone(payload), 0)))
	require.Error(t, err, "trailing payload byte")
	const (
		heapCountOffset   = 8
		depthOffset       = 12
		timingCountOffset = 46
	)
	for _, test := range []struct {
		name   string
		offset int
		value  uint32
	}{
		{name: "zero heaps", offset: heapCountOffset, value: 0},
		{name: "negative heaps", offset: heapCountOffset, value: ^uint32(0)},
		{name: "invalid depth", offset: depthOffset, value: 3},
		{name: "missing timings", offset: timingCountOffset, value: 6},
		{name: "extra timings", offset: timingCountOffset, value: 4},
		{name: "oversized timing count", offset: timingCountOffset, value: ^uint32(0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := bytes.Clone(payload)
			binary.LittleEndian.PutUint32(invalid[test.offset:], test.value)
			_, err := decodeCLRGCGlobalHeapHistory(bytes.NewReader(invalid))
			require.Error(t, err)
		})
	}
}

func TestDecodeCLRGCPerHeapHistory(t *testing.T) {
	for _, width := range []int32{4, 8} {
		payload := gcPerHeapTestPayload(width, 100, 200)
		reader := bytes.NewReader(payload)
		got, err := decodeCLRGCPerHeapHistory(reader, width)
		require.NoError(t, err)
		require.Equal(t, gcPerHeapHistory{
			heapIndex: 7, clrInstanceID: 3,
			fragmentation: [5]uint64{300, 302, 304, 306, 308},
		}, got)
		require.Zero(t, reader.Len())
		for size := range len(payload) {
			_, err := decodeCLRGCPerHeapHistory(bytes.NewReader(payload[:size]), width)
			require.Error(t, err, "pointer width %d, truncated payload size %d", width, size)
		}
		_, err = decodeCLRGCPerHeapHistory(bytes.NewReader(append(bytes.Clone(payload), 0)), width)
		require.Error(t, err, "trailing byte, pointer width %d", width)
		// Count follows the instance ID, seven pointers, and six uint32 fields.
		countOffset := 2 + 7*int(width) + 6*4
		for _, count := range []uint32{0, 4, 6, math.MaxUint32} {
			invalid := bytes.Clone(payload)
			binary.LittleEndian.PutUint32(invalid[countOffset:], count)
			_, err := decodeCLRGCPerHeapHistory(bytes.NewReader(invalid), width)
			require.Error(t, err, "generation count %d, pointer width %d", count, width)
		}
	}
	for _, width := range []int32{-1, 0, 2, 16} {
		_, err := decodeCLRGCPerHeapHistory(bytes.NewReader(nil), width)
		require.Error(t, err, "invalid pointer width %d", width)
	}
}

func TestCLRGCGenerationFragmentationRange(t *testing.T) {
	for _, test := range []struct {
		name                  string
		width                 int32
		freeList, freeObjects uint64
		want                  uint64
		invalid               bool
	}{
		{name: "zero", width: 8},
		{name: "wide sum of narrow fields", width: 4, freeList: math.MaxUint32, freeObjects: math.MaxUint32, want: 2 * uint64(math.MaxUint32)},
		{name: "exporter limit", width: 8, freeList: math.MaxInt64 - 1, freeObjects: 1, want: math.MaxInt64},
		{name: "sum exceeds limit", width: 8, freeList: math.MaxInt64, freeObjects: 1, invalid: true},
		{name: "field exceeds limit", width: 8, freeList: math.MaxUint64, invalid: true},
		{name: "unsigned sum overflow", width: 8, freeList: math.MaxUint64, freeObjects: 1, invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := gcPerHeapTestPayload(test.width, test.freeList, test.freeObjects)
			reader := bytes.NewReader(payload)
			_, err := readCLRGCPerHeapHeader(reader, test.width)
			require.NoError(t, err)
			got, err := readCLRGCGenerationFragmentation(reader, test.width)
			if test.invalid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, got)
		})
	}
}

func TestDecodeCLRGCPerHeapCapturedPayload(t *testing.T) {
	payload, err := os.ReadFile("testdata/gc-per-heap-net8.bin")
	require.NoError(t, err)
	got, err := decodeCLRGCPerHeapHistory(bytes.NewReader(payload), 8)
	require.NoError(t, err)
	require.Equal(t, gcPerHeapHistory{fragmentation: [5]uint64{48032, 0, 0, 1152, 0}}, got)
}

func TestDecodeCLRGCEvent(t *testing.T) {
	start, err := hex.DecodeString("2a00000002000000070000000100000003006300000000000000")
	require.NoError(t, err)
	end, err := hex.DecodeString("2a000000020000000300")
	require.NoError(t, err)
	var global bytes.Buffer
	require.NoError(t, binary.Write(&global, binary.LittleEndian, gcGlobalHeapHistoryHeader{
		NumHeaps: 2, CondemnedGeneration: 2, CLRInstanceID: 3,
	}))
	for _, test := range []struct {
		name    string
		id      uint32
		version uint32
		payload []byte
		want    gcRuntimeEvent
	}{
		{
			name: "start", id: clrGCStartEventID, version: 2, payload: start,
			want: gcRuntimeEvent{collection: gcCollectionEvent{count: 42, depth: 2, clrInstanceID: 3}},
		},
		{
			name: "end", id: clrGCEndEventID, version: 1, payload: end,
			want: gcRuntimeEvent{collection: gcCollectionEvent{count: 42, depth: 2, clrInstanceID: 3}},
		},
		{
			name: "global history", id: clrGCGlobalHeapHistoryEventID, version: 4, payload: global.Bytes(),
			want: gcRuntimeEvent{globalHistory: gcGlobalHeapHistory{depth: 2, heapCount: 2, clrInstanceID: 3}},
		},
		{
			name: "per-heap history", id: clrGCPerHeapHistoryEventID, version: 3, payload: gcPerHeapTestPayload(8, 100, 200),
			want: gcRuntimeEvent{perHeapHistory: gcPerHeapHistory{heapIndex: 7, clrInstanceID: 3, fragmentation: [5]uint64{300, 302, 304, 306, 308}}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			definition := netTraceMetadataHeader{ProviderName: "Microsoft-Windows-DotNETRuntime", EventID: test.id, Version: test.version}
			event := netTraceEventHeader{Timestamp: 55, ThreadID: 66}
			got, err := decodeCLRGCEvent(definition, event, bytes.NewReader(test.payload), 8)
			require.NoError(t, err)
			want := test.want
			want.eventID, want.timestamp, want.threadID = test.id, 55, 66
			require.Equal(t, &want, got)
			_, err = decodeCLRGCEvent(definition, event, bytes.NewReader(test.payload[:len(test.payload)-1]), 8)
			require.Error(t, err, "malformed payload")
			definition.Version++
			_, err = decodeCLRGCEvent(definition, event, bytes.NewReader(test.payload), 8)
			require.Error(t, err, "unsupported version")
			definition.ProviderName = "Other.Provider"
			got, err = decodeCLRGCEvent(definition, event, bytes.NewReader(test.payload), 8)
			require.NoError(t, err)
			require.Nil(t, got, "event IDs belong to their provider")
		})
	}
	got, err := decodeCLRGCEvent(netTraceMetadataHeader{
		ProviderName: "Microsoft-Windows-DotNETRuntime", EventID: 999,
	}, netTraceEventHeader{}, bytes.NewReader(nil), 8)
	require.NoError(t, err)
	require.Nil(t, got, "unrelated CLR events are ignored")
}

func gcPerHeapTestPayload(width int32, freeList, freeObjects uint64) []byte {
	appendPointer := func(data []byte, value uint64) []byte {
		if width == 4 {
			return binary.LittleEndian.AppendUint32(data, uint32(value))
		}
		return binary.LittleEndian.AppendUint64(data, value)
	}
	data := binary.LittleEndian.AppendUint16(nil, 3)
	for value := uint64(1); value <= 6; value++ {
		data = appendPointer(data, value)
	}
	for _, value := range []uint32{11, 12, 13, 14, 15, 7} {
		data = binary.LittleEndian.AppendUint32(data, value)
	}
	data = appendPointer(data, 16)
	data = binary.LittleEndian.AppendUint32(data, 5)
	for generation := range uint64(5) {
		for _, value := range []uint64{21, 22, 23, 24, freeList + generation, freeObjects + generation, 27, 28, 29, 30} {
			data = appendPointer(data, value)
		}
	}
	return data
}
