// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGCEventWatermarkFromIgnoredEvent(t *testing.T) {
	decoder := netTraceDecoder{pointerSize: 8, metadata: map[uint32]netTraceMetadata{
		1: {Header: netTraceMetadataHeader{ProviderName: "Microsoft-Windows-DotNETRuntime", EventID: clrGCStartEventID, Version: 2}},
		2: {Header: netTraceMetadataHeader{ProviderName: "Ignored.Provider", EventID: 1}},
	}}
	block := gcOrderingTestBlock(
		netTraceEventHeader{MetadataID: 1, Timestamp: 30, ThreadID: 1, SequenceNumber: 1},
		netTraceEventHeader{MetadataID: 1, Timestamp: 10, ThreadID: 2, SequenceNumber: 1},
		netTraceEventHeader{MetadataID: 2, Timestamp: 30, ThreadID: 1, SequenceNumber: 2, Sorted: true},
	)
	events, err := decoder.decodeEventBlock("EventBlock", block)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, int64(10), events[0].gc.timestamp)
	require.Equal(t, uint64(2), events[0].gc.threadID)
	require.Len(t, decoder.gcOrder.pending, 1, "boundary timestamp stays pending")
	block = gcOrderingTestBlock(netTraceEventHeader{
		MetadataID: 2, Timestamp: 31, ThreadID: 1, SequenceNumber: 3, Sorted: true,
	})
	events, err = decoder.decodeEventBlock("EventBlock", block)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, int64(30), events[0].gc.timestamp)
	require.Empty(t, decoder.gcOrder.pending)
}

func TestGCEventWatermarkChecksLossFirst(t *testing.T) {
	decoder := netTraceDecoder{
		metadata:  map[uint32]netTraceMetadata{2: {Header: netTraceMetadataHeader{ProviderName: "Ignored.Provider"}}},
		sequences: map[uint64]uint32{1: 1},
	}
	require.NoError(t, decoder.gcOrder.add(gcRuntimeEvent{timestamp: 10, threadID: 1}))
	block := gcOrderingTestBlock(netTraceEventHeader{
		MetadataID: 2, Timestamp: 20, ThreadID: 1, SequenceNumber: 3, Sorted: true,
	})
	events, err := decoder.decodeEventBlock("EventBlock", block)
	require.ErrorContains(t, err, "event loss")
	require.Empty(t, events)
}

func TestGCEventStreamBoundaries(t *testing.T) {
	event := gcRuntimeEvent{eventID: clrGCStartEventID, collection: gcCollectionEvent{count: 42, depth: 2, clrInstanceID: 3}}
	records := []netTraceRuntimeEvent{{gc: &event}}
	wire := runtimeEventStream(t, 15, records, false)
	for _, test := range []struct {
		name string
		wire []byte
		want int
		err  string
	}{
		{name: "clean end", wire: wire, want: 1},
		{name: "truncated", wire: wire[:len(wire)-1], err: "EOF"},
		{name: "sequence loss", wire: runtimeEventStream(t, 15, records, true), err: "event loss"},
		{name: "sequence point before truncation", wire: gcOrderingTestSequencePoint(wire[:len(wire)-1], 1), want: 1, err: "EOF"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var received []gcRuntimeEvent
			err := readRuntimeEvents(bytes.NewReader(test.wire), 15, "", func(record netTraceRuntimeEvent) error {
				require.NotNil(t, record.gc)
				received = append(received, *record.gc)
				return nil
			})
			if test.err == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.err)
			}
			require.Len(t, received, test.want)
			if test.want > 0 {
				require.Equal(t, event, received[0])
			}
		})
	}
	wantErr := errors.New("consumer stopped")
	for _, input := range [][]byte{wire, gcOrderingTestSequencePoint(wire[:len(wire)-1], 1)} {
		err := readRuntimeEvents(bytes.NewReader(input), 15, "", func(netTraceRuntimeEvent) error { return wantErr })
		require.ErrorIs(t, err, wantErr)
		require.NotErrorIs(t, err, io.EOF)
	}
}

func gcOrderingTestBlock(events ...netTraceEventHeader) []byte {
	wire := append([]byte{20, 0, 1, 0}, make([]byte, 16)...)
	var previous netTraceEventHeader
	for _, event := range events {
		flags := netTraceMetadataIDFlag | netTraceCaptureSequenceFlag | netTraceThreadIDFlag | netTracePayloadSizeFlag
		if event.Sorted {
			flags |= netTraceSortedFlag
		}
		wire = append(wire, flags)
		wire = binary.AppendUvarint(wire, uint64(event.MetadataID))
		wire = binary.AppendUvarint(wire, uint64(event.SequenceNumber-previous.SequenceNumber-1))
		wire = binary.AppendUvarint(wire, event.ThreadID) // Capture thread.
		wire = binary.AppendUvarint(wire, 0)              // Processor.
		wire = binary.AppendUvarint(wire, event.ThreadID)
		wire = binary.AppendUvarint(wire, uint64(event.Timestamp-previous.Timestamp))
		var payload []byte
		if event.MetadataID == 1 {
			payload = binary.LittleEndian.AppendUint32(nil, 42)
			payload = binary.LittleEndian.AppendUint32(payload, 2)
			payload = append(payload, make([]byte, 18)...)
		}
		wire = binary.AppendUvarint(wire, uint64(len(payload)))
		wire = append(wire, payload...)
		previous = event
	}
	return wire
}

func gcOrderingTestSequencePoint(stream []byte, sequence uint32) []byte {
	payload := binary.LittleEndian.AppendUint64(nil, 1) // Timestamp closes queued timestamp zero.
	payload = binary.LittleEndian.AppendUint32(payload, 1)
	payload = binary.LittleEndian.AppendUint64(payload, 0)
	payload = binary.LittleEndian.AppendUint32(payload, sequence)
	wire := append(bytes.Clone(stream), 5, 5, 1)
	wire = binary.LittleEndian.AppendUint32(wire, 2)
	wire = binary.LittleEndian.AppendUint32(wire, 2)
	wire = binary.LittleEndian.AppendUint32(wire, uint32(len("SPBlock")))
	wire = append(wire, "SPBlock"...)
	wire = append(wire, fastSerializationEndObject)
	wire = binary.LittleEndian.AppendUint32(wire, uint32(len(payload)))
	for len(wire)%4 != 0 {
		wire = append(wire, 0)
	}
	wire = append(wire, payload...)
	return append(wire, fastSerializationEndObject)
}
