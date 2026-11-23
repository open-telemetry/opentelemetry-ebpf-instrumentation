// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package dotnet

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/require"
)

func runtimeCounterStream(t *testing.T, pid int32, counters []runtimeCounter) []byte {
	t.Helper()
	events := make([]netTraceRuntimeEvent, len(counters))
	for i, counter := range counters {
		events[i].counter = counter
	}
	return runtimeEventStream(t, pid, events, false)
}

func runtimeEventStream(t *testing.T, pid int32, records []netTraceRuntimeEvent, reportLoss bool) []byte {
	t.Helper()
	return runtimeEventStreamWithMeter(t, pid, records, reportLoss, "")
}

func runtimeEventStreamWithMeter(t *testing.T, pid int32, records []netTraceRuntimeEvent, reportLoss bool, metricsSessionID string) []byte {
	t.Helper()
	write := func(buffer *bytes.Buffer, value any) {
		t.Helper()
		require.NoError(t, binary.Write(buffer, binary.LittleEndian, value))
	}
	writeString := func(buffer *bytes.Buffer, value string) {
		write(buffer, append(utf16.Encode([]rune(value)), 0))
	}
	writeHeader := func(buffer *bytes.Buffer, name string, version uint32) {
		buffer.Write([]byte{5, 5, 1})
		write(buffer, version)
		write(buffer, version)
		write(buffer, uint32(len(name)))
		buffer.WriteString(name)
		buffer.WriteByte(fastSerializationEndObject)
	}
	writeEvent := func(buffer *bytes.Buffer, metadataID uint64, payload []byte) {
		buffer.WriteByte(netTraceMetadataIDFlag | netTracePayloadSizeFlag)
		buffer.Write(binary.AppendUvarint(nil, metadataID))
		buffer.WriteByte(0) // Timestamp delta.
		buffer.Write(binary.AppendUvarint(nil, uint64(len(payload))))
		buffer.Write(payload)
	}
	var stream bytes.Buffer
	stream.WriteString("Nettrace\x14\x00\x00\x00!FastSerialization.1")
	writeHeader(&stream, "Trace", 4)
	write(&stream, netTraceInfo{ProcessID: pid, PointerSize: 8, QPCFrequency: 1_000_000_000})
	stream.WriteByte(fastSerializationEndObject)
	writeBlock := func(name string, events []byte) {
		var block bytes.Buffer
		write(&block, uint16(20))
		write(&block, uint16(1)) // Compressed headers.
		write(&block, [2]uint64{})
		block.Write(events)
		writeHeader(&stream, name, 2)
		write(&stream, uint32(block.Len()))
		for stream.Len()%4 != 0 {
			stream.WriteByte(0)
		}
		stream.Write(block.Bytes())
		stream.WriteByte(fastSerializationEndObject)
	}
	var metadata bytes.Buffer
	write(&metadata, uint32(1))
	writeString(&metadata, "System.Runtime")
	write(&metadata, uint32(1))
	writeString(&metadata, "EventCounters")
	write(&metadata, uint64(2))
	write(&metadata, uint32(0))
	write(&metadata, uint32(4))
	for range 2 { // Unnamed outer object containing Payload.
		write(&metadata, uint32(1))
		write(&metadata, netTraceTypeObject)
	}
	fields := []netTraceField{
		{Name: "Name", Type: netTraceTypeString},
		{Name: "CounterType", Type: netTraceTypeString},
		{Name: "IntervalSec", Type: netTraceTypeSingle},
		{Name: "Mean", Type: netTraceTypeDouble},
		{Name: "Increment", Type: netTraceTypeDouble},
	}
	write(&metadata, uint32(len(fields)))
	for _, field := range fields {
		write(&metadata, field.Type)
		writeString(&metadata, field.Name)
	}
	writeString(&metadata, "Payload")
	writeString(&metadata, "")
	var events bytes.Buffer
	writeEvent(&events, 0, metadata.Bytes())
	metadata.Reset()
	write(&metadata, uint32(2))
	writeString(&metadata, "System.Runtime")
	write(&metadata, uint32(2))
	writeString(&metadata, "ProcessorCount")
	write(&metadata, uint64(2))
	write(&metadata, uint32(0))
	write(&metadata, uint32(4))
	write(&metadata, uint32(1))
	write(&metadata, netTraceTypeInt32)
	writeString(&metadata, "processorCount")
	writeEvent(&events, 0, metadata.Bytes())
	metadata.Reset()
	write(&metadata, uint32(3))
	writeString(&metadata, "Microsoft-Windows-DotNETRuntime")
	write(&metadata, uint32(80))
	writeString(&metadata, "ExceptionThrown")
	write(&metadata, uint64(0x8000))
	write(&metadata, uint32(1))
	write(&metadata, uint32(2))
	write(&metadata, uint32(0))
	writeEvent(&events, 0, metadata.Bytes())
	if metricsSessionID != "" {
		metadata.Reset()
		write(&metadata, uint32(4))
		writeString(&metadata, "System.Diagnostics.Metrics")
		write(&metadata, uint32(4))
		writeString(&metadata, "CounterRateValuePublished")
		write(&metadata, uint64(2))
		write(&metadata, uint32(0))
		write(&metadata, uint32(4))
		names := []string{"sessionId", "meterName", "meterVersion", "instrumentName", "unit", "tags", "rate", "value"}
		write(&metadata, uint32(len(names)+1))
		for _, name := range names {
			write(&metadata, netTraceTypeString)
			writeString(&metadata, name)
		}
		write(&metadata, netTraceTypeInt32)
		writeString(&metadata, "instrumentId")
		writeEvent(&events, 0, metadata.Bytes())
	}
	metadata.Reset()
	write(&metadata, uint32(5))
	writeString(&metadata, "Microsoft-Windows-DotNETRuntime")
	write(&metadata, clrGCStartEventID)
	writeString(&metadata, "GCStart")
	write(&metadata, uint64(1))
	write(&metadata, uint32(2))
	write(&metadata, uint32(4))
	write(&metadata, uint32(0))
	writeEvent(&events, 0, metadata.Bytes())
	writeBlock("MetadataBlock", events.Bytes())
	events.Reset()
	for _, record := range records {
		var payload bytes.Buffer
		if record.gc != nil {
			require.Equal(t, clrGCStartEventID, record.gc.eventID)
			write(&payload, record.gc.collection.count)
			write(&payload, record.gc.collection.depth)
			write(&payload, uint32(0)) // Reason.
			write(&payload, uint32(0)) // Type.
			write(&payload, record.gc.collection.clrInstanceID)
			write(&payload, uint64(0)) // Client sequence number.
			writeEvent(&events, 5, payload.Bytes())
			continue
		}
		if record.exceptionType != "" {
			if metricsSessionID != "" {
				count := strconv.FormatUint(record.exceptionCount, 10)
				for _, value := range []string{metricsSessionID, "System.Runtime", "", "dotnet.exceptions", "{exception}", "error.type=" + record.exceptionType, count, count} {
					writeString(&payload, value)
				}
				write(&payload, int32(1))
				writeEvent(&events, 4, payload.Bytes())
				continue
			}
			payload.Write(clrExceptionPayload(record.exceptionType, 8))
			writeEvent(&events, 3, payload.Bytes())
			continue
		}
		counter := record.counter
		if counter.Name == "processor-count" {
			write(&payload, int32(counter.Value))
			writeEvent(&events, 2, payload.Bytes())
			continue
		}
		writeString(&payload, counter.Name)
		counterType := "Mean"
		if counter.Increment {
			counterType = "Sum"
		}
		writeString(&payload, counterType)
		write(&payload, float32(1))
		write(&payload, counter.Value)
		write(&payload, counter.Value)
		writeEvent(&events, 1, payload.Bytes())
	}
	writeBlock("EventBlock", events.Bytes())
	if reportLoss {
		var checkpoint bytes.Buffer
		write(&checkpoint, uint64(0))              // Timestamp.
		write(&checkpoint, uint32(1))              // One capture thread.
		write(&checkpoint, uint64(0))              // Default capture thread used by the events.
		write(&checkpoint, uint32(len(records)+1)) // One event was not delivered.
		writeHeader(&stream, "SPBlock", 2)
		write(&stream, uint32(checkpoint.Len()))
		for stream.Len()%4 != 0 {
			stream.WriteByte(0)
		}
		stream.Write(checkpoint.Bytes())
		stream.WriteByte(fastSerializationEndObject)
	}
	stream.WriteByte(fastSerializationNullReference)
	return stream.Bytes()
}
