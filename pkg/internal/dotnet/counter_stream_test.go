// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/require"
)

func runtimeCounterStream(t *testing.T, counters []runtimeCounter) []byte {
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
	write(&stream, netTraceInfo{ProcessID: 15, PointerSize: 8, QPCFrequency: 1_000_000_000})
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
	writeBlock("MetadataBlock", events.Bytes())
	events.Reset()
	for _, counter := range counters {
		var payload bytes.Buffer
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
	stream.WriteByte(fastSerializationNullReference)
	return stream.Bytes()
}
