// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

func TestProtocolToLargeBufferKind(t *testing.T) {
	tests := []struct {
		protocolType BpfProtocolType
		expected     largeBufferKind
	}{
		{ProtocolTypeKafka, KindLayerApp},
		{ProtocolTypeMySQL, KindLayerApp},
		{ProtocolTypePostgres, KindLayerApp},
		{ProtocolTypeMSSQL, KindLayerApp},
		{ProtocolTypeHTTP, KindLayerApp},
		{ProtocolTypeMQTT, KindLayerWire},
		{ProtocolTypeUnknown, KindLayerWire},
		{ProtocolTypeSunRPC, KindLayerWire},
		{ProtocolTypeAerospike, KindLayerApp},
	}
	for _, tt := range tests {
		require.Equal(t, tt.expected, protocolToLargeBufferKind(tt.protocolType))
	}
}

func TestTCPLargeBuffers(t *testing.T) {
	pctx := NewEBPFParseContext(nil, nil, nil)
	verifyLargeBuffer := func(traceID [16]uint8, spanID [8]uint8, packetType, direction uint8, connInfo BpfConnectionInfoT, expectedBuf string) {
		buf, ok := extractTCPLargeBuffer(pctx, traceID, spanID, packetType, direction, connInfo, ProtocolTypeMySQL)
		require.True(t, ok, "Expected to find large buffer")
		require.Equal(t, expectedBuf, unix.ByteSliceToString(buf.UnsafeView()), "Buffer content mismatch")
	}

	firstEvent := TCPLargeBufferHeader{
		Type:       12,
		PacketType: 1,
		Direction:  0,
		Len:        10,
		Kind:       uint8(KindLayerApp),
	}
	firstEvent.Tp.TraceId = [16]uint8{'1'}
	firstEvent.Tp.SpanId = [8]uint8{'2'}
	firstEvent.ConnInfo = BpfConnectionInfoT{
		D_port: 2000,
	}
	firstBuf := "obi rocks!"

	span, drop, err := appendTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, firstBuf))
	require.NoError(t, err)
	require.True(t, drop)
	require.Equal(t, request.Span{}, span)

	// Verify normal write
	verifyLargeBuffer(firstEvent.Tp.TraceId, firstEvent.Tp.SpanId, firstEvent.PacketType, firstEvent.Direction, firstEvent.ConnInfo, firstBuf)

	secondBuf := "obi rocks twice!"
	firstEvent.Len = uint32(len(secondBuf))
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, firstBuf))
	require.NoError(t, err)
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, secondBuf))
	require.NoError(t, err)
	// Verify buffer overwrite
	verifyLargeBuffer(firstEvent.Tp.TraceId, firstEvent.Tp.SpanId, firstEvent.PacketType, firstEvent.Direction, firstEvent.ConnInfo, secondBuf)

	// Verify second read error
	_, ok := extractTCPLargeBuffer(pctx, firstEvent.Tp.TraceId, firstEvent.Tp.SpanId, firstEvent.PacketType, firstEvent.Direction, firstEvent.ConnInfo, ProtocolTypeMySQL)
	require.False(t, ok, "Expected to not find large buffer after first read")

	firstEvent.Len = uint32(len(firstBuf))
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, firstBuf))
	require.NoError(t, err)

	// Verify no buffer read happens for different traceID/packet_type
	_, ok = extractTCPLargeBuffer(pctx, [16]uint8{99}, firstEvent.Tp.SpanId, firstEvent.PacketType, firstEvent.Direction, firstEvent.ConnInfo, ProtocolTypeMySQL)
	require.False(t, ok, "Expected to not find large buffer for this traceID")
	_, ok = extractTCPLargeBuffer(pctx, firstEvent.Tp.TraceId, [8]uint8{99}, firstEvent.PacketType, firstEvent.Direction, firstEvent.ConnInfo, ProtocolTypeMySQL)
	require.False(t, ok, "Expected to not find large buffer for this spanID")
	_, ok = extractTCPLargeBuffer(pctx, firstEvent.Tp.TraceId, firstEvent.Tp.SpanId, 3, firstEvent.Direction, firstEvent.ConnInfo, ProtocolTypeMySQL)
	require.False(t, ok, "Expected to not find large buffer for this packet_type")
	verifyLargeBuffer(firstEvent.Tp.TraceId, firstEvent.Tp.SpanId, firstEvent.PacketType, firstEvent.Direction, firstEvent.ConnInfo, firstBuf)

	// Test append to existing buffer
	firstEvent.Len = 10
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, firstBuf))
	require.NoError(t, err)

	appendEvent := TCPLargeBufferHeader{
		Type:       firstEvent.Type,
		PacketType: firstEvent.PacketType,
		Len:        6,
		Action:     largeBufferActionAppend,
		Kind:       uint8(KindLayerApp),
	}
	appendEvent.Tp.TraceId = firstEvent.Tp.TraceId
	appendEvent.Tp.SpanId = firstEvent.Tp.SpanId
	appendEvent.ConnInfo = BpfConnectionInfoT{
		D_port: 2000,
	}
	appendBuf := "append"

	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, appendEvent, appendBuf))
	require.NoError(t, err)
	// The buffer should now be firstBuf + appendBuf
	verifyLargeBuffer(firstEvent.Tp.TraceId, firstEvent.Tp.SpanId, firstEvent.PacketType, firstEvent.Direction, firstEvent.ConnInfo, firstBuf+appendBuf)

	// Test multiple appends
	// Re-init buffer
	firstEvent.Len = uint32(len(firstBuf))
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, firstBuf))
	require.NoError(t, err)
	// Append twice
	appendEvent.Len = 3
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, appendEvent, "foo"))
	require.NoError(t, err)
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, appendEvent, "bar"))
	require.NoError(t, err)
	verifyLargeBuffer(firstEvent.Tp.TraceId, firstEvent.Tp.SpanId, firstEvent.PacketType, firstEvent.Direction, firstEvent.ConnInfo, firstBuf+"foobar")
}

func TestTCPLargeBufferRekey(t *testing.T) {
	pctx := NewEBPFParseContext(nil, nil, nil)
	previousTraceID := [16]uint8{'o', 'l', 'd'}
	previousSpanID := [8]uint8{'s'}
	adoptedTraceID := [16]uint8{'n', 'e', 'w'}
	// a client adopts its own traceparent's span as well
	adoptedSpanID := [8]uint8{'c'}
	previousIDs := string(previousTraceID[:]) + string(previousSpanID[:])

	event := TCPLargeBufferHeader{
		Type:       12,
		PacketType: packetTypeRequest,
		Action:     largeBufferActionInit,
		Kind:       uint8(KindLayerApp),
	}
	event.Tp.TraceId = previousTraceID
	event.Tp.SpanId = previousSpanID
	event.ConnInfo = BpfConnectionInfoT{D_port: 8080}
	send := func(event TCPLargeBufferHeader, payload string) {
		t.Helper()
		event.Len = uint32(len(payload))
		_, drop, err := appendTCPLargeBuffer(pctx, toRingbufRecord(t, event, payload))
		require.NoError(t, err)
		require.True(t, drop)
	}

	send(event, "GET / HTTP/1.1\r\n")

	rekey := event
	rekey.Action = largeBufferActionRekey
	rekey.Tp.TraceId = adoptedTraceID
	rekey.Tp.SpanId = adoptedSpanID
	send(rekey, previousIDs)

	appendEvent := rekey
	appendEvent.Action = largeBufferActionAppend
	send(appendEvent, "Traceparent: x\r\n\r\n")

	_, ok := extractTCPLargeBuffer(pctx, previousTraceID, previousSpanID, event.PacketType, event.Direction, event.ConnInfo, ProtocolTypeHTTP)
	require.False(t, ok, "the buffer must move to the adopted trace and span")
	buf, ok := extractTCPLargeBuffer(pctx, adoptedTraceID, adoptedSpanID, event.PacketType, event.Direction, event.ConnInfo, ProtocolTypeHTTP)
	require.True(t, ok)
	require.Equal(t, "GET / HTTP/1.1\r\nTraceparent: x\r\n\r\n", unix.ByteSliceToString(buf.UnsafeView()))

	// Nothing was sent under the previous IDs: the rekey is a no-op.
	send(rekey, previousIDs)
	_, ok = extractTCPLargeBuffer(pctx, adoptedTraceID, adoptedSpanID, event.PacketType, event.Direction, event.ConnInfo, ProtocolTypeHTTP)
	require.False(t, ok)

	// the trace ID alone is not a valid payload
	rekey.Len = uint32(len(previousTraceID))
	_, _, err := appendTCPLargeBuffer(pctx, toRingbufRecord(t, rekey, string(previousTraceID[:])))
	require.Error(t, err)
}

func toRingbufRecord(t *testing.T, event TCPLargeBufferHeader, buf string) *ringbuf.Record {
	var fixedPart bytes.Buffer
	if err := binary.Write(&fixedPart, binary.LittleEndian, event); err != nil {
		t.Fatalf("failed to write ringbuf record fixed part: %v", err)
	}

	if len(buf) < int(unsafe.Sizeof(TCPLargeBufferHeader{})) {
		buf += strings.Repeat("\x00", int(unsafe.Sizeof(TCPLargeBufferHeader{}))-len(buf))
	}

	fixedPart.Write([]byte(buf))
	return &ringbuf.Record{
		RawSample: fixedPart.Bytes(),
	}
}
