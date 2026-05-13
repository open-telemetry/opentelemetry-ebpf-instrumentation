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
		protocolType uint8
		expected     largeBufferKind
	}{
		{ProtocolTypeKafka, KindLayerApp},
		{ProtocolTypeMySQL, KindLayerApp},
		{ProtocolTypePostgres, KindLayerApp},
		{ProtocolTypeMSSQL, KindLayerApp},
		{ProtocolTypeHTTP, KindLayerApp},
		{ProtocolTypeMQTT, KindLayerWire},
		{ProtocolTypeUnknown, KindLayerWire},
	}
	for _, tt := range tests {
		require.Equal(t, tt.expected, protocolToLargeBufferKind(tt.protocolType))
	}
}

func TestTCPLargeBuffers(t *testing.T) {
	pctx := NewEBPFParseContext(nil, nil, nil)
	verifyLargeBuffer := func(traceID [16]uint8, packetType, direction uint8, connInfo BpfConnectionInfoT, expectedBuf string) {
		buf, ok := extractTCPLargeBuffer(pctx, traceID, packetType, direction, connInfo, ProtocolTypeMySQL)
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
	firstEvent.ConnInfo = BpfConnectionInfoT{
		D_port: 2000,
	}
	firstBuf := "obi rocks!"

	span, drop, err := appendTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, firstBuf))
	require.NoError(t, err)
	require.True(t, drop)
	require.Equal(t, request.Span{}, span)

	// Verify normal write
	verifyLargeBuffer(firstEvent.Tp.TraceId, firstEvent.PacketType, firstEvent.Direction, firstEvent.ConnInfo, firstBuf)

	secondBuf := "obi rocks twice!"
	firstEvent.Len = uint32(len(secondBuf))
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, firstBuf))
	require.NoError(t, err)
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, secondBuf))
	require.NoError(t, err)
	// Verify buffer overwrite
	verifyLargeBuffer(firstEvent.Tp.TraceId, firstEvent.PacketType, firstEvent.Direction, firstEvent.ConnInfo, secondBuf)

	// Verify second read error
	_, ok := extractTCPLargeBuffer(pctx, firstEvent.Tp.TraceId, firstEvent.PacketType, firstEvent.Direction, firstEvent.ConnInfo, ProtocolTypeMySQL)
	require.False(t, ok, "Expected to not find large buffer after first read")

	firstEvent.Len = uint32(len(firstBuf))
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, firstBuf))
	require.NoError(t, err)

	// Verify no buffer read happens for different traceID/packet_type
	_, ok = extractTCPLargeBuffer(pctx, [16]uint8{99}, firstEvent.PacketType, firstEvent.Direction, firstEvent.ConnInfo, ProtocolTypeMySQL)
	require.False(t, ok, "Expected to not find large buffer for this traceID")
	_, ok = extractTCPLargeBuffer(pctx, firstEvent.Tp.TraceId, 3, firstEvent.Direction, firstEvent.ConnInfo, ProtocolTypeMySQL)
	require.False(t, ok, "Expected to not find large buffer for this packet_type")
	verifyLargeBuffer(firstEvent.Tp.TraceId, firstEvent.PacketType, firstEvent.Direction, firstEvent.ConnInfo, firstBuf)

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
	appendEvent.ConnInfo = BpfConnectionInfoT{
		D_port: 2000,
	}
	appendBuf := "append"

	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, appendEvent, appendBuf))
	require.NoError(t, err)
	// The buffer should now be firstBuf + appendBuf
	verifyLargeBuffer(firstEvent.Tp.TraceId, firstEvent.PacketType, firstEvent.Direction, firstEvent.ConnInfo, firstBuf+appendBuf)

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
	verifyLargeBuffer(firstEvent.Tp.TraceId, firstEvent.PacketType, firstEvent.Direction, firstEvent.ConnInfo, firstBuf+"foobar")
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

// TestLargeBufferKeyStability verifies that a large buffer appended under an
// original trace ID is still retrievable after the request's trace ID has been
// overwritten by a chunked traceparent scan.
//
// On the eBPF side, http_send_large_buffer always stores the buffer under
// req->original_trace_id (not req->tp.trace_id which may be updated later).
// On the Go side, extractTCPLargeBuffer is called with event.OriginalTraceId.
// This test ensures the two sides agree on the key, so a late traceparent
// discovery does not break large-buffer correlation.
func TestLargeBufferKeyStability(t *testing.T) {
	pctx := NewEBPFParseContext(nil, nil, nil)

	originalID := [16]uint8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	updatedID := [16]uint8{0xde, 0xad, 0xbe, 0xef}

	connInfo := BpfConnectionInfoT{D_port: 3000}
	const packetType uint8 = 1
	const direction uint8 = 0

	// Simulate eBPF: large_buf->tp.trace_id = req->original_trace_id
	event := TCPLargeBufferHeader{
		Type:       12,
		PacketType: packetType,
		Direction:  direction,
		Len:        uint32(len("hello")),
		Kind:       uint8(KindLayerApp),
	}
	event.Tp.TraceId = originalID
	event.ConnInfo = connInfo

	_, _, err := appendTCPLargeBuffer(pctx, toRingbufRecord(t, event, "hello"))
	require.NoError(t, err)

	// Looking up with the updated (overridden) trace ID must fail.
	_, ok := extractTCPLargeBuffer(pctx, updatedID, packetType, direction, connInfo, ProtocolTypeHTTP)
	require.False(t, ok, "lookup with overridden trace ID must not find the buffer")

	// Looking up with the original trace ID (as event.OriginalTraceId provides) must succeed.
	lb, ok := extractTCPLargeBuffer(pctx, originalID, packetType, direction, connInfo, ProtocolTypeHTTP)
	require.True(t, ok, "lookup with original trace ID must find the buffer")
	require.Equal(t, "hello", unix.ByteSliceToString(lb.UnsafeView()))
}
