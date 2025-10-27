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
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
)

func TestTCPLargeBuffers(t *testing.T) {
	pctx := NewEBPFParseContext(nil)
	verifyLargeBuffer := func(traceID [16]uint8, packetType, direction uint8, connInfo BpfConnectionInfoT, expectedBuf string) {
		buf, ok := extractTCPLargeBuffer(pctx, traceID, packetType, direction, connInfo)
		require.True(t, ok, "Expected to find large buffer")
		require.Equal(t, expectedBuf, unix.ByteSliceToString(buf), "Buffer content mismatch")
	}

	firstEvent := TCPLargeBufferHeader{
		Type:       12,
		PacketType: 1,
		Direction:  0,
		Len:        10,
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
	_, ok := extractTCPLargeBuffer(pctx, firstEvent.Tp.TraceId, firstEvent.PacketType, firstEvent.Direction, firstEvent.ConnInfo)
	require.False(t, ok, "Expected to not find large buffer after first read")

	firstEvent.Len = uint32(len(firstBuf))
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, firstBuf))
	require.NoError(t, err)

	// Verify no buffer read happens for different traceID/packet_type
	_, ok = extractTCPLargeBuffer(pctx, [16]uint8{99}, firstEvent.PacketType, firstEvent.Direction, firstEvent.ConnInfo)
	require.False(t, ok, "Expected to not find large buffer for this traceID")
	_, ok = extractTCPLargeBuffer(pctx, firstEvent.Tp.TraceId, 3, firstEvent.Direction, firstEvent.ConnInfo)
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
