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

func TestTCPLargeBufferTruncationDetection(t *testing.T) {
	pctx := NewEBPFParseContext(nil, nil, nil)

	// Simulate the truncation scenario:
	// A large response arrives in one syscall, BPF truncates to 256KB (16 × 16KB chunks).
	// Then a second syscall arrives with more data (truncated to 256KB).
	// Without the fix, we'd get |256KB|256KB| with a hole. With the fix, we stop at 256KB.

	baseEvent := TCPLargeBufferHeader{
		Type:       12,
		PacketType: 2, // response
		Direction:  1,
		Kind:       uint8(KindLayerWire),
	}
	baseEvent.Tp.TraceId = [16]uint8{'T'}
	baseEvent.ConnInfo = BpfConnectionInfoT{D_port: 8080}

	numChunks := largeBufferPerSyscallCap / largeBufferMaxChunkPayload // 16 chunks for 256KB

	// First emission: numChunks full chunks (init + numChunks-1 appends) = 256KB (per-syscall cap)
	chunkPayload := strings.Repeat("A", largeBufferMaxChunkPayload) // 16KB

	// Chunk 1: init
	initEvent := baseEvent
	initEvent.Action = largeBufferActionInit
	initEvent.Len = uint32(largeBufferMaxChunkPayload)
	_, _, err := appendTCPLargeBuffer(pctx, toRingbufRecord(t, initEvent, chunkPayload))
	require.NoError(t, err)

	// Chunks 2..numChunks: append
	appendEvent := baseEvent
	appendEvent.Action = largeBufferActionAppend
	appendEvent.Len = uint32(largeBufferMaxChunkPayload)
	for i := 0; i < numChunks-1; i++ {
		_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, appendEvent, chunkPayload))
		require.NoError(t, err)
	}

	// At this point total = 256KB = per-syscall cap, buffer should be sealed.
	// Second emission: these chunks should be DROPPED.
	for i := 0; i < numChunks; i++ {
		_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, appendEvent, chunkPayload))
		require.NoError(t, err)
	}

	// Extract and verify: should be exactly 256KB (first emission only).
	key := largeBufferKey{
		traceID:    baseEvent.Tp.TraceId,
		packetType: baseEvent.PacketType,
		direction:  baseEvent.Direction,
		connInfo:   baseEvent.ConnInfo,
		kind:       largeBufferKind(baseEvent.Kind),
	}
	lb, ok := pctx.largeBuffers.Get(key)
	require.True(t, ok)
	require.Equal(t, largeBufferPerSyscallCap, lb.Len(),
		"buffer should be exactly 256KB — second emission chunks must be dropped")
}

func TestTCPLargeBufferNoTruncationWhenShortChunk(t *testing.T) {
	pctx := NewEBPFParseContext(nil, nil, nil)

	// Simulate a non-truncated scenario: data < per-syscall cap, last chunk is short.
	// E.g., 50KB = 3 × 16KB + 2KB. No truncation, no sealing.

	baseEvent := TCPLargeBufferHeader{
		Type:       12,
		PacketType: 1,
		Direction:  0,
		Kind:       uint8(KindLayerApp),
	}
	baseEvent.Tp.TraceId = [16]uint8{'N'}
	baseEvent.ConnInfo = BpfConnectionInfoT{D_port: 3306}

	fullChunk := strings.Repeat("B", largeBufferMaxChunkPayload)
	shortChunk := strings.Repeat("C", 2048) // 2KB — natural end of emission

	// Init: 16KB
	initEvent := baseEvent
	initEvent.Action = largeBufferActionInit
	initEvent.Len = uint32(largeBufferMaxChunkPayload)
	_, _, err := appendTCPLargeBuffer(pctx, toRingbufRecord(t, initEvent, fullChunk))
	require.NoError(t, err)

	// Append: 16KB + 16KB
	appendEvent := baseEvent
	appendEvent.Action = largeBufferActionAppend
	appendEvent.Len = uint32(largeBufferMaxChunkPayload)
	for i := 0; i < 2; i++ {
		_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, appendEvent, fullChunk))
		require.NoError(t, err)
	}

	// Append: 2KB (short = natural end, NOT truncated)
	appendEvent.Len = uint32(len(shortChunk))
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, appendEvent, shortChunk))
	require.NoError(t, err)

	// Now a second emission (next syscall): should NOT be dropped.
	appendEvent.Len = uint32(largeBufferMaxChunkPayload)
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, appendEvent, fullChunk))
	require.NoError(t, err)

	key := largeBufferKey{
		traceID:    baseEvent.Tp.TraceId,
		packetType: baseEvent.PacketType,
		direction:  baseEvent.Direction,
		connInfo:   baseEvent.ConnInfo,
		kind:       largeBufferKind(baseEvent.Kind),
	}
	lb, ok := pctx.largeBuffers.Get(key)
	require.True(t, ok)
	expectedLen := 3*largeBufferMaxChunkPayload + 2048 + largeBufferMaxChunkPayload // 50KB + 16KB
	require.Equal(t, expectedLen, lb.Len(),
		"all chunks should be accepted when no truncation occurred")
}

func TestTCPLargeBufferInitResetsSealed(t *testing.T) {
	pctx := NewEBPFParseContext(nil, nil, nil)

	// After sealing, a new init should reset the sealed state.
	baseEvent := TCPLargeBufferHeader{
		Type:       12,
		PacketType: 1,
		Direction:  0,
		Kind:       uint8(KindLayerWire),
	}
	baseEvent.Tp.TraceId = [16]uint8{'R'}
	baseEvent.ConnInfo = BpfConnectionInfoT{D_port: 9090}

	numChunks := largeBufferPerSyscallCap / largeBufferMaxChunkPayload // 16 chunks for 256KB
	chunkPayload := strings.Repeat("X", largeBufferMaxChunkPayload)

	// First: fill to 256KB (triggers seal)
	initEvent := baseEvent
	initEvent.Action = largeBufferActionInit
	initEvent.Len = uint32(largeBufferMaxChunkPayload)
	_, _, _ = appendTCPLargeBuffer(pctx, toRingbufRecord(t, initEvent, chunkPayload))

	appendEvent := baseEvent
	appendEvent.Action = largeBufferActionAppend
	appendEvent.Len = uint32(largeBufferMaxChunkPayload)
	for i := 0; i < numChunks-1; i++ {
		_, _, _ = appendTCPLargeBuffer(pctx, toRingbufRecord(t, appendEvent, chunkPayload))
	}

	// Now re-init (new request on same connection)
	newPayload := strings.Repeat("Y", 100)
	initEvent.Len = uint32(len(newPayload))
	_, _, err := appendTCPLargeBuffer(pctx, toRingbufRecord(t, initEvent, newPayload))
	require.NoError(t, err)

	// Append should work (seal was cleared)
	appendEvent.Len = uint32(len(newPayload))
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, appendEvent, newPayload))
	require.NoError(t, err)

	key := largeBufferKey{
		traceID:    baseEvent.Tp.TraceId,
		packetType: baseEvent.PacketType,
		direction:  baseEvent.Direction,
		connInfo:   baseEvent.ConnInfo,
		kind:       largeBufferKind(baseEvent.Kind),
	}
	lb, ok := pctx.largeBuffers.Get(key)
	require.True(t, ok)
	require.Equal(t, 200, lb.Len(), "init should reset seal and allow new data")
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
