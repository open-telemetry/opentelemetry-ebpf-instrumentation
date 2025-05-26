package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/ringbuf"
)

func TestTCPLargeBuffers(t *testing.T) {
	pctx := NewEBPFParseContext(nil)
	verifyLargeBuffer := func(traceID [16]uint8, spanID [8]uint8, direction uint8, expectedBuf string) {
		buf, ok := getTCPLargeBuffer(pctx, traceID, spanID, direction)
		require.True(t, ok, "Expected to find large buffer")
		require.Equal(t, expectedBuf, string(buf), "Buffer content mismatch")
	}

	firstEvent := TCPLargeBufferHeader{
		Type:      12,
		Direction: 1,
		Len:       10,
	}
	firstEvent.Tp.TraceId = [16]uint8{'1'}
	firstEvent.Tp.SpanId = [8]uint8{'2'}
	firstBuf := "obi rocks!"

	span, drop, err := setTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, firstBuf))
	require.NoError(t, err)
	require.True(t, drop)
	require.Equal(t, request.Span{}, span)

	// Verify normal write
	verifyLargeBuffer(firstEvent.Tp.TraceId, firstEvent.Tp.SpanId, firstEvent.Direction, firstBuf)

	secondBuf := "obi rocks twice!"
	firstEvent.Len = uint32(len(secondBuf))
	_, _, err = setTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, firstBuf))
	require.NoError(t, err)
	_, _, err = setTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, secondBuf))
	require.NoError(t, err)
	// Verify buffer overwrite
	verifyLargeBuffer(firstEvent.Tp.TraceId, firstEvent.Tp.SpanId, firstEvent.Direction, secondBuf)

	// Verify second read error
	_, ok := getTCPLargeBuffer(pctx, firstEvent.Tp.TraceId, firstEvent.Tp.SpanId, firstEvent.Direction)
	require.False(t, ok, "Expected to not find large buffer after first read")

	firstEvent.Len = uint32(len(firstBuf))
	_, _, err = setTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, firstBuf))
	require.NoError(t, err)

	// Verify no buffer read happens for different traceID/direction
	_, ok = getTCPLargeBuffer(pctx, [16]uint8{99}, firstEvent.Tp.SpanId, firstEvent.Direction)
	require.False(t, ok, "Expected to not find large buffer for this traceID")
	_, ok = getTCPLargeBuffer(pctx, firstEvent.Tp.TraceId, firstEvent.Tp.SpanId, 3)
	require.False(t, ok, "Expected to not find large buffer for this direction")
	verifyLargeBuffer(firstEvent.Tp.TraceId, firstEvent.Tp.SpanId, firstEvent.Direction, firstBuf)
}

func toRingbufRecord(t *testing.T, event TCPLargeBufferHeader, buf string) *ringbuf.Record {
	var fixedPart bytes.Buffer
	if err := binary.Write(&fixedPart, binary.LittleEndian, event); err != nil {
		t.Fatalf("failed to write ringbuf record fixed part: %v", err)
	}

	fixedPart.Write([]byte(buf))
	return &ringbuf.Record{
		RawSample: fixedPart.Bytes(),
	}
}
