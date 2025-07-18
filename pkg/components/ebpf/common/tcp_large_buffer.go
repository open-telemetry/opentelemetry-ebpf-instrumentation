package ebpfcommon

import (
	"unsafe"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/ringbuf"
)

type (
	largeBufferKey struct {
		traceID   [16]uint8
		spanID    [8]uint8
		direction uint8
	}
	largeBuffer struct {
		buf []byte
	}
)

func appendTCPLargeBuffer(parseCtx *EBPFParseContext, record *ringbuf.Record) (request.Span, bool, error) {
	hdrSize := uint32(unsafe.Sizeof(TCPLargeBufferHeader{})) - uint32(unsafe.Sizeof(uintptr(0))) // Remove `buf` placeholder

	event, err := ReinterpretCast[TCPLargeBufferHeader](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}
	newBuffer := record.RawSample[hdrSize:]
	newLen := int(event.Len)

	key := largeBufferKey{
		traceID:   event.Tp.TraceId,
		spanID:    event.Tp.SpanId,
		direction: event.Direction,
	}

	switch event.Action {
	case 1: // LargeBufActionAppend
		// If this is an append action, we need to check if the buffer already exists
		if lb, ok := parseCtx.largeBuffers.Get(key); ok {
			// If it exists, we can append to it
			newBuffer = append(lb.buf, newBuffer...)
			newLen += len(lb.buf)
		}
	default: // LargeBufActionInit
	}

	copiedBuffer := make([]byte, newLen)
	copy(copiedBuffer, newBuffer)
	parseCtx.largeBuffers.Add(key, largeBuffer{
		buf: copiedBuffer,
	})

	return request.Span{}, true, nil
}

func extractTCPLargeBuffer(parseCtx *EBPFParseContext, traceID [16]uint8, spanID [8]uint8, direction uint8) ([]byte, bool) {
	key := largeBufferKey{
		spanID:    spanID,
		traceID:   traceID,
		direction: direction,
	}

	if lb, ok := parseCtx.largeBuffers.Get(key); ok {
		parseCtx.largeBuffers.Remove(key)
		return lb.buf, true
	}

	return nil, false
}
