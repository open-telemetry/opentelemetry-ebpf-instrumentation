// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
)

func TestReadGoChannelLinkEvent(t *testing.T) {
	parseCtx := &EBPFParseContext{
		pendingSpanLinks: newPendingSpanLinks(),
	}

	leftTraceID := trace.TraceID{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	leftSpanID := trace.SpanID{2, 2, 2, 2, 2, 2, 2, 2}
	rightTraceID := trace.TraceID{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3}
	rightSpanID := trace.SpanID{4, 4, 4, 4, 4, 4, 4, 4}

	event := channelLinkTrace{
		Type: EventTypeGoChannelLink,
	}
	copy(event.SpanTp.TraceId[:], leftTraceID[:])
	copy(event.SpanTp.SpanId[:], leftSpanID[:])
	event.SpanTp.Flags = TPFlagSampled
	copy(event.LinkedSpanTp.TraceId[:], rightTraceID[:])
	copy(event.LinkedSpanTp.SpanId[:], rightSpanID[:])
	event.LinkedSpanTp.Flags = TPFlagSampled

	raw := unsafe.Slice((*byte)(unsafe.Pointer(&event)), int(unsafe.Sizeof(event)))
	record := &ringbuf.Record{RawSample: append([]byte(nil), raw...)}

	span, ignore, err := readGoChannelLinkEvent(parseCtx, record)
	require.NoError(t, err)
	assert.True(t, ignore)
	assert.Equal(t, request.Span{}, span)

	leftSpan := request.Span{TraceID: leftTraceID, SpanID: leftSpanID}
	parseCtx.consumePendingSpanLinks(&leftSpan)
	if assert.Len(t, leftSpan.Links, 1) {
		assert.Equal(t, rightTraceID, leftSpan.Links[0].TraceID)
		assert.Equal(t, rightSpanID, leftSpan.Links[0].SpanID)
		assert.Equal(t, uint8(TPFlagSampled), leftSpan.Links[0].TraceFlags)
	}

	rightSpan := request.Span{TraceID: rightTraceID, SpanID: rightSpanID}
	parseCtx.consumePendingSpanLinks(&rightSpan)
	if assert.Len(t, rightSpan.Links, 1) {
		assert.Equal(t, leftTraceID, rightSpan.Links[0].TraceID)
		assert.Equal(t, leftSpanID, rightSpan.Links[0].SpanID)
		assert.Equal(t, uint8(TPFlagSampled), rightSpan.Links[0].TraceFlags)
	}
}

func TestPendingSpanLinksDeduplicates(t *testing.T) {
	pending := newPendingSpanLinks()

	traceID := trace.TraceID{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	spanID := trace.SpanID{2, 2, 2, 2, 2, 2, 2, 2}
	linkedTraceID := trace.TraceID{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3}
	linkedSpanID := trace.SpanID{4, 4, 4, 4, 4, 4, 4, 4}

	key := spanLinkKey{traceID: traceID, spanID: spanID}
	link := request.SpanLink{TraceID: linkedTraceID, SpanID: linkedSpanID, TraceFlags: TPFlagSampled}

	pending.recordPair(key, link)
	pending.recordPair(key, link)

	span := request.Span{TraceID: traceID, SpanID: spanID}
	pending.consume(&span)
	if assert.Len(t, span.Links, 1) {
		assert.Equal(t, linkedTraceID, span.Links[0].TraceID)
		assert.Equal(t, linkedSpanID, span.Links[0].SpanID)
	}
}
