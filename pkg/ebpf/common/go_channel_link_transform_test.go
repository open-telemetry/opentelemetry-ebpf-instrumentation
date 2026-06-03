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
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
)

func TestReadGoChannelLinkEvent(t *testing.T) {
	parseCtx := &EBPFParseContext{
		pendingSpanLinks: newPendingSpanLinks(),
	}

	senderTraceID := trace.TraceID{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	senderSpanID := trace.SpanID{2, 2, 2, 2, 2, 2, 2, 2}
	receiverTraceID := trace.TraceID{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3}
	receiverSpanID := trace.SpanID{4, 4, 4, 4, 4, 4, 4, 4}

	event := GoChannelLinkTrace{
		Type: EventTypeGoChannelLink,
	}
	copy(event.SenderTp.TraceId[:], senderTraceID[:])
	copy(event.SenderTp.SpanId[:], senderSpanID[:])
	event.SenderTp.Flags = TPFlagSampled
	copy(event.ReceiverTp.TraceId[:], receiverTraceID[:])
	copy(event.ReceiverTp.SpanId[:], receiverSpanID[:])
	event.ReceiverTp.Flags = TPFlagSampled

	raw := unsafe.Slice((*byte)(unsafe.Pointer(&event)), int(unsafe.Sizeof(event)))
	record := &ringbuf.Record{RawSample: append([]byte(nil), raw...)}

	span, ignore, err := readGoChannelLinkEvent(parseCtx, record)
	require.NoError(t, err)
	assert.True(t, ignore)
	assert.Equal(t, request.Span{}, span)

	receiverSpan := request.Span{TraceID: receiverTraceID, SpanID: receiverSpanID}
	parseCtx.consumePendingSpanLinks(&receiverSpan)
	if assert.Len(t, receiverSpan.Links, 1) {
		assert.Equal(t, senderTraceID, receiverSpan.Links[0].TraceID)
		assert.Equal(t, senderSpanID, receiverSpan.Links[0].SpanID)
		assert.Equal(t, uint8(TPFlagSampled), receiverSpan.Links[0].TraceFlags)
	}

	senderSpan := request.Span{TraceID: senderTraceID, SpanID: senderSpanID}
	parseCtx.consumePendingSpanLinks(&senderSpan)
	assert.Empty(t, senderSpan.Links)
}

func TestPendingSpanLinksDeduplicates(t *testing.T) {
	pending := newPendingSpanLinks()

	traceID := trace.TraceID{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	spanID := trace.SpanID{2, 2, 2, 2, 2, 2, 2, 2}
	linkedTraceID := trace.TraceID{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3}
	linkedSpanID := trace.SpanID{4, 4, 4, 4, 4, 4, 4, 4}

	key := spanLinkKey{traceID: traceID, spanID: spanID}
	link := request.SpanLink{TraceID: linkedTraceID, SpanID: linkedSpanID, TraceFlags: TPFlagSampled}

	pending.recordLink(key, link)
	pending.recordLink(key, link)

	span := request.Span{TraceID: traceID, SpanID: spanID}
	pending.consume(&span)
	if assert.Len(t, span.Links, 1) {
		assert.Equal(t, linkedTraceID, span.Links[0].TraceID)
		assert.Equal(t, linkedSpanID, span.Links[0].SpanID)
	}
}

func TestPendingSpanLinksIgnoresInvalidAndSelfLinks(t *testing.T) {
	pending := newPendingSpanLinks()

	traceID := trace.TraceID{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	spanID := trace.SpanID{2, 2, 2, 2, 2, 2, 2, 2}
	key := spanLinkKey{traceID: traceID, spanID: spanID}

	pending.recordLink(key, request.SpanLink{TraceID: trace.TraceID{}, SpanID: spanID})
	pending.recordLink(key, request.SpanLink{TraceID: traceID, SpanID: trace.SpanID{}})
	pending.recordLink(key, request.SpanLink{TraceID: traceID, SpanID: spanID})
	pending.recordLink(spanLinkKey{}, request.SpanLink{TraceID: traceID, SpanID: spanID})

	span := request.Span{TraceID: traceID, SpanID: spanID}
	pending.consume(&span)
	assert.Empty(t, span.Links)
}

func TestPendingSpanLinksCapsLinksPerSpan(t *testing.T) {
	pending := newPendingSpanLinks()

	traceID := trace.TraceID{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	spanID := trace.SpanID{2, 2, 2, 2, 2, 2, 2, 2}
	key := spanLinkKey{traceID: traceID, spanID: spanID}

	for i := 0; i < maxLinksPerSpan+2; i++ {
		linkTraceID := trace.TraceID{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, byte(i + 1)}
		linkSpanID := trace.SpanID{4, 4, 4, 4, 4, 4, 4, byte(i + 1)}
		pending.recordLink(key, request.SpanLink{TraceID: linkTraceID, SpanID: linkSpanID})
	}

	span := request.Span{TraceID: traceID, SpanID: spanID}
	pending.consume(&span)
	assert.Len(t, span.Links, maxLinksPerSpan)
}

func TestNewEBPFParseContextGoChannelSpanLinksOptIn(t *testing.T) {
	assert.Nil(t, NewEBPFParseContext(nil, nil, nil).pendingSpanLinks)
	assert.Nil(t, NewEBPFParseContext(&config.EBPFTracer{}, nil, nil).pendingSpanLinks)

	ctx := NewEBPFParseContext(&config.EBPFTracer{GoChannelSpanLinks: true}, nil, nil)
	require.NotNil(t, ctx.pendingSpanLinks)
}
