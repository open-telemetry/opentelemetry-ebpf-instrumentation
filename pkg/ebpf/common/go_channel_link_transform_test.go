// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

func TestGoChannelLinkEventTypeDoesNotConflictWithRuntimeMetrics(t *testing.T) {
	assert.Equal(t, uint8(18), uint8(EventTypeGoChannelLink))
	assert.NotEqual(t, uint8(17), uint8(EventTypeGoChannelLink))
}

func TestReadBPFTraceAsSpanGoChannelLinkEvent(t *testing.T) {
	parseCtx := NewEBPFParseContext(nil, nil, nil)

	senderTraceID := testTraceID(1)
	senderSpanID := testSpanID(2)
	receiverTraceID := testTraceID(3)
	receiverSpanID := testSpanID(4)

	record := channelLinkRecord(t, senderTraceID, senderSpanID, receiverTraceID, receiverSpanID)

	span, ignore, err := ReadBPFTraceAsSpan(parseCtx, nil, record, nil)
	require.NoError(t, err)
	assert.True(t, ignore)
	assert.Equal(t, request.Span{}, span)
	require.NotNil(t, parseCtx.pendingSpanLinks)

	receiverSpan := request.Span{TraceID: receiverTraceID, SpanID: receiverSpanID}
	parseCtx.consumePendingSpanLinks(&receiverSpan)
	require.Len(t, receiverSpan.Links, 1)
	assert.Equal(t, senderTraceID, receiverSpan.Links[0].TraceID)
	assert.Equal(t, senderSpanID, receiverSpan.Links[0].SpanID)
	assert.Equal(t, uint8(TPFlagSampled), receiverSpan.Links[0].TraceFlags)

	senderSpan := request.Span{TraceID: senderTraceID, SpanID: senderSpanID}
	parseCtx.consumePendingSpanLinks(&senderSpan)
	assert.Empty(t, senderSpan.Links)

	emptyReceiverSpan := request.Span{TraceID: receiverTraceID, SpanID: receiverSpanID}
	parseCtx.consumePendingSpanLinks(&emptyReceiverSpan)
	assert.Empty(t, emptyReceiverSpan.Links)
}

func TestReadGoChannelLinkEventRejectsMalformedRecord(t *testing.T) {
	parseCtx := NewEBPFParseContext(nil, nil, nil)

	span, ignore, err := ReadBPFTraceAsSpan(
		parseCtx,
		nil,
		&ringbuf.Record{RawSample: []byte{EventTypeGoChannelLink}},
		nil,
	)

	require.Error(t, err)
	assert.True(t, ignore)
	assert.Equal(t, request.Span{}, span)
	assert.Nil(t, parseCtx.pendingSpanLinks)
}

func TestPendingSpanLinksDeduplicates(t *testing.T) {
	pending := newPendingSpanLinks()

	key := spanLinkKey{traceID: testTraceID(1), spanID: testSpanID(2)}
	link := request.SpanLink{TraceID: testTraceID(3), SpanID: testSpanID(4), TraceFlags: TPFlagSampled}

	pending.recordLink(key, link)
	pending.recordLink(key, link)

	span := request.Span{TraceID: key.traceID, SpanID: key.spanID}
	pending.consume(&span)
	require.Len(t, span.Links, 1)
	assert.Equal(t, link, span.Links[0])
}

func TestPendingSpanLinksDoesNotDuplicateExistingSpanLinks(t *testing.T) {
	pending := newPendingSpanLinks()

	key := spanLinkKey{traceID: testTraceID(1), spanID: testSpanID(2)}
	link := request.SpanLink{TraceID: testTraceID(3), SpanID: testSpanID(4), TraceFlags: TPFlagSampled}

	pending.recordLink(key, link)

	span := request.Span{
		TraceID: key.traceID,
		SpanID:  key.spanID,
		Links:   []request.SpanLink{link},
	}
	pending.consume(&span)
	require.Len(t, span.Links, 1)
	assert.Equal(t, link, span.Links[0])

	emptySpan := request.Span{TraceID: key.traceID, SpanID: key.spanID}
	pending.consume(&emptySpan)
	assert.Empty(t, emptySpan.Links)
}

func TestPendingSpanLinksIgnoresInvalidAndSelfLinks(t *testing.T) {
	pending := newPendingSpanLinks()

	traceID := testTraceID(1)
	spanID := testSpanID(2)
	key := spanLinkKey{traceID: traceID, spanID: spanID}

	pending.recordLink(key, request.SpanLink{TraceID: trace.TraceID{}, SpanID: testSpanID(3)})
	pending.recordLink(key, request.SpanLink{TraceID: testTraceID(3), SpanID: trace.SpanID{}})
	pending.recordLink(key, request.SpanLink{TraceID: traceID, SpanID: spanID})
	pending.recordLink(spanLinkKey{}, request.SpanLink{TraceID: testTraceID(3), SpanID: testSpanID(3)})

	span := request.Span{TraceID: traceID, SpanID: spanID}
	pending.consume(&span)
	assert.Empty(t, span.Links)
}

func TestPendingSpanLinksCapsLinksAtOTelDefaultLimit(t *testing.T) {
	pending := newPendingSpanLinks()

	key := spanLinkKey{traceID: testTraceID(1), spanID: testSpanID(2)}

	for i := range maxSpanLinks + 2 {
		pending.recordLink(key, request.SpanLink{
			TraceID: testTraceID(100 + i),
			SpanID:  testSpanID(100 + i),
		})
	}

	span := request.Span{TraceID: key.traceID, SpanID: key.spanID}
	pending.consume(&span)
	assert.Len(t, span.Links, maxSpanLinks)
}

func TestPendingSpanLinksRespectsOTelDefaultLimitWithExistingLinks(t *testing.T) {
	pending := newPendingSpanLinks()

	key := spanLinkKey{traceID: testTraceID(1), spanID: testSpanID(2)}

	existingLinks := make([]request.SpanLink, 0, maxSpanLinks-1)
	for i := range maxSpanLinks - 1 {
		existingLinks = append(existingLinks, request.SpanLink{
			TraceID: testTraceID(100 + i),
			SpanID:  testSpanID(100 + i),
		})
	}

	for i := range 2 {
		pending.recordLink(key, request.SpanLink{
			TraceID: testTraceID(1000 + i),
			SpanID:  testSpanID(1000 + i),
		})
	}

	span := request.Span{
		TraceID: key.traceID,
		SpanID:  key.spanID,
		Links:   existingLinks,
	}

	pending.consume(&span)
	assert.Len(t, span.Links, maxSpanLinks)
	assert.Equal(t, testTraceID(1000), span.Links[maxSpanLinks-1].TraceID)
}

func TestPendingSpanLinksBoundsReceiverCache(t *testing.T) {
	pending := newPendingSpanLinks()
	link := request.SpanLink{TraceID: testTraceID(1), SpanID: testSpanID(1)}

	for i := range maxPendingSpanLinks + 1 {
		pending.recordLink(spanLinkKey{traceID: testTraceID(1000 + i), spanID: testSpanID(1000 + i)}, link)
	}

	assert.LessOrEqual(t, pending.cache.Len(), maxPendingSpanLinks)

	evictedSpan := request.Span{TraceID: testTraceID(1000), SpanID: testSpanID(1000)}
	pending.consume(&evictedSpan)
	assert.Empty(t, evictedSpan.Links)

	latestSpan := request.Span{
		TraceID: testTraceID(1000 + maxPendingSpanLinks),
		SpanID:  testSpanID(1000 + maxPendingSpanLinks),
	}
	pending.consume(&latestSpan)
	assert.Len(t, latestSpan.Links, 1)
}

func TestPendingSpanLinksExpire(t *testing.T) {
	pending := newPendingSpanLinksWith(8, time.Millisecond)

	key := spanLinkKey{traceID: testTraceID(1), spanID: testSpanID(2)}
	pending.recordLink(key, request.SpanLink{TraceID: testTraceID(3), SpanID: testSpanID(4)})

	time.Sleep(10 * time.Millisecond)

	span := request.Span{TraceID: key.traceID, SpanID: key.spanID}
	pending.consume(&span)
	assert.Empty(t, span.Links)
}

func TestFinalizeParsedSpanConsumesPendingSpanLinks(t *testing.T) {
	parseCtx := &EBPFParseContext{pendingSpanLinks: newPendingSpanLinks()}

	key := spanLinkKey{traceID: testTraceID(1), spanID: testSpanID(2)}
	link := request.SpanLink{TraceID: testTraceID(3), SpanID: testSpanID(4), TraceFlags: TPFlagSampled}
	parseCtx.pendingSpanLinks.recordLink(key, link)

	span, ignore, err := finalizeParsedSpan(
		parseCtx,
		request.Span{TraceID: key.traceID, SpanID: key.spanID},
		false,
		nil,
	)

	require.NoError(t, err)
	assert.False(t, ignore)
	require.Len(t, span.Links, 1)
	assert.Equal(t, link, span.Links[0])
}

func TestEmitExtraSpansConsumesPendingSpanLinks(t *testing.T) {
	var emitted []request.Span
	parseCtx := &EBPFParseContext{
		pendingSpanLinks: newPendingSpanLinks(),
		emitSpans: func(spans []request.Span) {
			emitted = append([]request.Span(nil), spans...)
		},
	}

	key := spanLinkKey{traceID: testTraceID(1), spanID: testSpanID(2)}
	link := request.SpanLink{TraceID: testTraceID(3), SpanID: testSpanID(4), TraceFlags: TPFlagSampled}
	parseCtx.pendingSpanLinks.recordLink(key, link)

	parseCtx.emitExtraSpans(request.Span{TraceID: key.traceID, SpanID: key.spanID})

	require.Len(t, emitted, 1)
	require.Len(t, emitted[0].Links, 1)
	assert.Equal(t, link, emitted[0].Links[0])
}

func channelLinkRecord(
	t *testing.T,
	senderTraceID trace.TraceID,
	senderSpanID trace.SpanID,
	receiverTraceID trace.TraceID,
	receiverSpanID trace.SpanID,
) *ringbuf.Record {
	t.Helper()

	event := GoChannelLinkTrace{Type: EventTypeGoChannelLink}
	copy(event.SenderTp.TraceId[:], senderTraceID[:])
	copy(event.SenderTp.SpanId[:], senderSpanID[:])
	event.SenderTp.Flags = TPFlagSampled
	copy(event.ReceiverTp.TraceId[:], receiverTraceID[:])
	copy(event.ReceiverTp.SpanId[:], receiverSpanID[:])
	event.ReceiverTp.Flags = TPFlagSampled

	raw := unsafe.Slice((*byte)(unsafe.Pointer(&event)), int(unsafe.Sizeof(event)))
	return &ringbuf.Record{RawSample: append([]byte(nil), raw...)}
}

func testTraceID(n int) trace.TraceID {
	id := trace.TraceID{1}
	id[14] = byte(n >> 8)
	id[15] = byte(n)
	return id
}

func testSpanID(n int) trace.SpanID {
	id := trace.SpanID{1}
	id[6] = byte(n >> 8)
	id[7] = byte(n)
	return id
}
