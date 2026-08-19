// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly

import (
	"container/list"
	"context"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

var (
	testTrace  = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	parentSpan = [8]byte{0xaa, 1, 2, 3, 4, 5, 6, 7}
	childSpan  = [8]byte{0xbb, 1, 2, 3, 4, 5, 6, 7}
)

func testSettler(t *testing.T, maxTx time.Duration) (*parentSettler, <-chan []request.Span) {
	t.Helper()

	ends, err := lru.New[spanKey, int64](128)
	require.NoError(t, err)

	output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(16))
	out := output.Subscribe()

	return &parentSettler{
		output: output,
		maxTx:  maxTx,
		ends:   ends,
		held:   map[spanKey][]*list.Element{},
		order:  list.New(),
	}, out
}

func serverSpan(end int64) request.Span {
	return request.Span{
		Type:    request.EventTypeHTTP,
		TraceID: testTrace,
		SpanID:  parentSpan,
		Start:   10,
		End:     end,
	}
}

func conditionalChild(start int64) request.Span {
	return request.Span{
		Type:              request.EventTypeHTTPClient,
		TraceID:           testTrace,
		SpanID:            childSpan,
		ParentSpanID:      parentSpan,
		ParentConditional: true,
		Start:             start,
		End:               start + 10,
	}
}

func collect(t *testing.T, out <-chan []request.Span) []request.Span {
	t.Helper()

	var spans []request.Span
	for {
		select {
		case batch := <-out:
			spans = append(spans, batch...)
		case <-time.After(100 * time.Millisecond):
			return spans
		}
	}
}

func TestSettleUnconditionalPassThrough(t *testing.T) {
	s, out := testSettler(t, time.Minute)

	child := conditionalChild(100)
	child.ParentConditional = false
	s.process(context.Background(), []request.Span{child})

	got := collect(t, out)
	require.Len(t, got, 1)
	assert.Equal(t, testTrace, [16]byte(got[0].TraceID))
	assert.Equal(t, parentSpan, [8]byte(got[0].ParentSpanID))
}

func TestSettleChildInsideParentKeepsLink(t *testing.T) {
	s, out := testSettler(t, time.Minute)

	// parent still running (ends at 200) when the child starts at 100
	s.process(context.Background(), []request.Span{serverSpan(200)})
	s.process(context.Background(), []request.Span{conditionalChild(100)})

	got := collect(t, out)
	require.Len(t, got, 2)
	child := got[1]
	assert.Equal(t, testTrace, [16]byte(child.TraceID))
	assert.Equal(t, parentSpan, [8]byte(child.ParentSpanID))
}

func TestSettleChildAfterParentEndIsDetached(t *testing.T) {
	s, out := testSettler(t, time.Minute)

	// parent finished at 50, child starts at 100
	s.process(context.Background(), []request.Span{serverSpan(50)})
	s.process(context.Background(), []request.Span{conditionalChild(100)})

	got := collect(t, out)
	require.Len(t, got, 2)
	child := got[1]
	assert.Equal(t, testTrace, [16]byte(child.TraceID))
	assert.False(t, child.ParentSpanID.IsValid())
}

func TestSettleChildHeldUntilParentArrives(t *testing.T) {
	s, out := testSettler(t, time.Minute)

	s.process(context.Background(), []request.Span{conditionalChild(100)})
	require.Empty(t, collect(t, out), "conditional child must wait for its parent")

	// parent arrives later, still running past the child's start
	s.process(context.Background(), []request.Span{serverSpan(200)})

	got := collect(t, out)
	require.Len(t, got, 2)
	for _, span := range got {
		assert.Equal(t, testTrace, [16]byte(span.TraceID))
	}
}

func TestSettleLateChildReleasedByParentAndDetached(t *testing.T) {
	s, out := testSettler(t, time.Minute)

	s.process(context.Background(), []request.Span{conditionalChild(300)})
	require.Empty(t, collect(t, out))

	// parent arrives having ended before the child started
	s.process(context.Background(), []request.Span{serverSpan(200)})

	got := collect(t, out)
	require.Len(t, got, 2)
	child := got[0]
	if child.SpanID != childSpan {
		child = got[1]
	}
	assert.Equal(t, testTrace, [16]byte(child.TraceID))
	assert.False(t, child.ParentSpanID.IsValid())
}

func TestSettleOrphanExpiresDetached(t *testing.T) {
	s, out := testSettler(t, time.Nanosecond)

	s.process(context.Background(), []request.Span{conditionalChild(100)})
	require.Empty(t, collect(t, out))

	s.expire(context.Background(), time.Now().Add(time.Second))

	got := collect(t, out)
	require.Len(t, got, 1)
	assert.Equal(t, testTrace, [16]byte(got[0].TraceID))
	assert.Zero(t, s.order.Len())
	assert.Empty(t, s.held)
}

func TestSettleDetachedParentKeepsDescendantTrace(t *testing.T) {
	s, out := testSettler(t, time.Minute)
	descendantSpan := [8]byte{0xcc, 1, 2, 3, 4, 5, 6, 7}
	descendant := request.Span{
		TraceID:      testTrace,
		SpanID:       descendantSpan,
		ParentSpanID: childSpan,
		Start:        110,
		End:          120,
	}

	s.process(context.Background(), []request.Span{serverSpan(50)})
	s.process(context.Background(), []request.Span{descendant})
	s.process(context.Background(), []request.Span{conditionalChild(100)})

	got := collect(t, out)
	require.Len(t, got, 3)
	var child, emittedDescendant request.Span
	for _, span := range got {
		switch span.SpanID {
		case childSpan:
			child = span
		case descendantSpan:
			emittedDescendant = span
		}
	}
	assert.Equal(t, testTrace, [16]byte(child.TraceID))
	assert.False(t, child.ParentSpanID.IsValid())
	assert.Equal(t, child.TraceID, emittedDescendant.TraceID)
	assert.Equal(t, child.SpanID, emittedDescendant.ParentSpanID)
}

func TestSettleFlushReleasesEverything(t *testing.T) {
	s, out := testSettler(t, time.Minute)

	s.process(context.Background(), []request.Span{conditionalChild(100)})
	s.flush(context.Background())

	got := collect(t, out)
	require.Len(t, got, 1)
	assert.False(t, got[0].ParentSpanID.IsValid())
	assert.Zero(t, s.order.Len())
}

func TestSettleHeldOverflowSettlesOldest(t *testing.T) {
	s, out := testSettler(t, time.Minute)

	for i := 0; i < maxHeldSpans+10; i++ {
		child := conditionalChild(int64(100 + i))
		child.SpanID[7] = byte(i)
		child.ParentSpanID[7] = byte(i % 251)
		s.process(context.Background(), []request.Span{child})
	}

	got := collect(t, out)
	assert.Len(t, got, 10, "overflow must settle the oldest, not grow unbounded")
	assert.LessOrEqual(t, s.order.Len(), maxHeldSpans)
}
