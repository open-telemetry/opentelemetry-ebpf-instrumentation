// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const testShutdownTimeout = 8 * time.Second

var drainDeadline = shutdownDrainTimeout(testShutdownTimeout) + time.Second

type pendingRingBufReader struct {
	mu        sync.Mutex
	pending   int
	sample    []byte
	flushed   bool
	flushes   chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	isClosed  atomic.Bool
}

func newPendingRingBufReader(pending int) *pendingRingBufReader {
	return &pendingRingBufReader{
		pending: pending,
		sample:  []byte{1},
		flushes: make(chan struct{}, 1),
		closed:  make(chan struct{}),
	}
}

func (r *pendingRingBufReader) Close() error {
	r.closeOnce.Do(func() {
		r.isClosed.Store(true)
		close(r.closed)
	})
	return nil
}

func (r *pendingRingBufReader) Read() (ringbuf.Record, error) {
	record := ringbuf.Record{}
	err := r.ReadInto(&record)
	return record, err
}

func (r *pendingRingBufReader) ReadInto(record *ringbuf.Record) error {
	r.mu.Lock()
	flushed := r.flushed
	r.mu.Unlock()
	if !flushed {
		select {
		case <-r.flushes:
			r.mu.Lock()
			r.flushed = true
			r.mu.Unlock()
		case <-r.closed:
			return ringbuf.ErrClosed
		}
	}
	if r.isClosed.Load() {
		return ringbuf.ErrClosed
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == 0 {
		r.flushed = false
		return ringbuf.ErrFlushed
	}
	r.pending--
	record.RawSample = r.sample
	return nil
}

func (r *pendingRingBufReader) AvailableBytes() int { return 0 }

func (r *pendingRingBufReader) Flush() error {
	select {
	case r.flushes <- struct{}{}:
	default:
	}
	return nil
}

func replacePendingRingBuf(pending int) *pendingRingBufReader {
	rb := newPendingRingBufReader(pending)
	readerFactory = func(_ *ebpf.Map) (ringBufReader, error) {
		return rb, nil
	}
	return rb
}

func forwardOneRecordType(cfg *config.EBPFTracer, shutdownTimeout time.Duration, closers ...io.Closer) func(context.Context, *msg.Queue[[]int]) {
	return ForwardRingbufWithShutdownTimeout(cfg, shutdownTimeout, nil,
		func(_ *ringbuf.Record) (int, bool, error) { return 1, false, nil },
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		closers...,
	)
}

func runUntilDone(fn func()) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	return done
}

func TestForwardRingbuf_DrainsPendingRecordsOnCancel(t *testing.T) {
	reader := replacePendingRingBuf(5)
	out := msg.NewQueue[[]int](msg.ChannelBufferLen(10))
	sub := out.Subscribe()
	closable := closableObject{}

	ctx, cancel := context.WithCancel(t.Context())
	done := runUntilDone(func() {
		ForwardRingbuf(&config.EBPFTracer{BatchLength: 10}, nil,
			func(_ *ringbuf.Record) (int, bool, error) { return 1, false, nil },
			nil,
			slog.New(slog.NewTextHandler(io.Discard, nil)),
			nil,
			&closable,
		)(ctx, out)
	})

	cancel()

	batch := testutil.ReadChannel(t, sub, testTimeout)
	assert.Len(t, batch, 5, "the pending records are forwarded as a partial batch")

	select {
	case <-done:
	case <-time.After(drainDeadline):
		require.FailNow(t, "forwarder did not finish")
	}
	assert.True(t, reader.isClosed.Load())
	assert.True(t, closable.closed.Load())
}

func TestForwardRingbuf_DrainIsBoundedWhenDownstreamBlocks(t *testing.T) {
	for _, shutdownTimeout := range []time.Duration{testShutdownTimeout, time.Second} {
		t.Run(shutdownTimeout.String(), func(t *testing.T) {
			reader := replacePendingRingBuf(100)
			out := msg.NewQueue[[]int](msg.ChannelBufferLen(0))
			_ = out.Subscribe()

			ctx, cancel := context.WithCancel(t.Context())
			done := runUntilDone(func() {
				forwardOneRecordType(&config.EBPFTracer{BatchLength: 1}, shutdownTimeout)(ctx, out)
			})

			start := time.Now()
			cancel()

			select {
			case <-done:
			case <-time.After(shutdownTimeout / 2):
				require.FailNow(t, "forwarder did not finish within half of the shutdown timeout")
			}
			assert.GreaterOrEqual(t, time.Since(start), shutdownDrainTimeout(shutdownTimeout))
			assert.True(t, reader.isClosed.Load())
		})
	}
}

func TestSharedRingbuf_DrainsPendingRecordsAndClosesResourcesOnCancel(t *testing.T) {
	reader := replacePendingRingBuf(3)
	out := msg.NewQueue[[]int](msg.ChannelBufferLen(10))
	sub := out.Subscribe()
	closable := closableObject{}

	forward := SharedRingbuf(NewEBPFEventContext(), &config.EBPFTracer{BatchLength: 10}, nil,
		func(_ *ringbuf.Record) (int, bool, error) { return 1, false, nil },
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
	)

	ctx, cancel := context.WithCancel(t.Context())
	done := runUntilDone(func() {
		forward(ctx, []io.Closer{&closable}, out)
	})

	cancel()

	batch := testutil.ReadChannel(t, sub, testTimeout)
	assert.Len(t, batch, 3)

	select {
	case <-done:
	case <-time.After(drainDeadline):
		require.FailNow(t, "forwarder did not finish")
	}
	assert.True(t, reader.isClosed.Load())
	assert.True(t, closable.closed.Load())
}

func TestForwardRingbuf_ClosesTheReaderWhenTheDrainStalls(t *testing.T) {
	reader := replacePendingRingBuf(0)
	reader.flushes = nil

	ctx, cancel := context.WithCancel(t.Context())
	done := runUntilDone(func() {
		forwardOneRecordType(&config.EBPFTracer{BatchLength: 10}, testShutdownTimeout)(ctx, msg.NewQueue[[]int]())
	})

	cancel()

	select {
	case <-done:
	case <-time.After(drainDeadline):
		require.FailNow(t, "forwarder did not finish")
	}
	assert.True(t, reader.isClosed.Load())
}

func TestForwardRingbuf_DrainIsBoundedWhenTheParserBlocks(t *testing.T) {
	replacePendingRingBuf(3)
	unblock := make(chan struct{})
	defer close(unblock)
	parsing := make(chan struct{}, 3)

	forward := ForwardRingbufWithShutdownTimeout(&config.EBPFTracer{BatchLength: 10}, testShutdownTimeout, nil,
		func(_ *ringbuf.Record) (int, bool, error) {
			parsing <- struct{}{}
			<-unblock
			return 1, false, nil
		},
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
	)

	ctx, cancel := context.WithCancel(t.Context())
	done := runUntilDone(func() {
		forward(ctx, msg.NewQueue[[]int](msg.ChannelBufferLen(10)))
	})

	cancel()
	testutil.ReadChannel(t, parsing, testTimeout)

	select {
	case <-done:
	case <-time.After(drainDeadline):
		require.FailNow(t, "forwarder did not finish while the parser was blocked")
	}
}

func TestForwardRingbuf_ParserContextOutlivesTheSignal(t *testing.T) {
	replacePendingRingBuf(3)
	parseErrs := make(chan error, 3)

	forward := ForwardRingbufWithDrainContext(&config.EBPFTracer{BatchLength: 10}, testShutdownTimeout, nil,
		func(ctx context.Context, _ *ringbuf.Record) (int, bool, error) {
			parseErrs <- ctx.Err()
			return 1, false, nil
		},
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
	)

	ctx, cancel := context.WithCancel(t.Context())
	done := runUntilDone(func() {
		forward(ctx, msg.NewQueue[[]int](msg.ChannelBufferLen(10)))
	})

	cancel()
	for range 3 {
		require.NoError(t, testutil.ReadChannel(t, parseErrs, testTimeout),
			"records drained after the signal must be parsed with a live context")
	}

	select {
	case <-done:
	case <-time.After(drainDeadline):
		require.FailNow(t, "forwarder did not finish")
	}
}

type queueRuntimeMetricsSender struct {
	fakeRuntimeMetricsSender
	queue *msg.Queue[int]
}

func (s *queueRuntimeMetricsSender) SendGoRuntimeMetricRecord(ctx context.Context, _ *ringbuf.Record, _ ServiceFilter) error {
	s.queue.SendCtx(ctx, 1)
	return nil
}

func TestSharedRingbuf_DrainsRuntimeMetricRecordsIntoATemporarilyFullQueue(t *testing.T) {
	const pending = 3
	reader := replacePendingRingBuf(pending)
	reader.sample = []byte{EventTypeGoRuntimeMetric}

	runtimeMetrics := msg.NewQueue[int](msg.ChannelBufferLen(0))
	received := runtimeMetrics.Subscribe()
	eventContext := NewEBPFEventContext()
	eventContext.RuntimeMetrics = &queueRuntimeMetricsSender{queue: runtimeMetrics}

	forward := SharedRingbufWithDrainContext(eventContext, &config.EBPFTracer{BatchLength: 10}, testShutdownTimeout, nil,
		func(ctx context.Context, record *ringbuf.Record) (int, bool, error) {
			handled, err := HandleRuntimeMetricsRecord(ctx, eventContext, record, &IdentityPidsFilter{}, nil)
			return 0, handled, err
		},
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
	)

	ctx, cancel := context.WithCancel(t.Context())
	done := runUntilDone(func() {
		forward(ctx, nil, msg.NewQueue[[]int]())
	})

	cancel()
	time.Sleep(shutdownDrainTimeout(testShutdownTimeout) / 4)
	for range pending {
		testutil.ReadChannel(t, received, testTimeout)
	}

	select {
	case <-done:
	case <-time.After(drainDeadline):
		require.FailNow(t, "forwarder did not finish")
	}
}
