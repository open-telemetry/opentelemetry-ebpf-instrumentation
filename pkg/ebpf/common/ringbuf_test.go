// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const testTimeout = 5 * time.Second

func TestForwardRingbuf_CapacityFull(t *testing.T) {
	// GIVEN a ring buffer forwarder
	ringBuf := replaceTestRingBuf()
	metrics := &metricsReporter{}
	forwardedMessagesQueue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(100))
	forwardedMessages := forwardedMessagesQueue.Subscribe()
	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}
	fltr.AllowPID(1, 1, exec.New(exec.Init{Service: svc.Attrs{UID: svc.UID{Name: "myService"}}}), PIDTypeGo)
	cfg := &config.EBPFTracer{BatchLength: 10}
	go ForwardRingbuf(
		cfg,
		nil, // the source ring buffer can be null
		func(r *ringbuf.Record) (request.Span, bool, error) {
			s, ignore, err := ReadBPFTraceAsSpan(nil, cfg, r, &fltr)
			if !ignore && err == nil && !s.IsValid() {
				return s, true, nil
			}
			return s, ignore, err
		},
		fltr.Filter,
		slog.With("test", "TestForwardRingbuf_CapacityFull"),
		metrics,
	)(t.Context(), forwardedMessagesQueue)

	// WHEN it starts receiving trace events
	get := [7]byte{'G', 'E', 'T', 0, 0, 0, 0}
	for i := range 20 {
		t := HTTPRequestTrace{Type: 1, Method: get, ContentLength: int64(i)}
		t.Pid.HostPid = 1
		ringBuf.events <- t
	}

	// THEN the RingBuf reader forwards them in batches
	batch := testutil.ReadChannel(t, forwardedMessages, testTimeout)
	require.Len(t, batch, 10)
	for i := range batch {
		assert.Equal(t, request.Span{Type: 1, Method: "GET", ContentLength: int64(i), Service: svc.Attrs{UID: svc.UID{Name: "myService"}}, Pid: request.PidInfo{HostPID: 1}}, batch[i])
	}

	batch = testutil.ReadChannel(t, forwardedMessages, testTimeout)
	require.Len(t, batch, 10)
	for i := range batch {
		assert.Equal(t, request.Span{Type: 1, Method: "GET", ContentLength: int64(10 + i), Service: svc.Attrs{UID: svc.UID{Name: "myService"}}, Pid: request.PidInfo{HostPID: 1}}, batch[i])
	}
	// AND metrics are properly updated
	assert.Equal(t, 2, metrics.flushes)
	assert.Equal(t, 20, metrics.flushedLen)

	// AND does not forward any extra message if no more elements are in the ring buffer
	select {
	case ev := <-forwardedMessages:
		assert.Failf(t, "unexpected messages in the forwarding channel", "%+v", ev)
	default:
		// OK!
	}
}

func TestForwardRingbuf_Deadline(t *testing.T) {
	// GIVEN a ring buffer forwarder
	ringBuf := replaceTestRingBuf()

	metrics := &metricsReporter{}
	forwardedMessagesQueue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(100))
	forwardedMessages := forwardedMessagesQueue.Subscribe()
	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}
	fltr.AllowPID(1, 1, exec.New(exec.Init{Service: svc.Attrs{UID: svc.UID{Name: "myService"}}}), PIDTypeGo)
	cfg := &config.EBPFTracer{BatchLength: 10, BatchTimeout: 20 * time.Millisecond}
	go ForwardRingbuf(
		cfg,
		nil, // the source ring buffer can be null
		func(r *ringbuf.Record) (request.Span, bool, error) {
			s, ignore, err := ReadBPFTraceAsSpan(nil, cfg, r, &fltr)
			if !ignore && err == nil && !s.IsValid() {
				return s, true, nil
			}
			return s, ignore, err
		},
		fltr.Filter,
		slog.With("test", "TestForwardRingbuf_Deadline"),
		metrics,
	)(t.Context(), forwardedMessagesQueue)

	// WHEN it receives, after a timeout, less events than its internal buffer
	get := [7]byte{'G', 'E', 'T', 0, 0, 0, 0}
	for i := range 7 {
		t := HTTPRequestTrace{Type: 1, Method: get, ContentLength: int64(i)}
		t.Pid.HostPid = 1

		ringBuf.events <- t
	}

	// THEN the RingBuf reader forwards them in a smaller batch
	batch := testutil.ReadChannel(t, forwardedMessages, testTimeout)
	for len(batch) < 7 {
		batch = append(batch, testutil.ReadChannel(t, forwardedMessages, testTimeout)...)
	}
	require.Len(t, batch, 7)
	for i := range batch {
		assert.Equal(t, request.Span{Type: 1, Method: "GET", ContentLength: int64(i), Service: svc.Attrs{UID: svc.UID{Name: "myService"}}, Pid: request.PidInfo{HostPID: 1}}, batch[i])
	}

	// AND metrics are properly updated
	assert.Equal(t, 1, metrics.flushes)
	assert.Equal(t, 7, metrics.flushedLen)
}

func TestForwardRingbuf_Close(t *testing.T) {
	// GIVEN a ring buffer forwarder
	ringBuf := replaceTestRingBuf()

	metrics := &metricsReporter{}
	closable := closableObject{}
	cfg := &config.EBPFTracer{BatchLength: 10}
	go ForwardRingbuf(
		cfg,
		nil, // the source ring buffer can be null
		func(r *ringbuf.Record) (request.Span, bool, error) {
			s, ignore, err := ReadBPFTraceAsSpan(nil, cfg, r, &IdentityPidsFilter{})
			if !ignore && err == nil && !s.IsValid() {
				return s, true, nil
			}
			return s, ignore, err
		},
		nil,
		slog.With("test", "TestForwardRingbuf_Close"),
		metrics,
		&closable,
	)(t.Context(), msg.NewQueue[[]request.Span](msg.ChannelBufferLen(100)))

	assert.False(t, ringBuf.explicitClose.Load())
	assert.False(t, closable.closed.Load())

	// WHEN the ring buffer is closed
	close(ringBuf.closeCh)

	// THEN the ring buffer and the passed io.Closer elements have been explicitly closed
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.True(ct, ringBuf.explicitClose.Load())
	}, testTimeout, 100*time.Millisecond)
	// Wait a bit for the defer to close resources
	time.Sleep(time.Second)

	assert.True(t, closable.closed.Load())

	// AND metrics haven't been updated
	assert.Equal(t, 0, metrics.flushes)
	assert.Equal(t, 0, metrics.flushedLen)
}

func TestForwardRingbuf_NoEventLoss(t *testing.T) {
	const N = 10000
	for _, batchLen := range []int{1, 10, 100} {
		t.Run(fmt.Sprintf("batchLen=%d", batchLen), func(t *testing.T) {
			ringBuf := replaceTestRingBuf()
			cfg := &config.EBPFTracer{
				BatchLength:  batchLen,
				BatchTimeout: 10 * time.Millisecond,
			}
			out := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(N/batchLen + 10))
			sub := out.Subscribe()

			go ForwardRingbuf(
				cfg, nil,
				func(_ *ringbuf.Record) (request.Span, bool, error) {
					return request.Span{Type: 1}, false, nil
				},
				nil,
				slog.New(slog.NewTextHandler(io.Discard, nil)),
				&metricsReporter{},
			)(t.Context(), out)

			// Feed events from a separate goroutine so we consume concurrently.
			// Producing everything up front before consuming would let the output queue
			// fill up and deadlock the whole pipeline.
			go func() {
				for range N {
					ringBuf.events <- HTTPRequestTrace{Type: 1}
				}
			}()

			received := 0
			deadline := time.After(10 * time.Second)
			for received < N {
				select {
				case batch := <-sub:
					received += len(batch)
				case <-deadline:
					t.Fatalf("timeout: got %d/%d events", received, N)
				}
			}
			assert.Equal(t, N, received)
		})
	}
}

func TestRingbufLastReadAtRace(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	rbf := &ringBufForwarder[HTTPRequestTrace]{
		cfg:    &config.EBPFTracer{BatchLength: 1},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		parse: func(*ringbuf.Record) (HTTPRequestTrace, bool, error) {
			return HTTPRequestTrace{}, true, nil
		},
	}

	eventsReader := newFlushTrackingReader()
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		rbf.readAndForwardInner(ctx, eventsReader, msg.NewQueue[[]HTTPRequestTrace](msg.ChannelBufferLen(1)))
	}()

	deadline := time.Now().Add(flushInterval + 500*time.Millisecond)
	for time.Now().Before(deadline) {
		readCount := eventsReader.ReadCount()
		eventsReader.AllowRead()
		require.Eventually(t, func() bool {
			return eventsReader.ReadCount() > readCount
		}, time.Second, 10*time.Millisecond)
		assert.Zero(t, eventsReader.FlushCount())
	}

	require.Eventually(t, func() bool {
		return eventsReader.FlushCount() > 0
	}, 2*flushInterval+time.Second, 100*time.Millisecond)

	cancel()
	eventsReader.Close()
	<-readDone
}

func TestSharedRingbufWaitsForBlockedParserBeforeCallerTeardown(t *testing.T) {
	previousFactory := readerFactory
	eventsReader := newCancelableSingleRecordReader()
	readerFactory = func(_ *ebpf.Map) (ringBufReader, error) {
		return eventsReader, nil
	}
	t.Cleanup(func() {
		readerFactory = previousFactory
	})

	ctx, cancel := context.WithCancel(t.Context())
	parserStarted := make(chan struct{})
	releaseParser := make(chan struct{})
	parserExited := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		cancel()
		releaseOnce.Do(func() { close(releaseParser) })
	})

	eventContext := NewEBPFEventContext()
	forward := SharedRingbuf[int](
		eventContext,
		&config.EBPFTracer{BatchLength: 1, BatchTimeout: time.Millisecond},
		nil,
		func(*ringbuf.Record) (int, bool, error) {
			close(parserStarted)
			<-releaseParser
			close(parserExited)
			return 0, true, nil
		},
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
	)
	waitReached := make(chan struct{}, 1)
	forwarder := eventContext.SharedRingBuffer.(*ringBufForwarder[int])
	forwarder.beforeWorkerWait = func() {
		waitReached <- struct{}{}
	}

	var teardownBeforeParserExit atomic.Bool
	forwardReturned := make(chan struct{})
	go func() {
		forward(ctx, nil, msg.NewQueue[[]int](msg.ChannelBufferLen(1)))
		select {
		case <-parserExited:
		default:
			teardownBeforeParserExit.Store(true)
		}
		close(forwardReturned)
	}()

	testutil.ReadChannel(t, parserStarted, testTimeout)
	cancel()
	testutil.ReadChannel(t, eventsReader.closed, testTimeout)
	select {
	case <-waitReached:
	case <-forwardReturned:
		t.Fatal("shared ring buffer returned without joining its parser")
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for the parser join")
	}

	releaseOnce.Do(func() { close(releaseParser) })
	testutil.ReadChannel(t, parserExited, testTimeout)
	testutil.ReadChannel(t, forwardReturned, testTimeout)
	assert.False(t, teardownBeforeParserExit.Load(), "caller teardown raced the parser")
}

func TestForwardRingbufWaitsForCancellationListenerClose(t *testing.T) {
	previousFactory := readerFactory
	eventsReader := newBlockingFirstCloseReader()
	readerFactory = func(_ *ebpf.Map) (ringBufReader, error) {
		return eventsReader, nil
	}
	t.Cleanup(func() {
		readerFactory = previousFactory
	})

	ctx, cancel := context.WithCancel(t.Context())
	releaseClose := make(chan struct{})
	waitReached := make(chan int, 2)
	var waitCount atomic.Int32
	var releaseOnce sync.Once
	eventsReader.releaseClose = releaseClose
	t.Cleanup(func() {
		cancel()
		releaseOnce.Do(func() { close(releaseClose) })
	})

	rbf := ringBufForwarder[int]{
		cfg:    &config.EBPFTracer{BatchLength: 1},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		parse:  func(*ringbuf.Record) (int, bool, error) { return 0, true, nil },
		beforeWorkerWait: func() {
			waitReached <- int(waitCount.Add(1))
		},
	}
	forwardReturned := make(chan struct{})
	go func() {
		rbf.readAndForward(ctx, msg.NewQueue[[]int](msg.ChannelBufferLen(1)))
		close(forwardReturned)
	}()

	cancel()
	testutil.ReadChannel(t, eventsReader.closeStarted, testTimeout)
	testutil.ReadChannel(t, eventsReader.readUnblocked, testTimeout)
	for expectedWait := 1; expectedWait <= 2; expectedWait++ {
		select {
		case actualWait := <-waitReached:
			require.Equal(t, expectedWait, actualWait)
		case <-forwardReturned:
			t.Fatalf("ring buffer returned before worker wait %d", expectedWait)
		case <-time.After(testTimeout):
			t.Fatalf("timed out waiting for worker wait %d", expectedWait)
		}
	}

	releaseOnce.Do(func() { close(releaseClose) })
	testutil.ReadChannel(t, forwardReturned, testTimeout)
	assert.GreaterOrEqual(t, eventsReader.closeCalls.Load(), int32(2))
}

func TestCancelAndWaitRingbufWorkersJoinsSynchronously(t *testing.T) {
	calls := make([]string, 0, 3)

	cancelAndWaitRingbufWorkers(
		func() {
			calls = append(calls, "cancel")
		},
		func() {
			require.Equal(t, []string{"cancel"}, calls)
			calls = append(calls, "before wait")
		},
		func() {
			require.Equal(t, []string{"cancel", "before wait"}, calls)
			calls = append(calls, "wait")
		},
	)

	require.Equal(t, []string{"cancel", "before wait", "wait"}, calls)
}

// replaces the original ring buffer factory by a fake ring buffer creator and returns it
func replaceTestRingBuf() *fakeRingBufReader {
	rb := fakeRingBufReader{events: make(chan HTTPRequestTrace, 100), closeCh: make(chan struct{})}
	readerFactory = func(_ *ebpf.Map) (ringBufReader, error) {
		return &rb, nil
	}
	return &rb
}

type fakeRingBufReader struct {
	events        chan HTTPRequestTrace
	closeCh       chan struct{}
	explicitClose atomic.Bool
}

func (f *fakeRingBufReader) Close() error {
	f.explicitClose.Store(true)
	// we don't close the channel, as we want to only test
	// that the ringbuf reader Close is invoked.
	return nil
}

func (f *fakeRingBufReader) Read() (ringbuf.Record, error) {
	record := ringbuf.Record{}

	err := f.ReadInto(&record)

	return record, err
}

func (f *fakeRingBufReader) ReadInto(record *ringbuf.Record) error {
	select {
	case traceEvent := <-f.events:
		binaryRecord := bytes.Buffer{}
		if err := binary.Write(&binaryRecord, binary.LittleEndian, traceEvent); err != nil {
			return err
		}
		record.RawSample = binaryRecord.Bytes()
		return nil
	case <-f.closeCh:
		return ringbuf.ErrClosed
	}
}

func (f *fakeRingBufReader) AvailableBytes() int { return 0 }

func (f *fakeRingBufReader) Flush() error { return nil }

type flushTrackingReader struct {
	readTokens chan struct{}
	closed     chan struct{}
	readCount  atomic.Int32
	// flushCount lets the test observe when the background flusher decides
	// reads went idle.
	flushCount atomic.Int32
}

type cancelableSingleRecordReader struct {
	closed    chan struct{}
	closeOnce sync.Once
	delivered atomic.Bool
}

func newCancelableSingleRecordReader() *cancelableSingleRecordReader {
	return &cancelableSingleRecordReader{closed: make(chan struct{})}
}

func (f *cancelableSingleRecordReader) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })
	return nil
}

func (f *cancelableSingleRecordReader) Read() (ringbuf.Record, error) {
	record := ringbuf.Record{}
	err := f.ReadInto(&record)
	return record, err
}

func (f *cancelableSingleRecordReader) ReadInto(record *ringbuf.Record) error {
	if f.delivered.CompareAndSwap(false, true) {
		record.RawSample = []byte{1}
		return nil
	}
	<-f.closed
	return ringbuf.ErrClosed
}

func (*cancelableSingleRecordReader) AvailableBytes() int { return 0 }

func (*cancelableSingleRecordReader) Flush() error { return nil }

type blockingFirstCloseReader struct {
	closeStarted  chan struct{}
	readUnblocked chan struct{}
	releaseClose  chan struct{}
	closeCalls    atomic.Int32
}

func newBlockingFirstCloseReader() *blockingFirstCloseReader {
	return &blockingFirstCloseReader{
		closeStarted:  make(chan struct{}),
		readUnblocked: make(chan struct{}),
	}
}

func (f *blockingFirstCloseReader) Close() error {
	if f.closeCalls.Add(1) == 1 {
		close(f.closeStarted)
		close(f.readUnblocked)
		<-f.releaseClose
	}
	return nil
}

func (*blockingFirstCloseReader) Read() (ringbuf.Record, error) {
	return ringbuf.Record{}, ringbuf.ErrClosed
}

func (f *blockingFirstCloseReader) ReadInto(*ringbuf.Record) error {
	<-f.readUnblocked
	return ringbuf.ErrClosed
}

func (*blockingFirstCloseReader) AvailableBytes() int { return 0 }

func (*blockingFirstCloseReader) Flush() error { return nil }

func newFlushTrackingReader() *flushTrackingReader {
	return &flushTrackingReader{
		readTokens: make(chan struct{}, 1),
		closed:     make(chan struct{}),
	}
}

func (f *flushTrackingReader) AllowRead() {
	select {
	case f.readTokens <- struct{}{}:
	default:
	}
}

func (f *flushTrackingReader) FlushCount() int {
	return int(f.flushCount.Load())
}

func (f *flushTrackingReader) ReadCount() int {
	return int(f.readCount.Load())
}

func (f *flushTrackingReader) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

func (f *flushTrackingReader) Read() (ringbuf.Record, error) {
	record := ringbuf.Record{}

	err := f.ReadInto(&record)

	return record, err
}

func (f *flushTrackingReader) ReadInto(record *ringbuf.Record) error {
	select {
	case <-f.readTokens:
		// Returning an empty sample is enough to exercise the read path and
		// update lastReadAt.
		record.RawSample = nil
		f.readCount.Add(1)
		return nil
	case <-f.closed:
		return ringbuf.ErrClosed
	}
}

func (f *flushTrackingReader) AvailableBytes() int { return 1 }

func (f *flushTrackingReader) Flush() error {
	f.flushCount.Add(1)
	return nil
}

type closableObject struct {
	closed atomic.Bool
}

func (c *closableObject) Close() error {
	c.closed.Store(true)
	return nil
}

type metricsReporter struct {
	imetrics.NoopReporter
	flushes    int
	flushedLen int
}

func (m *metricsReporter) TracerFlush(length int) {
	m.flushes++
	m.flushedLen += length
}

type TestPidsFilter struct {
	services map[app.PID]svc.Attrs
}

func (pf *TestPidsFilter) AllowPID(p app.PID, _ uint32, fi *exec.FileInfo, _ PIDType) {
	pf.services[p] = fi.ServiceAttrs()
}

func (pf *TestPidsFilter) BlockPID(p app.PID, _ uint32) {
	delete(pf.services, p)
}

func (pf *TestPidsFilter) ValidPID(_ app.PID, _ uint32, _ PIDType) bool {
	return true
}

func (pf *TestPidsFilter) CurrentPIDs(_ PIDType) map[uint32]map[app.PID]svc.Attrs {
	return nil
}

func (pf *TestPidsFilter) Filter(inputSpans []request.Span) []request.Span {
	for i := range inputSpans {
		s := &inputSpans[i]
		s.Service = pf.services[s.Pid.HostPID]
	}
	return inputSpans
}
