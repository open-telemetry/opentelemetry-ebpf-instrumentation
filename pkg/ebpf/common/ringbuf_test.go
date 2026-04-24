// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
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
	fltr.AllowPID(1, 1, &svc.Attrs{UID: svc.UID{Name: "myService"}}, PIDTypeGo)
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
	fltr.AllowPID(1, 1, &svc.Attrs{UID: svc.UID{Name: "myService"}}, PIDTypeGo)
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

func (pf *TestPidsFilter) AllowPID(p app.PID, _ uint32, s *svc.Attrs, _ PIDType) {
	pf.services[p] = *s
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
