// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package msg

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/obi"
	msg2 "go.opentelemetry.io/obi/pkg/pipe/msg"
)

const timeout = 5 * time.Second

func TestBasicOptions(t *testing.T) {
	logOutput := threadSafeBuffer{}

	slog.SetDefault(slog.New(slog.NewTextHandler(&logOutput, nil)))

	queue := QueueFromConfig[int](&obi.Config{
		ChannelBufferLen:   1,
		ChannelSendTimeout: 5 * time.Millisecond,
	}, imetrics.NoopReporter{}, "basicQueue")
	out := queue.Subscribe(msg2.SubscriberName("test-out"))

	ctx, c := context.WithTimeout(t.Context(), timeout)
	defer c()
	go func() {
		// will be immediately sent due to buffer = 1
		queue.SendCtx(ctx, 123)
		// won't be immediately sent due to timeout on buffer
		go queue.SendCtx(ctx, 456)
	}()

	// wait for the blocked log to be written
	var amsg atomic.Value
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		str, err := logOutput.ReadString('\n')
		require.NoError(ct, err)
		amsg.Store(str)
	}, timeout, 100*time.Millisecond)
	require.NotNil(t, amsg.Load())
	msg := amsg.Load().(string)
	assert.Contains(t, msg, "blocked")
	assert.Contains(t, msg, "timeout=5ms")
	assert.Contains(t, msg, "queueName=basicQueue")
	assert.Contains(t, msg, "queueLen=1")
	assert.Contains(t, msg, "queueCap=1")
	assert.Contains(t, msg, "subscriber=test-out")

	// the messages are eventually delivered
	assert.Equal(t, 123, testutil.ReadChannel(t, out, timeout))
	assert.Equal(t, 456, testutil.ReadChannel(t, out, timeout))
}

func TestBasicOptions_PanicOnBlock(t *testing.T) {
	logOutput := threadSafeBuffer{}
	slog.SetDefault(slog.New(slog.NewTextHandler(&logOutput, nil)))

	queue := QueueFromConfig[int](&obi.Config{
		ChannelBufferLen:        1,
		ChannelSendTimeout:      5 * time.Millisecond,
		ChannelSendTimeoutPanic: true,
	}, imetrics.NoopReporter{}, "basicQueue")
	out := queue.Subscribe(msg2.SubscriberName("test-out"))

	ctx, c := context.WithTimeout(t.Context(), timeout)
	defer c()
	// will be immediately sent due to buffer = 1
	sent := make(chan struct{})
	go func() {
		queue.SendCtx(ctx, 123)
		close(sent)
	}()
	testutil.ReadChannel(t, sent, timeout)
	// won't be immediately sent due to timeout on buffer
	assert.Panics(t, func() {
		queue.SendCtx(ctx, 456)
	}, "expected panic due to timeout")

	// the first message was delivered
	assert.Equal(t, 123, testutil.ReadChannel(t, out, timeout))
	// but the second message was never delivered
	testutil.ChannelEmpty(t, out, 10*time.Millisecond)
}

// bufferUtilizationRecorder captures the queue buffer utilization samples the
// factory is expected to wire into every queue it builds.
type bufferUtilizationRecorder struct {
	imetrics.NoopReporter

	mt      sync.Mutex
	samples map[string]float64
}

func (r *bufferUtilizationRecorder) QueueBufferUtilization(subscriber string, ratio float64) {
	r.mt.Lock()
	defer r.mt.Unlock()
	if r.samples == nil {
		r.samples = map[string]float64{}
	}
	r.samples[subscriber] = ratio
}

func (r *bufferUtilizationRecorder) sample(subscriber string) (float64, bool) {
	r.mt.Lock()
	defer r.mt.Unlock()
	ratio, ok := r.samples[subscriber]
	return ratio, ok
}

// The queue buffer utilization gauge defaults to a no-op, so it only reports
// when the factory passes the reporter down to msg.InternalMetrics. Without
// that wiring obi.queue.capacity.ratio is declared but never emitted.
func TestQueueFromConfig_ReportsBufferUtilization(t *testing.T) {
	recorder := &bufferUtilizationRecorder{}

	queue := QueueFromConfig[int](&obi.Config{
		ChannelBufferLen:   2,
		ChannelSendTimeout: time.Second,
	}, recorder, "utilizationQueue")
	out := queue.Subscribe(msg2.SubscriberName("test-subscriber"))

	ctx, c := context.WithTimeout(t.Context(), timeout)
	defer c()
	// the gauge is sampled before each send, so the second send observes the
	// message left in the buffer by the first one: 1 unread message out of 2
	queue.SendCtx(ctx, 123)
	queue.SendCtx(ctx, 456)

	ratio, ok := recorder.sample("test-subscriber")
	require.True(t, ok, "no utilization reported for the subscriber")
	assert.InDelta(t, 0.5, ratio, 0.0001)

	assert.Equal(t, 123, testutil.ReadChannel(t, out, timeout))
	assert.Equal(t, 456, testutil.ReadChannel(t, out, timeout))
}

// A nil reporter must leave the default no-op gauge in place instead of binding a
// method on a nil interface: several in-repo callers build a global.ContextInfo
// without a Metrics reporter, so sending must not panic.
func TestQueueFromConfig_NilReporter(t *testing.T) {
	queue := QueueFromConfig[int](&obi.Config{
		ChannelBufferLen:   1,
		ChannelSendTimeout: time.Second,
	}, nil, "nilReporterQueue")
	out := queue.Subscribe(msg2.SubscriberName("test-out"))

	ctx, c := context.WithTimeout(t.Context(), timeout)
	defer c()
	queue.SendCtx(ctx, 123)

	assert.Equal(t, 123, testutil.ReadChannel(t, out, timeout))
}

// avoids some race conditions between the queue and the eventually clauses
type threadSafeBuffer struct {
	mt     sync.Mutex
	buffer bytes.Buffer
}

func (t *threadSafeBuffer) Write(p []byte) (n int, err error) {
	t.mt.Lock()
	defer t.mt.Unlock()
	return t.buffer.Write(p)
}

func (t *threadSafeBuffer) ReadString(delim byte) (string, error) {
	t.mt.Lock()
	defer t.mt.Unlock()
	return t.buffer.ReadString(delim)
}
