// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package msg

import (
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/testutil"
)

const timeout = 5 * time.Second

func TestNoSubscribers(t *testing.T) {
	// test that sender is not blocked if there aren't subscribers
	q := NewQueue[int](ChannelBufferLen(0))
	sent := make(chan int)
	go func() {
		q.Send(1)
		close(sent)
	}()
	testutil.ReadChannel(t, sent, timeout)
	testutil.ChannelEmpty(t, sent, 5*time.Millisecond)
}

func TestMultipleSubscribers(t *testing.T) {
	q := NewQueue[int]()
	ch1 := q.Subscribe()
	ch2 := q.Subscribe()
	go q.Send(123)

	assert.Equal(t, 123, testutil.ReadChannel(t, ch1, timeout))
	assert.Equal(t, 123, testutil.ReadChannel(t, ch2, timeout))
	testutil.ChannelEmpty(t, ch1, 5*time.Millisecond)
	testutil.ChannelEmpty(t, ch2, 5*time.Millisecond)
}

func TestBypass(t *testing.T) {
	q1 := NewQueue[int]()
	q2 := NewQueue[int]()
	ch2 := q2.Subscribe()
	q1.Bypass(q2)
	go q1.Send(123)
	assert.Equal(t, 123, testutil.ReadChannel(t, ch2, timeout))
	testutil.ChannelEmpty(t, ch2, 5*time.Millisecond)
}

func TestBypass_SubscribeAfterBypass(t *testing.T) {
	q1 := NewQueue[int]()
	q2 := NewQueue[int]()
	q1.Bypass(q2)
	ch2 := q2.Subscribe()
	go q1.Send(123)
	assert.Equal(t, 123, testutil.ReadChannel(t, ch2, timeout))
	testutil.ChannelEmpty(t, ch2, 5*time.Millisecond)
}

func TestChainedBypass(t *testing.T) {
	q1 := NewQueue[int]()
	q2 := NewQueue[int]()
	q3 := NewQueue[int]()
	q1.Bypass(q2)
	q2.Bypass(q3)
	ch3 := q3.Subscribe()
	go q1.Send(123)

	assert.Equal(t, 123, testutil.ReadChannel(t, ch3, timeout))
	testutil.ChannelEmpty(t, ch3, 5*time.Millisecond)
}

func TestOneToManyBypass(t *testing.T) {
	src := NewQueue[int]()
	dst := NewQueue[int]()
	src.Bypass(dst)
	ch1 := dst.Subscribe()
	ch2 := dst.Subscribe()
	ch3 := dst.Subscribe()
	go src.Send(123)
	assert.Equal(t, 123, testutil.ReadChannel(t, ch1, timeout))
	assert.Equal(t, 123, testutil.ReadChannel(t, ch2, timeout))
	assert.Equal(t, 123, testutil.ReadChannel(t, ch3, timeout))
	testutil.ChannelEmpty(t, ch1, 5*time.Millisecond)
	testutil.ChannelEmpty(t, ch2, 5*time.Millisecond)
	testutil.ChannelEmpty(t, ch3, 5*time.Millisecond)
}

func TestErrors(t *testing.T) {
	t.Run("can't bypass to itself", func(t *testing.T) {
		q := NewQueue[int]()
		assert.Panics(t, func() {
			q.Bypass(q)
		})
	})
	t.Run("can't bypass to another queue that is already bypassing", func(t *testing.T) {
		q1 := NewQueue[int]()
		q2 := NewQueue[int]()
		q3 := NewQueue[int]()
		q1.Bypass(q2)
		assert.Panics(t, func() {
			q1.Bypass(q3)
		})
	})
}

func TestClose(t *testing.T) {
	q := NewQueue[int](ChannelBufferLen(10))
	ch1, ch2 := q.Subscribe(), q.Subscribe()
	// channels are not closed
	select {
	case <-ch1:
		t.Fatal("channel 1 should not be closed")
	case <-ch2:
		t.Fatal("channel 2 should not be closed")
	default:
		// ok!!
	}
	q.Send(123)
	q.Send(456)
	q.Close()
	// once closed, channels should be closed but might still have contents
	assert.Equal(t, 123, testutil.ReadChannel(t, ch1, timeout))
	assert.Equal(t, 123, testutil.ReadChannel(t, ch2, timeout))
	assert.Equal(t, 456, testutil.ReadChannel(t, ch1, timeout))
	assert.Equal(t, 456, testutil.ReadChannel(t, ch2, timeout))

	testutil.ChannelEmpty(t, ch1, time.Second)
	testutil.ChannelEmpty(t, ch1, time.Second)
}

func TestClose_Bypassed(t *testing.T) {
	q := NewQueue[int](ChannelBufferLen(10))
	q2 := NewQueue[int](ChannelBufferLen(10))
	q.Bypass(q2)
	ch1, ch2 := q2.Subscribe(), q2.Subscribe()
	// channels are not closed
	select {
	case <-ch1:
		t.Fatal("channel 1 should not be closed")
	case <-ch2:
		t.Fatal("channel 2 should not be closed")
	default:
		// ok!!
	}
	q.Send(123)
	q.Send(456)
	q.Close()
	// once closed, channels should be closed but might still have contents
	assert.Equal(t, 123, testutil.ReadChannel(t, ch1, timeout))
	assert.Equal(t, 123, testutil.ReadChannel(t, ch2, timeout))
	assert.Equal(t, 456, testutil.ReadChannel(t, ch1, timeout))
	assert.Equal(t, 456, testutil.ReadChannel(t, ch2, timeout))

	testutil.ChannelEmpty(t, ch1, time.Second)
	testutil.ChannelEmpty(t, ch1, time.Second)
}

func TestClose_Errors(t *testing.T) {
	q := NewQueue[int]()
	q.Close()
	t.Run("can't send on closed queue", func(t *testing.T) {
		assert.Panics(t, func() {
			q.Send(123)
		})
	})
	t.Run("can't subscribe on closed queue", func(t *testing.T) {
		assert.Panics(t, func() {
			q.Subscribe()
		})
	})
	t.Run("can't bypass on closed queue", func(t *testing.T) {
		assert.Panics(t, func() {
			q2 := NewQueue[int]()
			q.Bypass(q2)
		})
	})
	t.Run("it's ok re-closing a closed queue", func(t *testing.T) {
		assert.NotPanics(t, q.Close)
	})
}

func TestMarkCloseable(t *testing.T) {
	q := NewQueue[int](ChannelBufferLen(100), ClosingAttempts(3))
	q.Send(1)
	q.MarkCloseable()
	assert.NotPanics(t, func() {
		q.Send(2)
	})
	q.MarkCloseable()
	assert.NotPanics(t, func() {
		q.Send(3)
	})
	q.MarkCloseable()
	t.Run("can't send on closed queue", func(t *testing.T) {
		assert.Panics(t, func() {
			q.Send(4)
		})
	})
}

func TestBypassAndSubscribe(t *testing.T) {
	src := NewQueue[int](ChannelBufferLen(10))
	mid := NewQueue[int](ChannelBufferLen(10))
	dst := NewQueue[int](ChannelBufferLen(10))
	src.Bypass(mid)
	mid.Bypass(dst)
	midCh := mid.Subscribe()
	dstCh := dst.Subscribe()

	src.Send(123)
	assert.Equal(t, 123, testutil.ReadChannel(t, midCh, timeout))
	assert.Equal(t, 123, testutil.ReadChannel(t, dstCh, timeout))
	testutil.ChannelEmpty(t, midCh, 5*time.Millisecond)
	testutil.ChannelEmpty(t, dstCh, 5*time.Millisecond)
}

func TestSubscribeAndBypass(t *testing.T) {
	src := NewQueue[int](ChannelBufferLen(10))
	mid := NewQueue[int](ChannelBufferLen(10))
	dst := NewQueue[int](ChannelBufferLen(10))
	midCh := mid.Subscribe()
	dstCh := dst.Subscribe()

	src.Bypass(mid)
	mid.Bypass(dst)

	src.Send(123)
	assert.Equal(t, 123, testutil.ReadChannel(t, midCh, timeout))
	assert.Equal(t, 123, testutil.ReadChannel(t, dstCh, timeout))
	testutil.ChannelEmpty(t, midCh, 5*time.Millisecond)
	testutil.ChannelEmpty(t, dstCh, 5*time.Millisecond)
}

func TestLongChains(t *testing.T) {
	const queueLen = 10
	queues := make([]*Queue[int], queueLen)
	for i := range queues {
		queues[i] = NewQueue[int](ChannelBufferLen(10))
	}
	chans := make([]<-chan int, queueLen)
	bypassAndSubscribe := func(i int) {
		queues[i].Bypass(queues[i+1])
		chans[i] = queues[i].Subscribe()
	}
	subscribeAndBypass := func(i int) {
		chans[i] = queues[i].Subscribe()
		queues[i].Bypass(queues[i+1])
	}
	bypassAndSubscribe(4)
	subscribeAndBypass(5)
	bypassAndSubscribe(6)
	subscribeAndBypass(2)
	bypassAndSubscribe(0)
	subscribeAndBypass(7)
	bypassAndSubscribe(8)
	subscribeAndBypass(1)
	bypassAndSubscribe(3)
	chans[queueLen-1] = queues[queueLen-1].Subscribe()
	queues[0].Send(123)
	for i := range queueLen {
		assert.Equal(t, 123, testutil.ReadChannel(t, chans[i], timeout))
	}
}

func TestPipelineFork(t *testing.T) {
	// imitates the instrumenter.go metrics/traces pipeline forks, which in the
	// past has been a source of deadlocks
	t.Run("traces and metrics active", func(t *testing.T) {
		decoratedSpans := NewQueue[int](ChannelBufferLen(10))
		tracesExporter := decoratedSpans.Subscribe()
		tracesPrinter := decoratedSpans.Subscribe()
		ipDropper := NewQueue[int](ChannelBufferLen(10))
		decoratedSpans.Bypass(ipDropper)
		otelExporter := ipDropper.Subscribe()
		promExporter := ipDropper.Subscribe()
		decoratedSpans.Send(123)
		assert.Equal(t, 123, testutil.ReadChannel(t, tracesExporter, timeout))
		assert.Equal(t, 123, testutil.ReadChannel(t, tracesPrinter, timeout))
		assert.Equal(t, 123, testutil.ReadChannel(t, otelExporter, timeout))
		assert.Equal(t, 123, testutil.ReadChannel(t, promExporter, timeout))
	})
	t.Run("only traces active", func(t *testing.T) {
		decoratedSpans := NewQueue[int](ChannelBufferLen(10))
		tracesExporter := decoratedSpans.Subscribe()
		tracesPrinter := decoratedSpans.Subscribe()
		ipDropper := NewQueue[int](ChannelBufferLen(10))
		decoratedSpans.Bypass(ipDropper)
		decoratedSpans.Send(123)
		assert.Equal(t, 123, testutil.ReadChannel(t, tracesExporter, timeout))
		assert.Equal(t, 123, testutil.ReadChannel(t, tracesPrinter, timeout))
	})
	t.Run("only metrics active", func(t *testing.T) {
		decoratedSpans := NewQueue[int](ChannelBufferLen(10))
		ipDropper := NewQueue[int](ChannelBufferLen(10))
		decoratedSpans.Bypass(ipDropper)
		otelExporter := ipDropper.Subscribe()
		promExporter := ipDropper.Subscribe()
		decoratedSpans.Send(123)
		assert.Equal(t, 123, testutil.ReadChannel(t, otelExporter, timeout))
		assert.Equal(t, 123, testutil.ReadChannel(t, promExporter, timeout))
	})
}

func TestRandomConcurrentBypassSubscribeLongChains(t *testing.T) {
	// chain of 100 queues where queue[i] is connected to queue[i+1]
	const queueLen = 100
	queues := make([]*Queue[int], queueLen)
	for i := range queues {
		queues[i] = NewQueue[int](ChannelBufferLen(10))
	}
	// randomly connect & subscribe queues
	rndConnectionOrder := make([]int, queueLen)
	for i := range rndConnectionOrder {
		rndConnectionOrder[i] = i
	}
	// Fisher-Yates shuffle
	for i := len(rndConnectionOrder) - 1; i > 0; i-- {
		j := rand.IntN(i + 1)
		rndConnectionOrder[i], rndConnectionOrder[j] = rndConnectionOrder[j], rndConnectionOrder[i]
	}
	outChans := make([]<-chan int, queueLen)
	// connect+subscribe queues in random order, and concurrently in different goroutines
	wg := sync.WaitGroup{}
	wg.Add(queueLen)
	for _, i := range rndConnectionOrder {
		go func() {
			defer wg.Done()
			if i < queueLen-1 {
				if i%2 == 0 {
					outChans[i] = queues[i].Subscribe()
					queues[i].Bypass(queues[i+1])
				} else {
					queues[i].Bypass(queues[i+1])
					outChans[i] = queues[i].Subscribe()
				}
			} else {
				outChans[i] = queues[i].Subscribe()
			}
		}()
	}
	wg.Wait()
	queues[0].Send(123)
	for i := range queueLen {
		assert.Equal(t, 123, testutil.ReadChannel(t, outChans[i], timeout))
	}
	if t.Failed() {
		fmt.Println("failed queues:")
	}
}

func TestDeathPathNotBlocking(t *testing.T) {
	q1 := NewQueue[int](ChannelBufferLen(3), Name("q1"))
	q2 := NewQueue[int](ChannelBufferLen(3), Name("q2"))
	q2a1 := NewQueue[int](ChannelBufferLen(3), Name("q2a1"))
	q2a2 := NewQueue[int](ChannelBufferLen(3), Name("q2a2"))

	// q1 -> q2 -> q2a1 -> q2a2 // a dead path must not block if nobody subscribes to it
	//         \-> ch           // path with actual subscribers
	q1.Bypass(q2)
	ch := q2.Subscribe(SubscriberName("test"))
	q2a1.Bypass(q2a2)
	q2.Bypass(q2a1)

	go func() {
		q1.Send(1)
		q1.Send(2)
		q1.Send(3)
		q1.Send(4)
	}()

	require.Equal(t, 1, testutil.ReadChannel(t, ch, timeout))
	require.Equal(t, 2, testutil.ReadChannel(t, ch, timeout))
	require.Equal(t, 3, testutil.ReadChannel(t, ch, timeout))
	require.Equal(t, 4, testutil.ReadChannel(t, ch, timeout))
	testutil.ChannelEmpty(t, ch, 5*time.Millisecond)
}

func TestBlockingPanics(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		assert.Panics(t, func() {
			// tests the deadlock verifier. It should panic if a message is sent
			// and nobody reads it

			q1 := NewQueue[int](ChannelBufferLen(1), Name("q1"), PanicOnSendTimeout())
			q2 := NewQueue[int](ChannelBufferLen(1), Name("q2"), PanicOnSendTimeout())
			q2a1 := NewQueue[int](ChannelBufferLen(1), Name("q2a1"), PanicOnSendTimeout())
			q2a2 := NewQueue[int](ChannelBufferLen(1), Name("q2a2"), PanicOnSendTimeout())

			// q1 -> q2 -> q2a1 -> q2a2 // a dead path must not block if nobody subscribes to it
			//         \-> ch           // path with actual subscribers
			q1.Bypass(q2)
			_ = q2.Subscribe(SubscriberName("test"))
			q2.Bypass(q2a1)
			q2a1.Bypass(q2a2)

			q1.Send(1)
			q1.Send(2)

			time.Sleep(2 * defaultSendTimeout)
		}, "a deadlock should have been detected")
	})
}
