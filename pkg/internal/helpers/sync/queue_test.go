// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sync

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/testutil"
)

const timeout = 5 * time.Second

func TestQueueReleasesDequeuedValues(t *testing.T) {
	const payloadSize = 1024
	q := NewQueue[*[payloadSize]byte]()
	released := make(chan struct{}, 1)
	func() {
		value := new([payloadSize]byte)
		runtime.AddCleanup(value, func(done chan struct{}) { done <- struct{}{} }, released)
		q.Enqueue(value)
	}()
	q.Enqueue(new([payloadSize]byte))

	_, err := q.DequeueContext(t.Context())
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		runtime.GC()
		select {
		case <-released:
			return true
		default:
			return false
		}
	}, timeout, 10*time.Millisecond, "dequeued value is still reachable from a non-empty queue")
	runtime.KeepAlive(q)
}

func TestQueueDequeueBlockingIfEmpty(t *testing.T) {
	// GIVEN an empty queue
	q := NewQueue[int]()

	// WHEN dequeuing an element
	available := make(chan int, 30)
	go func() {
		for {
			available <- q.Dequeue()
		}
	}()

	// THEN it blocks until an element is available
	testutil.ChannelEmpty(t, available, 10*time.Millisecond)

	// AND WHEN there are available elements
	q.Enqueue(1)

	// THEN it unblocks and elements are returned in order
	assert.Equal(t, 1, testutil.ReadChannel(t, available, timeout))
}

func TestQueueDequeueContext(t *testing.T) {
	t.Run("returns queued item", func(t *testing.T) {
		q := NewQueue[int]()
		q.Enqueue(1)

		item, err := q.DequeueContext(context.Background())

		require.NoError(t, err)
		assert.Equal(t, 1, item)
	})

	t.Run("returns when context is canceled", func(t *testing.T) {
		q := NewQueue[int]()
		ctx, cancel := context.WithCancel(context.Background())
		dequeued := make(chan error, 1)

		go func() {
			_, err := q.DequeueContext(ctx)
			dequeued <- err
		}()

		cancel()

		require.ErrorIs(t, testutil.ReadChannel(t, dequeued, timeout), context.Canceled)
	})
}

func TestQueueOrdering(t *testing.T) {
	q := NewQueue[int]()

	go func() {
		for i := range 1000 {
			q.Enqueue(i)
		}
	}()

	for i := range 1000 {
		assert.Equal(t, i, q.Dequeue())
	}
}

func TestSynchronization(t *testing.T) {
	q := NewQueue[int]()
	// enqueuing from concurrent goroutines
	for i := range 1000 {
		cnt := i
		go q.Enqueue(cnt)
	}

	receivedValues := sync.Map{}
	wg := sync.WaitGroup{}
	wg.Add(1000)
	for range 1000 {
		// dequeuing from concurrent goroutines
		go func() {
			receivedValues.Store(q.Dequeue(), struct{}{})
			wg.Done()
		}()
	}

	// wait for all the goroutines to finish
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	testutil.ReadChannel(t, done, timeout)

	// check that each enqueued value has been effectively dequeued
	for i := range 1000 {
		_, ok := receivedValues.Load(i)
		assert.Truef(t, ok, "expected to receive value %d", i)
	}

	// make sure that the queue is empty
	available := make(chan int)
	go func() {
		available <- q.Dequeue()
	}()
	testutil.ChannelEmpty(t, available, 10*time.Millisecond)
}

func TestQueueTryDequeue(t *testing.T) {
	q := NewQueue[int]()

	_, ok := q.TryDequeue()
	assert.False(t, ok)

	q.Enqueue(1)
	q.Enqueue(2)

	v, ok := q.TryDequeue()
	require.True(t, ok)
	assert.Equal(t, 1, v)
	v, ok = q.TryDequeue()
	require.True(t, ok)
	assert.Equal(t, 2, v)

	_, ok = q.TryDequeue()
	assert.False(t, ok)
}
