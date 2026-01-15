// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package shardedqueue

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type testItem struct {
	Key   string
	Value int
}

func TestShardedQueue_EnqueueAndProcess(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(3) // we will enqueue 3 items

	q := NewShardedQueue(
		1, // single worker
		10,
		func(i testItem) string { return i.Key },
		func(_ int, ch <-chan testItem) {
			for range ch {
				wg.Done()
			}
		},
	)

	ctx := context.Background()
	if err := q.Enqueue(ctx, testItem{Key: "a"}); err != nil {
		t.Fatalf("enqueue failed: %v", err)
	}
	if err := q.Enqueue(ctx, testItem{Key: "b"}); err != nil {
		t.Fatalf("enqueue failed: %v", err)
	}
	if err := q.Enqueue(ctx, testItem{Key: "c"}); err != nil {
		t.Fatalf("enqueue failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for worker to process items")
	}

	q.Close()
}

func TestShardedQueue_ContextCancellation(t *testing.T) {
	q := NewShardedQueue(
		1,
		1,
		func(i testItem) string { return i.Key },
		func(_ int, _ <-chan testItem) {
			time.Sleep(time.Second) // block worker so queue stays full
		},
	)

	// fill queue
	if err := q.Enqueue(context.Background(), testItem{Key: "a"}); err != nil {
		t.Fatalf("unexpected enqueue error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancel

	err := q.Enqueue(ctx, testItem{Key: "a"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	q.Close()
}

func TestShardedQueue_Shutdown(t *testing.T) {
	q := NewShardedQueue(
		2,
		2,
		func(i testItem) string { return i.Key },
		func(_ int, _ <-chan testItem) {},
	)

	q.Close()

	err := q.Enqueue(context.Background(), testItem{Key: "x"})
	if !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("expected ErrQueueClosed, got %v", err)
	}
}

func TestShardedQueue_PerKeyOrdering(t *testing.T) {
	items := []testItem{
		{Key: "same", Value: 1},
		{Key: "same", Value: 2},
		{Key: "same", Value: 3},
	}

	var mu sync.Mutex
	var got []int
	var wg sync.WaitGroup
	wg.Add(len(items))

	q := NewShardedQueue(
		1, // single worker for ordering guarantee
		10,
		func(i testItem) string { return i.Key },
		func(_ int, ch <-chan testItem) {
			for item := range ch {
				mu.Lock()
				got = append(got, item.Value)
				mu.Unlock()
				wg.Done()
			}
		},
	)

	for _, item := range items {
		if err := q.Enqueue(context.Background(), item); err != nil {
			t.Fatalf("enqueue failed: %v", err)
		}
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for worker")
	}

	q.Close()

	for i := range items {
		if got[i] != items[i].Value {
			t.Fatalf("ordering violated: got %v want %v", got, items)
		}
	}
}
