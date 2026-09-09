// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/nodejs"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func nodeTarget(pid app.PID) nodejs.InjectionTarget {
	return nodejs.InjectionTarget{Pid: pid}
}

func TestNodeInjectionQueue_InjectsInOrder(t *testing.T) {
	var mt sync.Mutex
	var got []app.PID
	done := make(chan struct{})

	queue := newNodeInjectionQueue(slog.Default(), nil, func(_ context.Context, target nodejs.InjectionTarget) {
		mt.Lock()
		defer mt.Unlock()
		got = append(got, target.Pid)
		if len(got) == 3 {
			close(done)
		}
	})
	queue.start(t.Context())

	for _, pid := range []app.PID{1, 2, 3} {
		queue.enqueue(nodeTarget(pid))
	}

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for injections")
	}

	mt.Lock()
	defer mt.Unlock()
	assert.Equal(t, []app.PID{1, 2, 3}, got)
}

// With the worker parked on the first target the buffer takes exactly its
// capacity, so the injections that eventually run are the ones that were
// admitted, and the rest were dropped rather than queued or blocked on.
func TestNodeInjectionQueue_EnqueueDoesNotBlockWhenFull(t *testing.T) {
	const admitted = nodeInjectionQueueLen + 1

	release := make(chan struct{})
	parked := make(chan struct{})
	drained := make(chan struct{})

	var injections atomic.Int32
	queue := newNodeInjectionQueue(slog.Default(), nil, func(context.Context, nodejs.InjectionTarget) {
		switch injections.Add(1) {
		case 1:
			close(parked)
			<-release
		case admitted:
			close(drained)
		}
	})
	queue.start(t.Context())

	queue.enqueue(nodeTarget(1))
	<-parked

	for pid := app.PID(2); pid <= nodeInjectionQueueLen+50; pid++ {
		queue.enqueue(nodeTarget(pid))
	}
	close(release)

	select {
	case <-drained:
	case <-time.After(testTimeout):
		t.Fatalf("injected %d of the %d admitted targets", injections.Load(), admitted)
	}

	// Nothing beyond the admitted targets was accepted, so a short settle is
	// enough to catch an over-count.
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int32(admitted), injections.Load())
}

// The worker must not start an injection once shutdown has begun, and the
// target it dequeues has to be released rather than leaked.
func TestNodeInjectionQueue_ClosesDequeuedTargetAfterCancellation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping on non-linux platform: it relies on /proc filesystem")
	}
	pid := app.PID(os.Getpid())
	startTime, err := procs.StartTime(pid)
	require.NoError(t, err)
	process, err := procs.OpenProcessHandle(pid, startTime)
	require.NoError(t, err)
	t.Cleanup(func() { _ = process.Close() })

	var injections atomic.Int32
	queue := newNodeInjectionQueue(slog.Default(), nil, func(context.Context, nodejs.InjectionTarget) {
		injections.Add(1)
	})
	target := nodeTarget(pid)
	target.Process = process

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	assert.False(t, queue.injectTarget(ctx, target))
	assert.Equal(t, int32(0), injections.Load())
	assert.Error(t, process.Alive(), "a dequeued target must be closed when cancellation wins")
}

// A target offered after shutdown is released too: discovery keeps producing
// while the queue is winding down.
func TestNodeInjectionQueue_EnqueueAfterShutdownIsDropped(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping on non-linux platform: it relies on /proc filesystem")
	}
	pid := app.PID(os.Getpid())
	startTime, err := procs.StartTime(pid)
	require.NoError(t, err)
	process, err := procs.OpenProcessHandle(pid, startTime)
	require.NoError(t, err)
	t.Cleanup(func() { _ = process.Close() })

	var injections atomic.Int32
	queue := newNodeInjectionQueue(slog.Default(), nil, func(context.Context, nodejs.InjectionTarget) {
		injections.Add(1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	queue.start(ctx)
	cancel()
	queue.wait()

	target := nodeTarget(pid)
	target.Process = process
	queue.enqueue(target)

	assert.Equal(t, int32(0), injections.Load())
	assert.Error(t, process.Alive(), "a target offered after shutdown must be closed")
}
