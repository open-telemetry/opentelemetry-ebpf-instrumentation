// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	javaagent "go.opentelemetry.io/obi/pkg/internal/java"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func javaTarget(pid app.PID) javaagent.InjectionTarget {
	return javaagent.InjectionTarget{Type: svc.InstrumentableJava, Pid: pid}
}

// Attaching to a HotSpot JVM switches the euid/egid of the whole OBI process,
// so two injections must never be in flight at the same time.
func TestJavaInjectionQueue_InjectsOneAtATimeInOrder(t *testing.T) {
	const targets = 20

	var (
		mt       sync.Mutex
		order    []app.PID
		inFlight atomic.Int32
		maxSeen  atomic.Int32
	)
	done := make(chan struct{})

	queue := newJavaInjectionQueue(slog.Default(), func(_ context.Context, target javaagent.InjectionTarget) error {
		if current := inFlight.Add(1); current > maxSeen.Load() {
			maxSeen.Store(current)
		}
		// Widen the window in which an overlapping injection would be visible.
		time.Sleep(time.Millisecond)

		mt.Lock()
		order = append(order, target.Pid)
		last := len(order) == targets
		mt.Unlock()

		inFlight.Add(-1)
		if last {
			close(done)
		}
		return nil
	})

	ctx := t.Context()
	queue.start(ctx)

	var want []app.PID
	for pid := app.PID(1); pid <= targets; pid++ {
		queue.enqueue(javaTarget(pid))
		want = append(want, pid)
	}

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for all injections")
	}

	assert.Equal(t, int32(1), maxSeen.Load(), "injections must not overlap")
	mt.Lock()
	defer mt.Unlock()
	assert.Equal(t, want, order)
}

// Models what jvm.JAttacher does: it switches the euid/egid of the whole OBI
// process to the target's owner and restores the previous values when the attach
// ends. JVMs owned by different users must never see each other's identity.
func TestJavaInjectionQueue_NoTwoJVMsShareProcessCredentials(t *testing.T) {
	const (
		obiUID  = 0
		targets = 20
	)

	var (
		processEUID atomic.Int32
		violations  atomic.Int32
		injected    atomic.Int32
	)
	processEUID.Store(obiUID)
	done := make(chan struct{})

	queue := newJavaInjectionQueue(slog.Default(), func(_ context.Context, target javaagent.InjectionTarget) error {
		targetUID := int32(target.Pid)

		if !processEUID.CompareAndSwap(obiUID, targetUID) {
			violations.Add(1)
		}
		time.Sleep(time.Millisecond)

		// Restoring is only correct if nothing else moved the credentials in
		// the meantime.
		if !processEUID.CompareAndSwap(targetUID, obiUID) {
			violations.Add(1)
		}

		if injected.Add(1) == targets {
			close(done)
		}
		return nil
	})

	ctx := t.Context()
	queue.start(ctx)

	for pid := app.PID(1); pid <= targets; pid++ {
		queue.enqueue(javaTarget(pid))
	}

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for all injections")
	}

	assert.Equal(t, int32(0), violations.Load(), "an injection ran under or restored another target's credentials")
	assert.Equal(t, int32(obiUID), processEUID.Load())
}

// A stuck attach holds the worker for up to the attach timeout. Discovery must
// keep making progress meanwhile, so enqueue never blocks.
func TestJavaInjectionQueue_EnqueueDoesNotBlockOnStuckInjection(t *testing.T) {
	injecting := make(chan struct{})
	release := make(chan struct{})
	var firstInjection sync.Once

	queue := newJavaInjectionQueue(slog.Default(), func(ctx context.Context, _ javaagent.InjectionTarget) error {
		firstInjection.Do(func() { close(injecting) })
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	})

	ctx := t.Context()
	queue.start(ctx)

	queue.enqueue(javaTarget(1))
	<-injecting

	enqueued := make(chan struct{})
	go func() {
		defer close(enqueued)
		// One more than the buffer, to also cover the full-queue drop path.
		for pid := app.PID(2); pid <= javaInjectionQueueLen+2; pid++ {
			queue.enqueue(javaTarget(pid))
		}
	}()

	select {
	case <-enqueued:
	case <-time.After(testTimeout):
		t.Fatal("enqueue blocked behind a stuck injection")
	}

	close(release)
}

// javaInjections.wait() runs inside the attacher loop's shutdown path, which the
// pipeline bounds with its own cancel timeout. The in-flight injection sees the
// cancelled context, so the drain must not wait out the attach timeout.
func TestJavaInjectionQueue_ShutdownCancelsInFlightAndSkipsPending(t *testing.T) {
	injecting := make(chan struct{})
	var started atomic.Int32
	cancelled := make(chan struct{}, 1)

	queue := newJavaInjectionQueue(slog.Default(), func(ctx context.Context, _ javaagent.InjectionTarget) error {
		if started.Add(1) == 1 {
			close(injecting)
		}
		<-ctx.Done()
		cancelled <- struct{}{}
		return ctx.Err()
	})

	ctx, cancel := context.WithCancel(context.Background())
	queue.start(ctx)

	queue.enqueue(javaTarget(1))
	<-injecting
	queue.enqueue(javaTarget(2))
	queue.enqueue(javaTarget(3))

	cancel()

	waited := make(chan struct{})
	go func() {
		queue.wait()
		close(waited)
	}()

	select {
	case <-waited:
	case <-time.After(testTimeout):
		t.Fatal("shutdown did not return after context cancellation")
	}

	require.Len(t, cancelled, 1)
	assert.Equal(t, int32(1), started.Load(), "queued targets must not be injected during shutdown")
}

func TestJavaInjectionQueue_ClosesDequeuedTargetAfterCancellation(t *testing.T) {
	pid := app.PID(os.Getpid())
	startTime, err := procs.StartTime(pid)
	require.NoError(t, err)
	process, err := procs.OpenProcessHandle(pid, startTime)
	require.NoError(t, err)
	t.Cleanup(func() { _ = process.Close() })

	var injections atomic.Int32
	queue := newJavaInjectionQueue(slog.Default(), func(context.Context, javaagent.InjectionTarget) error {
		injections.Add(1)
		return nil
	})
	target := javaTarget(pid)
	target.Process = process
	target.StartTime = startTime
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	assert.False(t, queue.injectTarget(ctx, target))
	assert.Equal(t, int32(0), injections.Load())
	assert.Error(t, process.Alive(), "a dequeued target must be closed when cancellation wins")
}

// The queue is bounded and only JVMs are ever injected. If processes of other
// languages took slots, discovery churn during a stuck attach would evict a JVM
// discovered later, losing its Java TLS telemetry for the life of the process.
func TestJavaInjectionQueue_OnlyJVMsAreAdmitted(t *testing.T) {
	injecting := make(chan struct{})
	release := make(chan struct{})
	injected := make(chan app.PID, javaInjectionQueueLen+2)
	var firstInjection sync.Once

	queue := newJavaInjectionQueue(slog.Default(), func(ctx context.Context, target javaagent.InjectionTarget) error {
		injected <- target.Pid
		firstInjection.Do(func() {
			close(injecting)
			select {
			case <-release:
			case <-ctx.Done():
			}
		})
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue.start(ctx)

	// Hold the worker, then flood the queue with processes the injector would
	// ignore, well past its capacity.
	queue.enqueue(javaTarget(1))
	<-injecting
	require.Equal(t, app.PID(1), <-injected)

	for pid := app.PID(2); pid <= javaInjectionQueueLen+2; pid++ {
		queue.enqueue(javaagent.InjectionTarget{Type: svc.InstrumentableGeneric, Pid: pid})
	}

	const lateJVM = app.PID(javaInjectionQueueLen + 3)
	queue.enqueue(javaTarget(lateJVM))
	close(release)

	select {
	case pid := <-injected:
		assert.Equal(t, lateJVM, pid, "a JVM discovered after non-Java processes must still be injected")
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for the second injection")
	}

	cancel()
	queue.wait()
	assert.Empty(t, injected, "only JVMs may be injected")
}

func TestJavaInjectionQueue_EnqueueAfterShutdownIsDropped(t *testing.T) {
	var injections atomic.Int32

	queue := newJavaInjectionQueue(slog.Default(), func(context.Context, javaagent.InjectionTarget) error {
		injections.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	queue.start(ctx)
	cancel()
	queue.wait()

	pid := app.PID(os.Getpid())
	startTime, err := procs.StartTime(pid)
	require.NoError(t, err)
	process, err := procs.OpenProcessHandle(pid, startTime)
	require.NoError(t, err)
	target := javaTarget(pid)
	target.Process = process
	target.StartTime = startTime

	queue.enqueue(target)

	assert.Equal(t, int32(0), injections.Load())
	assert.Error(t, process.Alive(), "a target dropped after shutdown must be closed")
}
