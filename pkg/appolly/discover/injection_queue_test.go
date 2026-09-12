// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	javaagent "go.opentelemetry.io/obi/pkg/internal/java"
	"go.opentelemetry.io/obi/pkg/internal/nodejs"
)

// Attaching to a JVM switches OBI's euid and egid process-wide, so no other
// injection may run beside one, whatever its runtime. Each runtime keeps its
// own bounded queue; the slot is what keeps their workers from overlapping.
func TestInjectionSlot_SerializesAcrossRuntimes(t *testing.T) {
	slot := newInjectionSlot()

	var inFlight atomic.Int32
	var overlapped atomic.Bool
	enter := func() {
		if inFlight.Add(1) > 1 {
			overlapped.Store(true)
		}
	}

	attaching := make(chan struct{})
	release := make(chan struct{})
	java := newJavaInjectionQueue(slog.Default(), slot,
		func(context.Context, javaagent.InjectionTarget) error {
			enter()
			defer inFlight.Add(-1)
			close(attaching)
			<-release
			return nil
		})

	injected := make(chan struct{})
	node := newNodeInjectionQueue(slog.Default(), slot,
		func(context.Context, nodejs.InjectionTarget) {
			enter()
			defer inFlight.Add(-1)
			close(injected)
		})

	java.start(t.Context())
	node.start(t.Context())

	java.enqueue(javaTarget(1))
	<-attaching
	node.enqueue(nodeTarget(2))

	select {
	case <-injected:
		t.Fatal("a node injection ran while a java attach held the slot")
	case <-time.After(200 * time.Millisecond):
	}

	close(release)

	select {
	case <-injected:
	case <-time.After(testTimeout):
		t.Fatal("the node injection did not run once the slot was released")
	}

	assert.False(t, overlapped.Load(), "two injections were in flight at once")
}

// A worker waiting its turn must still observe shutdown rather than block on
// the slot until the injection ahead of it finishes.
func TestInjectionSlot_WaitingWorkerObservesShutdown(t *testing.T) {
	slot := newInjectionSlot()
	require := assert.New(t)
	require.True(slot.acquire(context.Background()))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.False(slot.acquire(ctx), "acquire must give up once the context is done")

	slot.release()
	require.True(slot.acquire(context.Background()), "the slot must be reusable after release")
}

// The queue must not start an injection it cannot finish, so a target dequeued
// during shutdown is closed without ever reaching the injector.
func TestInjectionQueue_CancellationBeatsTheSlot(t *testing.T) {
	slot := newInjectionSlot()
	assert.True(t, slot.acquire(context.Background()))

	var injections atomic.Int32
	queue := newNodeInjectionQueue(slog.Default(), slot,
		func(context.Context, nodejs.InjectionTarget) {
			injections.Add(1)
		})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	assert.False(t, queue.injectTarget(ctx, nodeTarget(1)))
	assert.Equal(t, int32(0), injections.Load())
}
