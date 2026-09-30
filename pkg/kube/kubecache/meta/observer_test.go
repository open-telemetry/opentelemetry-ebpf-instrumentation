// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

type fakeObserver struct {
	errorRate int32
	count     atomic.Int32
}

func (f *fakeObserver) ID() string {
	return fmt.Sprintf("%p", f)
}

func (f *fakeObserver) On(_ *informer.Event) error {
	count := f.count.Add(1)
	if f.errorRate > 0 && count%f.errorRate == 0 {
		return errors.New("fake error on " + f.ID())
	}
	return nil
}

type blockingObserver struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingObserver) ID() string {
	return "blocking"
}

func (b *blockingObserver) On(_ *informer.Event) error {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return nil
}

type recordingObserver struct {
	id     string
	events chan informer.EventType
}

func (r *recordingObserver) ID() string {
	return r.id
}

func (r *recordingObserver) On(event *informer.Event) error {
	r.events <- event.Type
	return nil
}

func TestNotificationErrors(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
	log := slog.With("test", "TestNotificationErrors")
	n := NewBaseNotifier(log)
	fo5 := &fakeObserver{errorRate: 5}
	fo10 := &fakeObserver{errorRate: 10}
	foNever1 := &fakeObserver{errorRate: 0}
	fonever2 := &fakeObserver{errorRate: 0}
	n.Subscribe(fo5)
	n.Subscribe(foNever1)
	n.Subscribe(fo10)
	n.Subscribe(fonever2)

	for range 20 {
		n.Notify(&informer.Event{})
	}

	// check that the observers that return an error are unsubscribed
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.Equal(ct, int32(5), fo5.count.Load())
		assert.Equal(ct, int32(10), fo10.count.Load())
		assert.Equal(ct, int32(20), foNever1.count.Load())
		assert.Equal(ct, int32(20), fonever2.count.Load())
	}, time.Second, 10*time.Millisecond)
}

func TestSlowObserverDoesNotBlockOtherObservers(t *testing.T) {
	n := NewBaseNotifier(slog.Default())
	blocker := &blockingObserver{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	n.Subscribe(blocker)
	t.Cleanup(func() { close(blocker.release) })

	n.Notify(&informer.Event{})
	select {
	case <-blocker.started:
	case <-time.After(time.Second):
		t.Fatal("blocking observer was not invoked")
	}

	fast := &recordingObserver{
		id:     "fast",
		events: make(chan informer.EventType, 1),
	}
	n.Subscribe(fast)
	n.Notify(&informer.Event{Type: informer.EventType_UPDATED})

	select {
	case eventType := <-fast.events:
		assert.Equal(t, informer.EventType_UPDATED, eventType)
	case <-time.After(time.Second):
		t.Fatal("fast observer was blocked by the slow observer")
	}
}

func TestNotifyObserverWaitsForDelivery(t *testing.T) {
	n := NewBaseNotifier(slog.Default())
	blocker := &blockingObserver{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	n.Subscribe(blocker)

	done := make(chan struct{})
	go func() {
		n.NotifyObserver(blocker, &informer.Event{})
		close(done)
	}()

	testutil.ReadChannel(t, blocker.started, time.Second)
	testutil.ChannelEmpty(t, done, 10*time.Millisecond)
	close(blocker.release)
	testutil.ReadChannel(t, done, time.Second)
}

func TestSubscribeReplacesObserverWithSameID(t *testing.T) {
	n := NewBaseNotifier(slog.Default())
	previous := &recordingObserver{id: "observer", events: make(chan informer.EventType, 1)}
	replacement := &recordingObserver{id: "observer", events: make(chan informer.EventType, 1)}
	n.Subscribe(previous)
	n.Subscribe(replacement)

	n.Notify(&informer.Event{Type: informer.EventType_UPDATED})

	assert.Equal(t, informer.EventType_UPDATED, testutil.ReadChannel(t, replacement.events, time.Second))
	testutil.ChannelEmpty(t, previous.events, 10*time.Millisecond)
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	n := NewBaseNotifier(slog.Default())
	observer := &recordingObserver{id: "observer", events: make(chan informer.EventType, 1)}
	n.Subscribe(observer)
	n.Unsubscribe(observer)
	n.Unsubscribe(observer)

	n.Notify(&informer.Event{Type: informer.EventType_UPDATED})
	n.NotifyObserver(observer, &informer.Event{Type: informer.EventType_UPDATED})

	testutil.ChannelEmpty(t, observer.events, 10*time.Millisecond)
}

func TestObserverReceivesEventsInOrder(t *testing.T) {
	n := NewBaseNotifier(slog.Default())
	observer := &recordingObserver{
		id:     "recording",
		events: make(chan informer.EventType, 3),
	}
	n.Subscribe(observer)

	n.NotifyObserver(observer, &informer.Event{Type: informer.EventType_CREATED})
	n.Notify(&informer.Event{Type: informer.EventType_UPDATED})
	n.NotifyObserver(observer, &informer.Event{Type: informer.EventType_SYNC_FINISHED})

	assert.Equal(t, informer.EventType_CREATED, testutil.ReadChannel(t, observer.events, time.Second))
	assert.Equal(t, informer.EventType_UPDATED, testutil.ReadChannel(t, observer.events, time.Second))
	assert.Equal(t, informer.EventType_SYNC_FINISHED, testutil.ReadChannel(t, observer.events, time.Second))
}
