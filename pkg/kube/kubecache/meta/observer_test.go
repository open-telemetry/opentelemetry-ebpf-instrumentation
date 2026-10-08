// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

const observerTestTimeout = time.Second

type fakeObserver struct {
	errorRate int
	count     int
}

func (f *fakeObserver) ID() string {
	return fmt.Sprintf("%p", f)
}

func (f *fakeObserver) On(_ *informer.Event) error {
	f.count++
	if f.errorRate > 0 && f.count%f.errorRate == 0 {
		return errors.New("fake error on " + f.ID())
	}
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
		n.NotifyAndWait(&informer.Event{})
	}

	// check that the observers that return an error are unsubscribed
	assert.Equal(t, 5, fo5.count)
	assert.Equal(t, 10, fo10.count)
	assert.Equal(t, 20, foNever1.count)
	assert.Equal(t, 20, fonever2.count)
}

type blockingObserver struct {
	id      string
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (o *blockingObserver) ID() string {
	return o.id
}

func (o *blockingObserver) On(_ *informer.Event) error {
	o.once.Do(func() { close(o.started) })
	<-o.release
	return nil
}

type channelObserver struct {
	id     string
	events chan *informer.Event
}

func (o *channelObserver) ID() string {
	return o.id
}

func (o *channelObserver) On(event *informer.Event) error {
	o.events <- event
	return nil
}

func TestSlowObserverDoesNotBlockOthers(t *testing.T) {
	n := NewBaseNotifier(slog.Default())
	blocker := &blockingObserver{
		id:      "blocking",
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	fast := &channelObserver{id: "fast", events: make(chan *informer.Event, 1)}
	n.Subscribe(blocker)
	n.Subscribe(fast)

	t.Cleanup(func() {
		close(blocker.release)
		n.Unsubscribe(blocker)
		n.Unsubscribe(fast)
	})

	done := make(chan struct{})
	go func() {
		n.Notify(&informer.Event{})
		close(done)
	}()

	testutil.ReadChannel(t, blocker.started, observerTestTimeout)
	testutil.ReadChannel(t, done, observerTestTimeout)
	testutil.ReadChannel(t, fast.events, observerTestTimeout)
}

func TestObserverPreservesEventOrder(t *testing.T) {
	n := NewBaseNotifier(slog.Default())
	observer := &channelObserver{id: "ordered", events: make(chan *informer.Event, 10)}
	n.Subscribe(observer)
	t.Cleanup(func() { n.Unsubscribe(observer) })

	for index := range 10 {
		n.Notify(&informer.Event{Resource: &informer.ObjectMeta{StatusTimeEpoch: int64(index)}})
	}

	for index := range 10 {
		event := testutil.ReadChannel(t, observer.events, observerTestTimeout)
		assert.Equal(t, int64(index), event.Resource.StatusTimeEpoch)
	}
}

func TestObserverMustResubscribeWhenQueueIsFull(t *testing.T) {
	n := NewBaseNotifier(slog.Default())
	observer := &blockingObserver{
		id:      "blocking",
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(observer.release) }) })
	n.Subscribe(observer)

	n.Notify(&informer.Event{})
	testutil.ReadChannel(t, observer.started, observerTestTimeout)
	for range observerQueueCapacity + 1 {
		n.Notify(&informer.Event{})
	}

	n.mutex.RLock()
	_, subscribed := n.observers[observer.ID()]
	n.mutex.RUnlock()
	assert.False(t, subscribed)
	release.Do(func() { close(observer.release) })

	replacement := &channelObserver{id: observer.ID(), events: make(chan *informer.Event, 2)}
	n.SubscribeWithSnapshot(replacement, func() []*informer.Event {
		return []*informer.Event{{Resource: &informer.ObjectMeta{Name: "snapshot"}}}
	})
	t.Cleanup(func() { n.Unsubscribe(replacement) })
	n.Notify(&informer.Event{Resource: &informer.ObjectMeta{Name: "live"}})

	first := testutil.ReadChannel(t, replacement.events, observerTestTimeout)
	second := testutil.ReadChannel(t, replacement.events, observerTestTimeout)
	require.NotNil(t, first.Resource)
	require.NotNil(t, second.Resource)
	assert.Equal(t, "snapshot", first.Resource.Name)
	assert.Equal(t, "live", second.Resource.Name)
}

func TestSnapshotPrecedesQueuedLiveEvents(t *testing.T) {
	n := NewBaseNotifier(slog.Default())
	observer := &channelObserver{id: "snapshot", events: make(chan *informer.Event, 2)}
	snapshotStarted := make(chan struct{})
	releaseSnapshot := make(chan struct{})
	subscribed := make(chan struct{})

	go func() {
		n.SubscribeWithSnapshot(observer, func() []*informer.Event {
			close(snapshotStarted)
			<-releaseSnapshot
			return []*informer.Event{{Resource: &informer.ObjectMeta{Name: "snapshot"}}}
		})
		close(subscribed)
	}()
	t.Cleanup(func() { n.Unsubscribe(observer) })

	testutil.ReadChannel(t, snapshotStarted, observerTestTimeout)
	n.Notify(&informer.Event{Resource: &informer.ObjectMeta{Name: "live"}})
	close(releaseSnapshot)
	testutil.ReadChannel(t, subscribed, observerTestTimeout)

	first := testutil.ReadChannel(t, observer.events, observerTestTimeout)
	second := testutil.ReadChannel(t, observer.events, observerTestTimeout)
	require.NotNil(t, first.Resource)
	require.NotNil(t, second.Resource)
	assert.Equal(t, "snapshot", first.Resource.Name)
	assert.Equal(t, "live", second.Resource.Name)
}

func TestNotifyAndWaitWaitsForObserver(t *testing.T) {
	n := NewBaseNotifier(slog.Default())
	observer := &blockingObserver{
		id:      "blocking",
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	n.Subscribe(observer)

	done := make(chan struct{})
	go func() {
		n.NotifyAndWait(&informer.Event{})
		close(done)
	}()

	testutil.ReadChannel(t, observer.started, observerTestTimeout)
	testutil.ChannelEmpty(t, done, 10*time.Millisecond)
	close(observer.release)
	testutil.ReadChannel(t, done, observerTestTimeout)
	n.Unsubscribe(observer)
}
