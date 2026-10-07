// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
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

func TestNotificationErrors(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
	log := slog.With("test", "TestNotificationErrors")
	n := NewBaseNotifier(log)
	t.Cleanup(n.Close)
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
	}, time.Second, time.Millisecond)
}

type callbackObserver struct {
	id string
	on func(*informer.Event) error
}

func (o callbackObserver) ID() string                     { return o.id }
func (o callbackObserver) On(event *informer.Event) error { return o.on(event) }

func TestSlowObserverDoesNotBlockFanoutOrReplacement(t *testing.T) {
	n := NewBaseNotifier(slog.Default())
	t.Cleanup(n.Close)
	started, release := make(chan struct{}), make(chan struct{})
	old := &callbackObserver{id: "slow", on: func(*informer.Event) error {
		close(started)
		<-release
		return errors.New("old observer failed")
	}}
	defer close(release)
	n.Subscribe(old)

	got := make(chan *informer.Event, 2)
	fast := &callbackObserver{id: "fast", on: func(event *informer.Event) error {
		got <- event
		return nil
	}}
	n.Subscribe(fast)
	event := &informer.Event{Type: informer.EventType_UPDATED}
	go n.Notify(event)
	testutil.ReadChannel(t, started, time.Second)
	require.Same(t, event, testutil.ReadChannel(t, got, time.Second))

	waiting := make(chan bool, 1)
	go func() { waiting <- n.NotifyObserver(old, event) }()
	testutil.ChannelEmpty(t, waiting, 10*time.Millisecond)

	replacement := &callbackObserver{id: "slow", on: fast.on}
	n.Subscribe(replacement)
	require.False(t, testutil.ReadChannel(t, waiting, time.Second))
	n.Unsubscribe(old)
	require.False(t, n.NotifyObserver(old, event))
	require.True(t, n.NotifyObserver(replacement, event))
	require.Same(t, event, testutil.ReadChannel(t, got, time.Second))

	n.Close()
	n.Close()
	n.Subscribe(replacement)
	require.False(t, n.NotifyObserver(replacement, event))
}

func TestSnapshotLargerThanQueueCompletesBeforeSubscribeReturns(t *testing.T) {
	n := NewBaseNotifier(slog.Default())
	t.Cleanup(n.Close)
	count := 0
	observer := &callbackObserver{id: "snapshot", on: func(*informer.Event) error {
		count++
		return nil
	}}
	n.SubscribeWithSnapshot(observer, func() []*informer.Event {
		events := make([]*informer.Event, ObserverQueueCapacity+1)
		for index := range events {
			events[index] = &informer.Event{Type: informer.EventType_CREATED}
		}
		return events
	})
	require.Equal(t, ObserverQueueCapacity+1, count)
}

func TestObserverWithoutSnapshotStopsOnOverflow(t *testing.T) {
	n := NewBaseNotifier(slog.Default())
	t.Cleanup(n.Close)
	started, release := make(chan struct{}), make(chan struct{})
	observer := &callbackObserver{id: "blocked", on: func(*informer.Event) error {
		close(started)
		<-release
		return nil
	}}
	defer close(release)
	n.Subscribe(observer)
	n.Notify(&informer.Event{})
	testutil.ReadChannel(t, started, time.Second)

	for range ObserverQueueCapacity + 1 {
		n.Notify(&informer.Event{})
	}
	require.False(t, n.NotifyObserver(observer, &informer.Event{}))
}

func TestObserverRegistrationRejectsNonComparableValues(t *testing.T) {
	n := NewBaseNotifier(slog.Default())
	t.Cleanup(n.Close)
	observer := callbackObserver{id: "value", on: func(*informer.Event) error { return nil }}
	require.PanicsWithValue(t,
		"meta.Observer must be comparable; use a pointer for observers containing slices, maps, or functions",
		func() { n.Subscribe(observer) },
	)

	n.Subscribe(&observer)
	require.True(t, n.NotifyObserver(&observer, &informer.Event{}))
	require.False(t, n.NotifyObserver(observer, &informer.Event{}))
	n.Unsubscribe(observer)
	require.True(t, n.NotifyObserver(&observer, &informer.Event{}))
}
