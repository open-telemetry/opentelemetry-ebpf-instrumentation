// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta // import "go.opentelemetry.io/obi/pkg/kube/kubecache/meta"

import (
	"context"
	"log/slog"
	"sync"

	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

// A full queue unsubscribes the observer. It must subscribe again, using
// SubscribeWithSnapshot when it needs to rebuild state before live events.
const observerQueueCapacity = 1024

// Observer can be subscribed to a Notifier to receive events
type Observer interface {
	ID() string
	// On new event. If the observer returns an error, it will be assumed as invalid and will be automatically
	// unsubscribed from the notifier. The Observer implementation should free its occupied resources and finish
	// its execution
	On(event *informer.Event) error
}

// Notifier can get subscriptions from Observers
type Notifier interface {
	Subscribe(observer Observer)
	Unsubscribe(observer Observer)
	Notify(event *informer.Event)
}

type BaseNotifier struct {
	log       *slog.Logger
	mutex     sync.RWMutex
	observers map[string]*observerSubscription
}

type observerSubscription struct {
	observer Observer
	events   chan observerNotification
	ctx      context.Context
	cancel   context.CancelFunc
}

type observerNotification struct {
	event     *informer.Event
	processed chan struct{}
}

type queuedNotification struct {
	observerNotification
	subscription *observerSubscription
}

func NewBaseNotifier(log *slog.Logger) BaseNotifier {
	return BaseNotifier{
		log:       log,
		observers: make(map[string]*observerSubscription),
	}
}

func (i *BaseNotifier) Unsubscribe(observer Observer) {
	i.mutex.Lock()
	if subscription := i.observers[observer.ID()]; subscription != nil {
		delete(i.observers, observer.ID())
		subscription.cancel()
	}
	i.mutex.Unlock()
}

func (i *BaseNotifier) Notify(event *informer.Event) {
	i.enqueue(event, false)
}

// NotifyAndWait delivers an event in order and waits until every current observer
// has processed it.
func (i *BaseNotifier) NotifyAndWait(event *informer.Event) {
	for _, queued := range i.enqueue(event, true) {
		select {
		case <-queued.processed:
		case <-queued.subscription.ctx.Done():
		}
	}
}

func (i *BaseNotifier) enqueue(event *informer.Event, wait bool) []queuedNotification {
	i.mutex.RLock()
	var queued []queuedNotification
	if wait {
		queued = make([]queuedNotification, 0, len(i.observers))
	}
	var overflowed []*observerSubscription
	for _, subscription := range i.observers {
		notification := observerNotification{event: event}
		if wait {
			notification.processed = make(chan struct{})
		}
		select {
		case subscription.events <- notification:
			if wait {
				queued = append(queued, queuedNotification{
					observerNotification: notification,
					subscription:         subscription,
				})
			}
		default:
			overflowed = append(overflowed, subscription)
		}
	}
	i.mutex.RUnlock()

	for _, subscription := range overflowed {
		i.log.Warn("observer queue full. Unsubscribing it; observer must resubscribe", "observer", subscription.observer.ID())
		i.removeSubscription(subscription)
	}
	return queued
}

func (i *BaseNotifier) Subscribe(observer Observer) {
	i.SubscribeWithSnapshot(observer, nil)
}

// SubscribeWithSnapshot registers an observer before reading its initial state.
// Events received while snapshot is running are queued and delivered after it.
func (i *BaseNotifier) SubscribeWithSnapshot(observer Observer, snapshot func() []*informer.Event) {
	ctx, cancel := context.WithCancel(context.Background())
	subscription := &observerSubscription{
		observer: observer,
		events:   make(chan observerNotification, observerQueueCapacity),
		ctx:      ctx,
		cancel:   cancel,
	}

	i.mutex.Lock()
	if previous := i.observers[observer.ID()]; previous != nil {
		previous.cancel()
	}
	i.observers[observer.ID()] = subscription
	i.mutex.Unlock()

	var initial []*informer.Event
	if snapshot != nil {
		initial = snapshot()
	}
	ready := make(chan struct{})
	go i.notify(subscription, initial, ready)
	select {
	case <-ready:
	case <-subscription.ctx.Done():
	}
}

func (i *BaseNotifier) notify(
	subscription *observerSubscription,
	initial []*informer.Event,
	ready chan struct{},
) {
	for _, event := range initial {
		if !i.deliver(subscription, observerNotification{event: event}) {
			close(ready)
			return
		}
	}
	close(ready)

	for {
		select {
		case <-subscription.ctx.Done():
			return
		case notification := <-subscription.events:
			if i.deliver(subscription, notification) {
				continue
			}
			return
		}
	}
}

func (i *BaseNotifier) deliver(subscription *observerSubscription, notification observerNotification) bool {
	select {
	case <-subscription.ctx.Done():
		return false
	default:
	}

	err := subscription.observer.On(notification.event)
	if notification.processed != nil {
		close(notification.processed)
	}
	if err == nil {
		return true
	}

	i.log.Debug("observer failed. Unsubscribing it", "observer", subscription.observer.ID(), "error", err)
	i.removeSubscription(subscription)
	return false
}

func (i *BaseNotifier) removeSubscription(subscription *observerSubscription) {
	i.mutex.Lock()
	if i.observers[subscription.observer.ID()] == subscription {
		delete(i.observers, subscription.observer.ID())
		subscription.cancel()
	}
	i.mutex.Unlock()
}
