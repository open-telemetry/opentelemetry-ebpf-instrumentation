// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta // import "go.opentelemetry.io/obi/pkg/kube/kubecache/meta"

import (
	"context"
	"log/slog"
	"sync"

	syncqueue "go.opentelemetry.io/obi/pkg/internal/helpers/sync"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

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
	events   *syncqueue.Queue[*informer.Event]
	cancel   context.CancelFunc
}

func NewBaseNotifier(log *slog.Logger) BaseNotifier {
	return BaseNotifier{
		log:       log,
		observers: make(map[string]*observerSubscription),
	}
}

func (i *BaseNotifier) Unsubscribe(observer Observer) {
	i.mutex.Lock()
	subscription := i.observers[observer.ID()]
	if subscription != nil {
		delete(i.observers, observer.ID())
	}
	i.mutex.Unlock()

	if subscription != nil {
		subscription.cancel()
	}
}

func (i *BaseNotifier) Notify(event *informer.Event) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	for _, subscription := range i.observers {
		subscription.events.Enqueue(event)
	}
}

// NotifyObserver sends an event only to the given observer.
func (i *BaseNotifier) NotifyObserver(observer Observer, event *informer.Event) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	if subscription := i.observers[observer.ID()]; subscription != nil {
		subscription.events.Enqueue(event)
	}
}

func (i *BaseNotifier) Subscribe(observer Observer) {
	ctx, cancel := context.WithCancel(context.Background())
	subscription := &observerSubscription{
		observer: observer,
		events:   syncqueue.NewQueue[*informer.Event](),
		cancel:   cancel,
	}

	i.mutex.Lock()
	previous := i.observers[observer.ID()]
	i.observers[observer.ID()] = subscription
	i.mutex.Unlock()

	if previous != nil {
		previous.cancel()
	}
	go i.notify(ctx, subscription)
}

func (i *BaseNotifier) notify(ctx context.Context, subscription *observerSubscription) {
	for {
		event, err := subscription.events.DequeueContext(ctx)
		if err != nil {
			return
		}
		if err := subscription.observer.On(event); err != nil {
			i.log.Debug("observer failed. Unsubscribing it",
				"observer", subscription.observer.ID(), "error", err)
			i.unsubscribe(subscription)
			return
		}
	}
}

func (i *BaseNotifier) unsubscribe(subscription *observerSubscription) {
	i.mutex.Lock()
	if i.observers[subscription.observer.ID()] == subscription {
		delete(i.observers, subscription.observer.ID())
	}
	i.mutex.Unlock()
	subscription.cancel()
}
