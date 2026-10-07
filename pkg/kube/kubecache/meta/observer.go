// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta // import "go.opentelemetry.io/obi/pkg/kube/kubecache/meta"

import (
	"log/slog"
	"reflect"
	"sync"

	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

// ObserverQueueCapacity bounds the pending live events for each observer.
const ObserverQueueCapacity = 1024

// Observer receives metadata events. Implementations must be comparable Go values
// (normally pointers), so a stale observer cannot affect a replacement with the same ID.
type Observer interface {
	ID() string
	// On processes an event. Returning an error removes the observer.
	// Blocking implementations must also respond to their owner's cancellation.
	On(event *informer.Event) error
}

// Notifier can get subscriptions from Observers.
type Notifier interface {
	Subscribe(observer Observer)
	Unsubscribe(observer Observer)
	Notify(event *informer.Event)
}

type BaseNotifier struct {
	log       *slog.Logger
	mutex     sync.Mutex
	observers map[string]*observerSubscription
	closed    bool
}

type observerSubscription struct {
	observer Observer
	events   chan observerNotification
	stop     chan struct{}
	snapshot func() []*informer.Event
	resync   bool // protected by the notifier mutex
}

type observerNotification struct {
	event     *informer.Event
	processed chan struct{}
}

func NewBaseNotifier(log *slog.Logger) BaseNotifier {
	return BaseNotifier{log: log, observers: map[string]*observerSubscription{}}
}

func (i *BaseNotifier) Subscribe(observer Observer) {
	i.SubscribeWithSnapshot(observer, nil)
}

// SubscribeWithSnapshot completes the welcome snapshot before returning.
// snapshot must only read cached state. On overflow, the worker reconciles a fresh
// snapshot with its previously delivered objects, then resumes live delivery.
func (i *BaseNotifier) SubscribeWithSnapshot(observer Observer, snapshot func() []*informer.Event) {
	if !reflect.ValueOf(observer).Comparable() {
		panic("meta.Observer must be comparable; use a pointer for observers containing slices, maps, or functions")
	}

	i.mutex.Lock()
	if i.closed {
		i.mutex.Unlock()
		return
	}
	if previous := i.observers[observer.ID()]; previous != nil {
		close(previous.stop)
	}
	subscription := &observerSubscription{
		observer: observer,
		events:   make(chan observerNotification, ObserverQueueCapacity),
		stop:     make(chan struct{}),
		snapshot: snapshot,
	}
	var initial []*informer.Event
	if snapshot != nil {
		initial = snapshot()
	}
	i.observers[observer.ID()] = subscription
	i.mutex.Unlock()

	ready := make(chan struct{})
	go i.runObserver(subscription, initial, ready)
	select {
	case <-ready:
	case <-subscription.stop:
	}
}

func (i *BaseNotifier) subscription(observer Observer) *observerSubscription {
	if !reflect.ValueOf(observer).Comparable() {
		return nil
	}
	i.mutex.Lock()
	defer i.mutex.Unlock()
	subscription := i.observers[observer.ID()]
	if subscription != nil && subscription.observer == observer {
		return subscription
	}
	return nil
}

func (i *BaseNotifier) Unsubscribe(observer Observer) {
	if subscription := i.subscription(observer); subscription != nil {
		i.removeSubscription(subscription)
	}
}

func (i *BaseNotifier) removeSubscription(subscription *observerSubscription) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	if i.observers[subscription.observer.ID()] == subscription {
		delete(i.observers, subscription.observer.ID())
		close(subscription.stop)
	}
}

func (i *BaseNotifier) Notify(event *informer.Event) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.enqueue(event)
}

func (i *BaseNotifier) enqueue(event *informer.Event) {
	for id, subscription := range i.observers {
		if subscription.resync {
			continue
		}
		select {
		case subscription.events <- observerNotification{event: event, processed: make(chan struct{})}:
		default:
			i.log.Warn("observer queue overflow", "observer", id)
			if subscription.snapshot == nil {
				delete(i.observers, id)
				close(subscription.stop)
			} else {
				subscription.resync = true
			}
		}
	}
}

// NotifyObserver waits for this observer to process the event. A stale or stopped
// subscription returns false. This also supplies backpressure to a single producer.
func (i *BaseNotifier) NotifyObserver(observer Observer, event *informer.Event) bool {
	subscription := i.subscription(observer)
	if subscription == nil {
		return false
	}
	notification := observerNotification{event: event, processed: make(chan struct{})}
	select {
	case subscription.events <- notification:
	case <-subscription.stop:
		return false
	}
	select {
	case <-notification.processed:
		return true
	case <-subscription.stop:
		return false
	}
}

func (i *BaseNotifier) runObserver(subscription *observerSubscription, pending []*informer.Event, ready chan struct{}) {
	known := map[[3]string]*informer.ObjectMeta{}
	for {
		var notification observerNotification
		if len(pending) > 0 {
			notification = observerNotification{event: pending[0], processed: make(chan struct{})}
			pending[0] = nil
			pending = pending[1:]
		} else {
			if ready != nil {
				close(ready)
				ready = nil
			}
			i.mutex.Lock()
			if len(subscription.events) == 0 && subscription.resync && !i.closed {
				pending = subscription.reconcile(known)
				subscription.resync = false
			}
			i.mutex.Unlock()
			if len(pending) > 0 {
				continue
			}
			select {
			case notification = <-subscription.events:
			case <-subscription.stop:
				return
			}
		}

		select {
		case <-subscription.stop:
			return
		default:
		}
		if err := subscription.observer.On(notification.event); err != nil {
			i.log.Debug("observer failed. Unsubscribing it", "observer", subscription.observer.ID(), "error", err)
			i.removeSubscription(subscription)
			return
		}
		if object := notification.event.GetResource(); object != nil && subscription.snapshot != nil {
			key := [3]string{object.Kind, object.Namespace, object.Name}
			if notification.event.Type == informer.EventType_DELETED {
				delete(known, key)
			} else {
				known[key] = object
			}
		}
		close(notification.processed)
	}
}

func (s *observerSubscription) reconcile(known map[[3]string]*informer.ObjectMeta) []*informer.Event {
	snapshot := s.snapshot()
	current := make(map[[3]string]struct{}, len(snapshot))
	for index, event := range snapshot {
		if object := event.Resource; object != nil {
			key := [3]string{object.Kind, object.Namespace, object.Name}
			current[key] = struct{}{}
			if _, exists := known[key]; exists {
				snapshot[index] = &informer.Event{Type: informer.EventType_UPDATED, Resource: object}
			}
		}
	}
	var deleted []*informer.Event
	for key, object := range known {
		if _, exists := current[key]; !exists {
			deleted = append(deleted, &informer.Event{Type: informer.EventType_DELETED, Resource: object})
		}
	}
	return append(deleted, snapshot...)
}

// Close stops idle workers and prevents further subscriptions. In-flight callbacks
// must cooperate with their owner's cancellation.
func (i *BaseNotifier) Close() {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	if !i.closed {
		i.closed = true
		for _, subscription := range i.observers {
			close(subscription.stop)
		}
		clear(i.observers)
	}
}
