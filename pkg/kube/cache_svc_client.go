// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kube // import "go.opentelemetry.io/obi/pkg/kube"

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/meta"
)

func cslog() *slog.Logger {
	return slog.With("component", "kube.CacheSvcClient")
}

const defaultReconnectInitialInterval = 5 * time.Second

type cacheSvcClient struct {
	meta.BaseNotifier
	address string
	log     *slog.Logger

	lastEventTSEpoch         int64
	ctx                      context.Context
	syncTimeout              time.Duration
	waitForSubscription      chan struct{}
	waitForSubscriptionOnce  sync.Once
	waitForSynchronization   chan struct{}
	waitForSyncClosed        bool
	reconnectInitialInterval time.Duration

	metadataMutex sync.RWMutex
	metadata      map[qualifiedName]*informer.ObjectMeta
	synchronized  bool
}

func (sc *cacheSvcClient) Start(ctx context.Context) {
	sc.log = cslog()
	sc.waitForSubscription = make(chan struct{})
	sc.waitForSynchronization = make(chan struct{})
	sc.ctx = ctx
	sc.reconnectInitialInterval = normalizeReconnectInitialInterval(sc.reconnectInitialInterval)

	go func() {
		select {
		case <-ctx.Done():
			sc.log.Debug("context done, stopping client")
			return
		case <-sc.waitForSubscription:
			sc.log.Debug("subscriptor attached, start connection to K8s cache service")
		}

		for {
			select {
			case <-ctx.Done():
				sc.log.Debug("context done, stopping client")
				return
			default:
				// TODO: reconnection should include a timestamp
				// with the last received event, to avoid unnecessarily
				// receiving the whole metadata snapshot on each reconnection
				err := sc.connect(ctx)
				sc.log.Info("K8s cache service connection lost. Reconnecting...", "error", err)
				// TODO: exponential backoff
				time.Sleep(sc.reconnectInitialInterval)
			}
		}
	}()
}

func normalizeReconnectInitialInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return defaultReconnectInitialInterval
	}

	return interval
}

func (sc *cacheSvcClient) connect(ctx context.Context) error {
	// Set up a connection to the server.
	conn, err := grpc.NewClient(sc.address,
		// TODO: allow configuring the transport credentials
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("did not connect: %w", err)
	}
	defer conn.Close()

	client := informer.NewEventStreamServiceClient(conn)

	// Subscribe to the event stream.
	stream, err := client.Subscribe(ctx, &informer.SubscribeMessage{
		FromTimestampEpoch: sc.lastEventTSEpoch,
	})
	if err != nil {
		return fmt.Errorf("could not subscribe: %w", err)
	}

	// Receive and print messages.
	for {
		event, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("error receiving message: %w", err)
		}
		sc.recordEvent(event)
		if event.GetType() == informer.EventType_SYNC_FINISHED {
			sc.NotifyAndWait(event)
			// send a notification about the client being synced with the K8s metadata service
			// so OBI can start processing/decorating the received flows and traces
			if !sc.waitForSyncClosed {
				close(sc.waitForSynchronization)
				sc.waitForSyncClosed = true
			}
			continue
		}

		// we can safely assume that server-side events are ordered by timestamp
		if event.Resource != nil {
			sc.lastEventTSEpoch = event.Resource.StatusTimeEpoch
		}
		sc.Notify(event)
	}
}

func (sc *cacheSvcClient) Subscribe(observer meta.Observer) {
	sc.SubscribeWithSnapshot(observer, sc.snapshot)

	sc.waitForSubscriptionOnce.Do(func() { close(sc.waitForSubscription) })

	// after the subscription is done, we temporarily pause the execution until the
	// cache is fully loaded
	sc.log.Info("waiting for K8s metadata synchronization", "timeout", sc.syncTimeout)
	select {
	case <-sc.waitForSynchronization:
		sc.log.Debug("K8s metadata cache service synchronized")
	case <-sc.ctx.Done():
		sc.log.Debug("context done. Nothing to do")
	case <-time.After(sc.syncTimeout):
		sc.log.Warn("timed out while waiting for K8s metadata synchronization." +
			" Processes running in containers are not instrumented until their Pod is known." +
			" If this is expected due to the size of your cluster, you might want to increase the timeout via" +
			" the OTEL_EBPF_KUBE_INFORMERS_SYNC_TIMEOUT configuration option")
	}
}

func (sc *cacheSvcClient) recordEvent(event *informer.Event) {
	sc.metadataMutex.Lock()
	defer sc.metadataMutex.Unlock()

	if event.GetType() == informer.EventType_SYNC_FINISHED {
		sc.synchronized = true
		return
	}
	resource := event.GetResource()
	if resource == nil {
		return
	}
	if sc.metadata == nil {
		sc.metadata = map[qualifiedName]*informer.ObjectMeta{}
	}
	if event.GetType() == informer.EventType_DELETED {
		delete(sc.metadata, qName(resource))
	} else {
		sc.metadata[qName(resource)] = resource
	}
}

func (sc *cacheSvcClient) snapshot() []*informer.Event {
	sc.metadataMutex.RLock()
	defer sc.metadataMutex.RUnlock()

	events := make([]*informer.Event, 0, len(sc.metadata)+1)
	for _, resource := range sc.metadata {
		events = append(events, &informer.Event{Type: informer.EventType_CREATED, Resource: resource})
	}
	if sc.synchronized {
		events = append(events, &informer.Event{Type: informer.EventType_SYNC_FINISHED})
	}
	return events
}
