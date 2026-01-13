// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/instrument"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/meta/cni"
)

// watchManager manages multiple resourceWatcher instances and coordinates their synchronization.
type watchManager struct {
	ctx    context.Context
	cancel context.CancelFunc
	client kubernetes.Interface
	config *informersConfig

	podWatcher     *resourceWatcher
	nodeWatcher    *resourceWatcher
	serviceWatcher *resourceWatcher

	syncedMu    sync.Mutex
	syncedTypes map[string]bool // tracks which resources have completed initial sync
	waitForSync chan struct{}   // closed when all watchers are synced

	log     *slog.Logger
	metrics instrument.InternalMetrics
}

// newWatchManager creates a new watch manager.
func newWatchManager(ctx context.Context, config *informersConfig, client kubernetes.Interface, metrics instrument.InternalMetrics, log *slog.Logger) (*watchManager, error) {
	ctx, cancel := context.WithCancel(ctx)

	wm := &watchManager{
		ctx:         ctx,
		cancel:      cancel,
		client:      client,
		config:      config,
		syncedTypes: make(map[string]bool),
		waitForSync: make(chan struct{}),
		log:         log.With("component", "watchManager"),
		metrics:     metrics,
	}

	return wm, nil
}

// Start initializes and starts all resource watchers based on configuration.
func (wm *watchManager) Start(inf *Informers) error {
	wm.log.Debug("starting watch manager")

	expectedSyncs := 0

	// Create and start pod watcher
	if err := wm.startPodWatcher(inf); err != nil {
		return fmt.Errorf("failed to start pod watcher: %w", err)
	}
	expectedSyncs++

	// Create and start node watcher if not disabled
	if !wm.config.disableNodes {
		if err := wm.startNodeWatcher(inf); err != nil {
			return fmt.Errorf("failed to start node watcher: %w", err)
		}
		expectedSyncs++
	}

	// Create and start service watcher if not disabled
	if !wm.config.disableServices {
		if err := wm.startServiceWatcher(inf); err != nil {
			return fmt.Errorf("failed to start service watcher: %w", err)
		}
		expectedSyncs++
	}

	// Wait for all watchers to complete initial sync
	go func() {
		for {
			wm.syncedMu.Lock()
			syncedCount := len(wm.syncedTypes)
			wm.syncedMu.Unlock()

			if syncedCount >= expectedSyncs {
				wm.log.Info("all resource watchers synced", "count", syncedCount)
				close(wm.waitForSync)
				return
			}

			// Check every 100ms
			select {
			case <-wm.ctx.Done():
				return
			case <-func() <-chan struct{} {
				ch := make(chan struct{})
				go func() {
					<-wm.ctx.Done()
					close(ch)
				}()
				return ch
			}():
				return
			default:
				// Small sleep to avoid busy-waiting
				select {
				case <-wm.ctx.Done():
					return
				default:
				}
			}
		}
	}()

	wm.log.Info("watch manager started")
	return nil
}

// Stop stops all resource watchers.
func (wm *watchManager) Stop() {
	wm.log.Debug("stopping watch manager")

	if wm.podWatcher != nil {
		wm.podWatcher.Stop()
	}
	if wm.nodeWatcher != nil {
		wm.nodeWatcher.Stop()
	}
	if wm.serviceWatcher != nil {
		wm.serviceWatcher.Stop()
	}

	wm.cancel()
	wm.log.Info("watch manager stopped")
}

// markSynced marks a resource type as synced.
func (wm *watchManager) markSynced(resourceType string) {
	wm.syncedMu.Lock()
	defer wm.syncedMu.Unlock()

	wm.syncedTypes[resourceType] = true
	wm.log.Debug("resource type synced", "resourceType", resourceType, "totalSynced", len(wm.syncedTypes))
}

// startPodWatcher creates and starts the pod watcher.
func (wm *watchManager) startPodWatcher(inf *Informers) error {
	fieldSelector := ""
	if wm.config.restrictNode != "" {
		fieldSelector = fields.Set{"spec.nodeName": wm.config.restrictNode}.String()
	}

	// Wrap podToIndexableEntity to match TransformFunc signature
	podTransform := func(obj interface{}) (interface{}, error) {
		pod, ok := obj.(*v1.Pod)
		if !ok {
			// Handle already transformed objects
			if ie, ok := obj.(*indexableEntity); ok {
				return ie, nil
			}
			// Handle stale objects
			if stale, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				return stale, nil
			}
			return nil, fmt.Errorf("expected *v1.Pod, got %T", obj)
		}
		return inf.podToIndexableEntity(pod)
	}

	cfg := &resourceWatcherConfig{
		ctx:           wm.ctx,
		client:        wm.client,
		resourceType:  typePod,
		fieldSelector: fieldSelector,
		resyncPeriod:  wm.config.resyncPeriod,
		transformFn:   podTransform,
		eventHandler:  inf.ipInfoEventHandler(wm.ctx),
		metrics:       wm.metrics,
		log:           wm.log,
		syncCallback:  wm.markSynced,
	}

	watcher, err := newResourceWatcher(cfg)
	if err != nil {
		return err
	}

	if err := watcher.Start(); err != nil {
		return err
	}

	wm.podWatcher = watcher
	wm.log.Debug("pod watcher started")
	return nil
}

// startNodeWatcher creates and starts the node watcher.
func (wm *watchManager) startNodeWatcher(inf *Informers) error {
	fieldSelector := ""
	if wm.config.restrictNode != "" {
		fieldSelector = fields.Set{"metadata.name": wm.config.restrictNode}.String()
	}

	// Transform function for nodes
	nodeTransform := func(obj interface{}) (interface{}, error) {
		node, ok := obj.(*v1.Node)
		if !ok {
			// Handle already transformed objects
			if ie, ok := obj.(*indexableEntity); ok {
				return ie, nil
			}
			// Handle stale objects
			if stale, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				return stale, nil
			}
			return nil, fmt.Errorf("expected *v1.Node, got %T", obj)
		}

		// Extract IPs from node addresses
		ips := make([]string, 0, len(node.Status.Addresses))
		for _, address := range node.Status.Addresses {
			ip := net.ParseIP(address.Address)
			if ip != nil {
				ips = append(ips, ip.String())
			}
		}

		// Add CNI-specific IPs
		ips = cni.AddOvnIPs(ips, node)

		return &indexableEntity{
			ObjectMeta: minimalIndex(&node.ObjectMeta),
			EncodedMeta: &informer.ObjectMeta{
				Name:            node.Name,
				Namespace:       node.Namespace,
				Labels:          node.Labels,
				Ips:             ips,
				Kind:            typeNode,
				StatusTimeEpoch: objLastUpdateTime(&node.ObjectMeta, nil, node.Status.Conditions),
			},
		}, nil
	}

	cfg := &resourceWatcherConfig{
		ctx:           wm.ctx,
		client:        wm.client,
		resourceType:  typeNode,
		fieldSelector: fieldSelector,
		resyncPeriod:  wm.config.resyncPeriod,
		transformFn:   nodeTransform,
		eventHandler:  inf.ipInfoEventHandler(wm.ctx),
		metrics:       wm.metrics,
		log:           wm.log,
		syncCallback:  wm.markSynced,
	}

	watcher, err := newResourceWatcher(cfg)
	if err != nil {
		return err
	}

	if err := watcher.Start(); err != nil {
		return err
	}

	wm.nodeWatcher = watcher
	wm.log.Debug("node watcher started")
	return nil
}

// startServiceWatcher creates and starts the service watcher.
func (wm *watchManager) startServiceWatcher(inf *Informers) error {
	// Services are never filtered by node

	// Transform function for services
	serviceTransform := func(obj interface{}) (interface{}, error) {
		svc, ok := obj.(*v1.Service)
		if !ok {
			// Handle already transformed objects
			if ie, ok := obj.(*indexableEntity); ok {
				return ie, nil
			}
			// Handle stale objects
			if stale, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				return stale, nil
			}
			return nil, fmt.Errorf("expected *v1.Service, got %T", obj)
		}

		var ips []string
		if svc.Spec.ClusterIP != v1.ClusterIPNone {
			ips = svc.Spec.ClusterIPs
		}

		return &indexableEntity{
			ObjectMeta: minimalIndex(&svc.ObjectMeta),
			EncodedMeta: &informer.ObjectMeta{
				Name:            svc.Name,
				Namespace:       svc.Namespace,
				Labels:          svc.Labels,
				Ips:             ips,
				Kind:            typeService,
				StatusTimeEpoch: objLastUpdateTime(&svc.ObjectMeta, nil, nil),
			},
		}, nil
	}

	cfg := &resourceWatcherConfig{
		ctx:           wm.ctx,
		client:        wm.client,
		resourceType:  typeService,
		fieldSelector: "", // No field selector for services
		resyncPeriod:  wm.config.resyncPeriod,
		transformFn:   serviceTransform,
		eventHandler:  inf.ipInfoEventHandler(wm.ctx),
		metrics:       wm.metrics,
		log:           wm.log,
		syncCallback:  wm.markSynced,
	}

	watcher, err := newResourceWatcher(cfg)
	if err != nil {
		return err
	}

	if err := watcher.Start(); err != nil {
		return err
	}

	wm.serviceWatcher = watcher
	wm.log.Debug("service watcher started")
	return nil
}
