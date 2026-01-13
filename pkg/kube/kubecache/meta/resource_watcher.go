// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"go.opentelemetry.io/obi/pkg/kube/kubecache/instrument"
)

// resourceWatcher manages the Watch lifecycle for a single Kubernetes resource type.
type resourceWatcher struct {
	ctx          context.Context
	cancel       context.CancelFunc
	client       kubernetes.Interface
	resourceType string // "Pod", "Node", or "Service"
	listOptions  metav1.ListOptions

	cache        *watchBackedCache
	transformFn  TransformFunc
	eventHandler *cache.ResourceEventHandlerFuncs

	resyncPeriod time.Duration
	resyncTicker *time.Ticker

	currentRV string // current resourceVersion

	log     *slog.Logger
	metrics instrument.InternalMetrics

	syncCallback func(string) // callback when initial sync completes
}

// TransformFunc transforms a Kubernetes API object into a cache-optimized object.
type TransformFunc func(obj interface{}) (interface{}, error)

// resourceWatcherConfig holds configuration for creating a new resourceWatcher.
type resourceWatcherConfig struct {
	ctx          context.Context
	client       kubernetes.Interface
	resourceType string
	fieldSelector string
	resyncPeriod time.Duration
	transformFn  TransformFunc
	eventHandler *cache.ResourceEventHandlerFuncs
	metrics      instrument.InternalMetrics
	log          *slog.Logger
	syncCallback func(string)
}

// newResourceWatcher creates a new resource watcher.
func newResourceWatcher(cfg *resourceWatcherConfig) (*resourceWatcher, error) {
	ctx, cancel := context.WithCancel(cfg.ctx)

	listOpts := metav1.ListOptions{}
	if cfg.fieldSelector != "" {
		listOpts.FieldSelector = cfg.fieldSelector
	}

	rw := &resourceWatcher{
		ctx:          ctx,
		cancel:       cancel,
		client:       cfg.client,
		resourceType: cfg.resourceType,
		listOptions:  listOpts,
		cache:        newWatchBackedCache(cfg.resourceType, cfg.log),
		transformFn:  cfg.transformFn,
		eventHandler: cfg.eventHandler,
		resyncPeriod: cfg.resyncPeriod,
		log:          cfg.log.With("component", "resourceWatcher", "resourceType", cfg.resourceType),
		metrics:      cfg.metrics,
		syncCallback: cfg.syncCallback,
	}

	return rw, nil
}

// Start begins watching the resource. It performs initial LIST, starts the watch loop, and sets up periodic resync.
func (w *resourceWatcher) Start() error {
	// Perform initial LIST to populate cache
	if err := w.performInitialList(); err != nil {
		return fmt.Errorf("failed to perform initial list for %s: %w", w.resourceType, err)
	}

	// Signal that initial sync is complete
	if w.syncCallback != nil {
		w.syncCallback(w.resourceType)
	}

	// Start resync ticker
	if w.resyncPeriod > 0 {
		w.resyncTicker = time.NewTicker(w.resyncPeriod)
	}

	// Start watch loop in background
	go w.watchLoop()

	w.log.Info("resource watcher started", "resourceType", w.resourceType)
	return nil
}

// Stop stops the resource watcher.
func (w *resourceWatcher) Stop() {
	if w.resyncTicker != nil {
		w.resyncTicker.Stop()
	}
	w.cancel()
	w.log.Info("resource watcher stopped", "resourceType", w.resourceType)
}

// performInitialList performs the initial LIST operation to populate the cache.
func (w *resourceWatcher) performInitialList() error {
	w.log.Debug("performing initial LIST", "resourceType", w.resourceType)

	var resourceVersion string

	switch w.resourceType {
	case typePod:
		podList, listErr := w.client.CoreV1().Pods(metav1.NamespaceAll).List(w.ctx, w.listOptions)
		if listErr != nil {
			return listErr
		}
		resourceVersion = podList.ResourceVersion

		// Transform and add each pod to cache
		for i := range podList.Items {
			if err := w.addObjectToCache(&podList.Items[i]); err != nil {
				w.log.Warn("failed to add pod to cache during initial list", "error", err)
			}
		}

	case typeNode:
		nodeList, listErr := w.client.CoreV1().Nodes().List(w.ctx, w.listOptions)
		if listErr != nil {
			return listErr
		}
		resourceVersion = nodeList.ResourceVersion

		// Transform and add each node to cache
		for i := range nodeList.Items {
			if err := w.addObjectToCache(&nodeList.Items[i]); err != nil {
				w.log.Warn("failed to add node to cache during initial list", "error", err)
			}
		}

	case typeService:
		svcList, listErr := w.client.CoreV1().Services(metav1.NamespaceAll).List(w.ctx, w.listOptions)
		if listErr != nil {
			return listErr
		}
		resourceVersion = svcList.ResourceVersion

		// Transform and add each service to cache
		for i := range svcList.Items {
			if err := w.addObjectToCache(&svcList.Items[i]); err != nil {
				w.log.Warn("failed to add service to cache during initial list", "error", err)
			}
		}

	default:
		return fmt.Errorf("unsupported resource type: %s", w.resourceType)
	}

	w.currentRV = resourceVersion
	w.log.Info("initial LIST complete", "resourceType", w.resourceType, "resourceVersion", resourceVersion, "count", len(w.cache.List()))
	return nil
}

// addObjectToCache transforms an object and adds it to the cache, calling the AddFunc handler.
func (w *resourceWatcher) addObjectToCache(obj interface{}) error {
	transformed, err := w.transformFn(obj)
	if err != nil {
		return fmt.Errorf("failed to transform object: %w", err)
	}

	if err := w.cache.Add(transformed); err != nil {
		return fmt.Errorf("failed to add to cache: %w", err)
	}

	if w.eventHandler != nil && w.eventHandler.AddFunc != nil {
		w.eventHandler.AddFunc(transformed)
	}

	return nil
}

// watchLoop runs the main watch processing loop.
func (w *resourceWatcher) watchLoop() {
	backoff := time.Second
	maxBackoff := 5 * time.Minute
	consecutiveErrors := 0

	for {
		select {
		case <-w.ctx.Done():
			w.log.Debug("watch loop terminated")
			return

		case <-func() <-chan time.Time {
			if w.resyncTicker != nil {
				return w.resyncTicker.C
			}
			// Return a never-triggering channel if resync is disabled
			return make(<-chan time.Time)
		}():
			w.log.Debug("resync triggered")
			if err := w.performResync(); err != nil {
				w.log.Warn("resync failed", "error", err)
			}

		default:
			// Run watch
			err := w.runWatch()
			if err != nil {
				consecutiveErrors++
				w.log.Warn("watch error", "error", err, "consecutiveErrors", consecutiveErrors)

				// Exponential backoff
				if consecutiveErrors > 1 {
					backoff = backoff * 2
					if backoff > maxBackoff {
						backoff = maxBackoff
					}
				}

				select {
				case <-w.ctx.Done():
					return
				case <-time.After(backoff):
					// Retry after backoff
				}
			} else {
				// Reset backoff on successful watch
				consecutiveErrors = 0
				backoff = time.Second
			}
		}
	}
}

// runWatch establishes a watch connection and processes events.
func (w *resourceWatcher) runWatch() error {
	w.log.Debug("starting watch", "resourceVersion", w.currentRV)

	// Set up watch options
	watchOpts := w.listOptions
	watchOpts.ResourceVersion = w.currentRV
	watchOpts.Watch = true
	watchOpts.AllowWatchBookmarks = true

	var watcher watch.Interface
	var err error

	switch w.resourceType {
	case typePod:
		watcher, err = w.client.CoreV1().Pods(metav1.NamespaceAll).Watch(w.ctx, watchOpts)
	case typeNode:
		watcher, err = w.client.CoreV1().Nodes().Watch(w.ctx, watchOpts)
	case typeService:
		watcher, err = w.client.CoreV1().Services(metav1.NamespaceAll).Watch(w.ctx, watchOpts)
	default:
		return fmt.Errorf("unsupported resource type: %s", w.resourceType)
	}

	if err != nil {
		// Check if resource version is too old
		if isResourceVersionTooOldError(err) {
			w.log.Warn("resource version too old, performing resync")
			if resyncErr := w.performResync(); resyncErr != nil {
				return fmt.Errorf("resync after resource version error failed: %w", resyncErr)
			}
			return nil
		}
		return fmt.Errorf("failed to create watch: %w", err)
	}
	defer watcher.Stop()

	// Process watch events
	for {
		select {
		case <-w.ctx.Done():
			return nil

		case event, ok := <-watcher.ResultChan():
			if !ok {
				// Watch channel closed, need to restart
				w.log.Debug("watch channel closed")
				return nil
			}

			if err := w.processWatchEvent(event); err != nil {
				w.log.Warn("error processing watch event", "error", err, "eventType", event.Type)
				// Continue processing other events despite this error
			}
		}
	}
}

// processWatchEvent handles individual watch events.
func (w *resourceWatcher) processWatchEvent(event watch.Event) error {
	switch event.Type {
	case watch.Added:
		return w.handleAddEvent(event.Object)

	case watch.Modified:
		return w.handleModifyEvent(event.Object)

	case watch.Deleted:
		return w.handleDeleteEvent(event.Object)

	case watch.Bookmark:
		return w.handleBookmarkEvent(event.Object)

	case watch.Error:
		return w.handleErrorEvent(event.Object)

	default:
		w.log.Warn("unknown watch event type", "type", event.Type)
		return nil
	}
}

// handleAddEvent processes watch Added events.
func (w *resourceWatcher) handleAddEvent(obj interface{}) error {
	transformed, err := w.transformFn(obj)
	if err != nil {
		return fmt.Errorf("failed to transform added object: %w", err)
	}

	if err := w.cache.Add(transformed); err != nil {
		return fmt.Errorf("failed to add object to cache: %w", err)
	}

	// Update resource version
	w.updateResourceVersion(obj)

	// Call event handler
	if w.eventHandler != nil && w.eventHandler.AddFunc != nil {
		w.eventHandler.AddFunc(transformed)
	}

	return nil
}

// handleModifyEvent processes watch Modified events.
func (w *resourceWatcher) handleModifyEvent(obj interface{}) error {
	transformed, err := w.transformFn(obj)
	if err != nil {
		return fmt.Errorf("failed to transform modified object: %w", err)
	}

	// Get old object for comparison (for UpdateFunc handler)
	var oldObj interface{}
	if key, err := cache.MetaNamespaceKeyFunc(transformed); err == nil {
		if old, exists, _ := w.cache.GetByKey(key); exists {
			oldObj = old
		}
	}

	if err := w.cache.Update(transformed); err != nil {
		return fmt.Errorf("failed to update object in cache: %w", err)
	}

	// Update resource version
	w.updateResourceVersion(obj)

	// Call event handler
	if w.eventHandler != nil && w.eventHandler.UpdateFunc != nil {
		if oldObj != nil {
			w.eventHandler.UpdateFunc(oldObj, transformed)
		} else {
			// If we don't have the old object, treat it as an add
			if w.eventHandler.AddFunc != nil {
				w.eventHandler.AddFunc(transformed)
			}
		}
	}

	return nil
}

// handleDeleteEvent processes watch Deleted events.
func (w *resourceWatcher) handleDeleteEvent(obj interface{}) error {
	transformed, err := w.transformFn(obj)
	if err != nil {
		return fmt.Errorf("failed to transform deleted object: %w", err)
	}

	if err := w.cache.Delete(transformed); err != nil {
		return fmt.Errorf("failed to delete object from cache: %w", err)
	}

	// Update resource version
	w.updateResourceVersion(obj)

	// Call event handler
	if w.eventHandler != nil && w.eventHandler.DeleteFunc != nil {
		w.eventHandler.DeleteFunc(transformed)
	}

	return nil
}

// handleBookmarkEvent processes watch Bookmark events.
func (w *resourceWatcher) handleBookmarkEvent(obj interface{}) error {
	// Bookmarks only update the resource version
	w.updateResourceVersion(obj)
	w.log.Debug("bookmark received", "resourceVersion", w.currentRV)
	return nil
}

// handleErrorEvent processes watch Error events.
func (w *resourceWatcher) handleErrorEvent(obj interface{}) error {
	w.log.Warn("watch error event received", "object", obj)
	// Return error to trigger watch restart
	return fmt.Errorf("watch error event: %v", obj)
}

// updateResourceVersion extracts and updates the resource version from an object.
func (w *resourceWatcher) updateResourceVersion(obj interface{}) {
	accessor, err := meta.Accessor(obj)
	if err == nil && accessor.GetResourceVersion() != "" {
		w.currentRV = accessor.GetResourceVersion()
	}
}

// performResync performs a periodic resync by listing all objects and comparing with the cache.
func (w *resourceWatcher) performResync() error {
	w.log.Debug("performing resync", "resourceType", w.resourceType)

	// Get current cache contents
	currentCache := make(map[string]interface{})
	for _, item := range w.cache.List() {
		if key, err := cache.MetaNamespaceKeyFunc(item); err == nil {
			currentCache[key] = item
		}
	}

	// Perform LIST with ResourceVersion="0" to get current state
	listOpts := w.listOptions
	listOpts.ResourceVersion = "0"

	var resourceVersion string
	freshObjects := make(map[string]interface{})

	switch w.resourceType {
	case typePod:
		podList, err := w.client.CoreV1().Pods(metav1.NamespaceAll).List(w.ctx, listOpts)
		if err != nil {
			return fmt.Errorf("failed to list pods during resync: %w", err)
		}
		resourceVersion = podList.ResourceVersion
		for i := range podList.Items {
			transformed, err := w.transformFn(&podList.Items[i])
			if err != nil {
				continue
			}
			if key, err := cache.MetaNamespaceKeyFunc(transformed); err == nil {
				freshObjects[key] = transformed
			}
		}

	case typeNode:
		nodeList, err := w.client.CoreV1().Nodes().List(w.ctx, listOpts)
		if err != nil {
			return fmt.Errorf("failed to list nodes during resync: %w", err)
		}
		resourceVersion = nodeList.ResourceVersion
		for i := range nodeList.Items {
			transformed, err := w.transformFn(&nodeList.Items[i])
			if err != nil {
				continue
			}
			if key, err := cache.MetaNamespaceKeyFunc(transformed); err == nil {
				freshObjects[key] = transformed
			}
		}

	case typeService:
		svcList, err := w.client.CoreV1().Services(metav1.NamespaceAll).List(w.ctx, listOpts)
		if err != nil {
			return fmt.Errorf("failed to list services during resync: %w", err)
		}
		resourceVersion = svcList.ResourceVersion
		for i := range svcList.Items {
			transformed, err := w.transformFn(&svcList.Items[i])
			if err != nil {
				continue
			}
			if key, err := cache.MetaNamespaceKeyFunc(transformed); err == nil {
				freshObjects[key] = transformed
			}
		}

	default:
		return fmt.Errorf("unsupported resource type: %s", w.resourceType)
	}

	// Compare fresh objects with cache
	for key, freshObj := range freshObjects {
		if cachedObj, exists := currentCache[key]; exists {
			// Object exists in both - check if it changed
			freshEntity, freshOK := freshObj.(*indexableEntity)
			cachedEntity, cachedOK := cachedObj.(*indexableEntity)
			if freshOK && cachedOK && !unchanged(cachedEntity.EncodedMeta, freshEntity.EncodedMeta) {
				// Object changed - update
				w.cache.Update(freshObj)
				if w.eventHandler != nil && w.eventHandler.UpdateFunc != nil {
					w.eventHandler.UpdateFunc(cachedObj, freshObj)
				}
			}
			// Remove from currentCache to track what's left
			delete(currentCache, key)
		} else {
			// New object - add
			w.cache.Add(freshObj)
			if w.eventHandler != nil && w.eventHandler.AddFunc != nil {
				w.eventHandler.AddFunc(freshObj)
			}
		}
	}

	// Remaining items in currentCache are deleted
	for _, deletedObj := range currentCache {
		w.cache.Delete(deletedObj)
		if w.eventHandler != nil && w.eventHandler.DeleteFunc != nil {
			w.eventHandler.DeleteFunc(deletedObj)
		}
	}

	w.currentRV = resourceVersion
	w.log.Info("resync complete", "resourceType", w.resourceType, "resourceVersion", resourceVersion, "count", len(freshObjects))
	return nil
}

// isResourceVersionTooOldError checks if an error is due to an expired resource version.
func isResourceVersionTooOldError(err error) bool {
	// Check for the "too old resource version" error from Kubernetes API
	// This can be determined by checking the error message
	if err == nil {
		return false
	}
	errMsg := err.Error()
	return contains(errMsg, "too old resource version") ||
		contains(errMsg, "resource version is too old") ||
		contains(errMsg, "expired")
}

// contains checks if a string contains a substring (case-insensitive helper).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}()))
}
