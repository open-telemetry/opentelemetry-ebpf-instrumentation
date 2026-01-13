// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta

import (
	"fmt"
	"log/slog"
	"sync"

	"k8s.io/client-go/tools/cache"
)

// watchBackedCache implements cache.Store interface with thread-safe in-memory storage.
// This cache is used by resourceWatcher to store transformed Kubernetes objects.
type watchBackedCache struct {
	mu           sync.RWMutex
	items        map[string]interface{} // key = namespace/name
	keyFunc      cache.KeyFunc
	resourceType string
	log          *slog.Logger
}

// newWatchBackedCache creates a new cache instance for a specific resource type.
func newWatchBackedCache(resourceType string, log *slog.Logger) *watchBackedCache {
	return &watchBackedCache{
		items:        make(map[string]interface{}),
		keyFunc:      cache.MetaNamespaceKeyFunc,
		resourceType: resourceType,
		log:          log.With("component", "watchBackedCache", "resourceType", resourceType),
	}
}

// Add inserts an item into the cache.
func (c *watchBackedCache) Add(obj interface{}) error {
	key, err := c.keyFunc(obj)
	if err != nil {
		return fmt.Errorf("failed to get key for object: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = obj
	c.log.Debug("added object to cache", "key", key)
	return nil
}

// Update modifies an existing item in the cache or adds it if it doesn't exist.
func (c *watchBackedCache) Update(obj interface{}) error {
	key, err := c.keyFunc(obj)
	if err != nil {
		return fmt.Errorf("failed to get key for object: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = obj
	c.log.Debug("updated object in cache", "key", key)
	return nil
}

// Delete removes an item from the cache.
func (c *watchBackedCache) Delete(obj interface{}) error {
	key, err := c.keyFunc(obj)
	if err != nil {
		return fmt.Errorf("failed to get key for object: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.items, key)
	c.log.Debug("deleted object from cache", "key", key)
	return nil
}

// List returns all items currently in the cache.
func (c *watchBackedCache) List() []interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	list := make([]interface{}, 0, len(c.items))
	for _, item := range c.items {
		list = append(list, item)
	}
	return list
}

// ListKeys returns all keys of items currently in the cache.
func (c *watchBackedCache) ListKeys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.items))
	for key := range c.items {
		keys = append(keys, key)
	}
	return keys
}

// Get returns the requested item if it exists in the cache.
func (c *watchBackedCache) Get(obj interface{}) (item interface{}, exists bool, err error) {
	key, err := c.keyFunc(obj)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get key for object: %w", err)
	}
	return c.GetByKey(key)
}

// GetByKey returns the requested item by key if it exists in the cache.
func (c *watchBackedCache) GetByKey(key string) (item interface{}, exists bool, err error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, exists = c.items[key]
	return item, exists, nil
}

// Replace replaces the cache contents with the given list of objects.
// This is typically used during resync operations.
func (c *watchBackedCache) Replace(list []interface{}, resourceVersion string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Clear existing items
	c.items = make(map[string]interface{}, len(list))

	// Add all items from the list
	for _, item := range list {
		key, err := c.keyFunc(item)
		if err != nil {
			return fmt.Errorf("failed to get key for object during replace: %w", err)
		}
		c.items[key] = item
	}

	c.log.Debug("replaced cache contents", "count", len(list), "resourceVersion", resourceVersion)
	return nil
}

// Resync is a no-op for this cache implementation as resync is handled by resourceWatcher.
func (c *watchBackedCache) Resync() error {
	// Resync logic is handled by the resourceWatcher, not the cache itself
	return nil
}
