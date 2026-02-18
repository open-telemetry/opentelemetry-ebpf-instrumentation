/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.util;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

public class CappedConcurrentHashMap<K, V> {
  private final int capacity;
  private final ConcurrentHashMap<K, V> map;
  private final ConcurrentLinkedQueue<K> queue;

  public CappedConcurrentHashMap(int capacity) {
    if (capacity <= 0) throw new IllegalArgumentException("capacity must be > 0");
    this.capacity = capacity;
    this.map = new ConcurrentHashMap<>();
    this.queue = new ConcurrentLinkedQueue<>();
  }

  /**
   * Put a value. If key is new, it becomes the newest element; if capacity exceeded, oldest
   * elements will be evicted (best-effort).
   *
   * <p>Returns the previous value or null if none.
   */
  public V put(K key, V value) {
    if (key == null || value == null) {
      return null;
    }

    V previous = map.put(key, value);

    // If it was absent before (previous == null) record insertion order.
    if (previous == null) {
      queue.add(key);
      evictIfNeeded();
    }
    // If key existed, we replaced value and keep original insertion order.
    return previous;
  }

  public V get(K key) {
    return map.get(key);
  }

  public V remove(K key) {
    // we don't eagerly evict on remove
    return map.remove(key);
  }

  public boolean containsKey(K key) {
    return map.containsKey(key);
  }

  public int size() {
    return map.size();
  }

  private void evictIfNeeded() {
    // Best-effort eviction loop: removes oldest entries until size <= capacity.
    // Because operations are concurrent, map.size() is not a lock; we might overshoot briefly.
    while (map.size() > capacity) {
      K oldest = queue.poll();
      if (oldest == null) break; // nothing to evict
      map.remove(oldest);
      // continue while loop until size <= capacity or queue exhausted
    }
  }
}
