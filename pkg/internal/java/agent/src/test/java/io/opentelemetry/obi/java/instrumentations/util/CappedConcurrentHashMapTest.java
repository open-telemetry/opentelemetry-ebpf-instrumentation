/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.util;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class CappedConcurrentHashMapTest {

  @Test
  void testConstructor_ValidCapacity() {
    CappedConcurrentHashMap<String, String> map = new CappedConcurrentHashMap<>(10);
    assertNotNull(map);
    assertEquals(0, map.size());
  }

  @Test
  void testConstructor_InvalidCapacity_Zero() {
    IllegalArgumentException exception =
        assertThrows(IllegalArgumentException.class, () -> new CappedConcurrentHashMap<>(0));
    assertEquals("capacity must be > 0", exception.getMessage());
  }

  @Test
  void testConstructor_InvalidCapacity_Negative() {
    IllegalArgumentException exception =
        assertThrows(IllegalArgumentException.class, () -> new CappedConcurrentHashMap<>(-1));
    assertEquals("capacity must be > 0", exception.getMessage());
  }

  @Test
  void testPut_NullKey() {
    CappedConcurrentHashMap<String, String> map = new CappedConcurrentHashMap<>(5);
    assertNull(map.put(null, "value"));
  }

  @Test
  void testPut_NullValue() {
    CappedConcurrentHashMap<String, String> map = new CappedConcurrentHashMap<>(5);
    assertNull(map.put("key", null));
  }

  @Test
  void testPut_SingleElement() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(5);
    Integer previous = map.put("key1", 100);
    assertNull(previous);
    assertEquals(1, map.size());
    assertEquals(100, map.get("key1"));
  }

  @Test
  void testPut_ReplaceExistingKey() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(5);
    map.put("key1", 100);
    Integer previous = map.put("key1", 200);
    assertEquals(100, previous);
    assertEquals(1, map.size());
    assertEquals(200, map.get("key1"));
  }

  @Test
  void testPut_MultipleElements_WithinCapacity() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(5);
    for (int i = 0; i < 5; i++) {
      map.put("key" + i, i);
    }
    assertEquals(5, map.size());
    for (int i = 0; i < 5; i++) {
      assertEquals(i, map.get("key" + i));
    }
  }

  @Test
  void testPut_ExceedsCapacity_EvictsOldest() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(3);

    // Add 3 elements (at capacity)
    map.put("key1", 1);
    map.put("key2", 2);
    map.put("key3", 3);
    assertEquals(3, map.size());

    // Add 4th element - should evict key1
    map.put("key4", 4);
    assertEquals(3, map.size());
    assertFalse(map.containsKey("key1"));
    assertTrue(map.containsKey("key2"));
    assertTrue(map.containsKey("key3"));
    assertTrue(map.containsKey("key4"));
  }

  @Test
  void testPut_ExceedsCapacity_MultipleEvictions() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(3);

    // Add 6 elements - should maintain max 3
    for (int i = 1; i <= 6; i++) {
      map.put("key" + i, i);
    }

    assertEquals(3, map.size());
    // First 3 should be evicted
    assertFalse(map.containsKey("key1"));
    assertFalse(map.containsKey("key2"));
    assertFalse(map.containsKey("key3"));
    // Last 3 should remain
    assertTrue(map.containsKey("key4"));
    assertTrue(map.containsKey("key5"));
    assertTrue(map.containsKey("key6"));
  }

  @Test
  void testPut_ExceedsCapacity_CapacityOne() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(1);

    map.put("key1", 1);
    assertEquals(1, map.size());
    assertEquals(1, map.get("key1"));

    map.put("key2", 2);
    assertEquals(1, map.size());
    assertFalse(map.containsKey("key1"));
    assertTrue(map.containsKey("key2"));

    map.put("key3", 3);
    assertEquals(1, map.size());
    assertFalse(map.containsKey("key2"));
    assertTrue(map.containsKey("key3"));
  }

  @Test
  void testPut_ReplaceExisting_NoEviction() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(3);

    map.put("key1", 1);
    map.put("key2", 2);
    map.put("key3", 3);
    assertEquals(3, map.size());

    // Replace key2 - should not trigger eviction
    map.put("key2", 20);
    assertEquals(3, map.size());
    assertTrue(map.containsKey("key1"));
    assertTrue(map.containsKey("key2"));
    assertTrue(map.containsKey("key3"));
    assertEquals(20, map.get("key2"));
  }

  @Test
  void testGet_ExistingKey() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(5);
    map.put("key1", 100);
    assertEquals(100, map.get("key1"));
  }

  @Test
  void testGet_NonExistingKey() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(5);
    assertNull(map.get("nonexistent"));
  }

  @Test
  void testGet_AfterEviction() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(2);
    map.put("key1", 1);
    map.put("key2", 2);
    map.put("key3", 3); // Should evict key1

    assertNull(map.get("key1"));
    assertEquals(2, map.get("key2"));
    assertEquals(3, map.get("key3"));
  }

  @Test
  void testRemove_ExistingKey() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(5);
    map.put("key1", 100);
    Integer removed = map.remove("key1");
    assertEquals(100, removed);
    assertEquals(0, map.size());
    assertFalse(map.containsKey("key1"));
  }

  @Test
  void testRemove_NonExistingKey() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(5);
    Integer removed = map.remove("nonexistent");
    assertNull(removed);
  }

  @Test
  void testContainsKey_Existing() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(5);
    map.put("key1", 100);
    assertTrue(map.containsKey("key1"));
  }

  @Test
  void testContainsKey_NonExisting() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(5);
    assertFalse(map.containsKey("key1"));
  }

  @Test
  void testSize_Empty() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(5);
    assertEquals(0, map.size());
  }

  @Test
  void testSize_AfterAdding() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(5);
    for (int i = 0; i < 3; i++) {
      map.put("key" + i, i);
    }
    assertEquals(3, map.size());
  }

  @Test
  void testSize_AfterEviction() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(3);
    for (int i = 0; i < 10; i++) {
      map.put("key" + i, i);
    }
    assertEquals(3, map.size());
  }

  @Test
  void testSize_AfterRemoval() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(5);
    map.put("key1", 1);
    map.put("key2", 2);
    map.remove("key1");
    assertEquals(1, map.size());
  }

  @Test
  void testEviction_PreservesInsertionOrder() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(5);

    // Add elements in specific order
    for (int i = 1; i <= 5; i++) {
      map.put("key" + i, i);
    }

    // Add more elements and verify FIFO eviction
    map.put("key6", 6);
    assertFalse(map.containsKey("key1")); // Oldest evicted first

    map.put("key7", 7);
    assertFalse(map.containsKey("key2")); // Second oldest evicted

    // Remaining should be key3, key4, key5, key6, key7
    assertTrue(map.containsKey("key3"));
    assertTrue(map.containsKey("key4"));
    assertTrue(map.containsKey("key5"));
    assertTrue(map.containsKey("key6"));
    assertTrue(map.containsKey("key7"));
  }

  @Test
  void testEviction_LargeNumberOfElements() {
    CappedConcurrentHashMap<Integer, String> map = new CappedConcurrentHashMap<>(100);

    // Add 1000 elements
    for (int i = 0; i < 1000; i++) {
      map.put(i, "value" + i);
    }

    // Should maintain capacity
    assertTrue(map.size() <= 100);

    // Most recent 100 should be present
    for (int i = 900; i < 1000; i++) {
      assertTrue(map.containsKey(i), "Key " + i + " should be present");
    }

    // Oldest should be evicted
    for (int i = 0; i < 100; i++) {
      assertFalse(map.containsKey(i), "Key " + i + " should be evicted");
    }
  }

  @Test
  void testConcurrency_MultipleThreadsAdding() throws InterruptedException {
    CappedConcurrentHashMap<Integer, String> map = new CappedConcurrentHashMap<>(50);
    int numThreads = 10;
    int insertsPerThread = 100;
    ExecutorService executor = Executors.newFixedThreadPool(numThreads);
    CountDownLatch latch = new CountDownLatch(numThreads);

    for (int t = 0; t < numThreads; t++) {
      final int threadId = t;
      executor.submit(
          () -> {
            try {
              for (int i = 0; i < insertsPerThread; i++) {
                int key = threadId * insertsPerThread + i;
                map.put(key, "value" + key);
              }
            } finally {
              latch.countDown();
            }
          });
    }

    assertTrue(latch.await(10, TimeUnit.SECONDS));
    executor.shutdown();
    assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));

    // Size should not exceed capacity
    assertTrue(map.size() <= 50, "Size should not exceed capacity, was: " + map.size());
  }

  @Test
  void testConcurrency_MixedOperations() throws InterruptedException {
    CappedConcurrentHashMap<Integer, String> map = new CappedConcurrentHashMap<>(100);
    int numThreads = 5;
    ExecutorService executor = Executors.newFixedThreadPool(numThreads);
    CountDownLatch latch = new CountDownLatch(numThreads);
    AtomicInteger putCount = new AtomicInteger(0);

    for (int t = 0; t < numThreads; t++) {
      final int threadId = t;
      executor.submit(
          () -> {
            try {
              for (int i = 0; i < 50; i++) {
                int key = threadId * 1000 + i;
                map.put(key, "value" + key);
                putCount.incrementAndGet();

                if (i % 10 == 0) {
                  map.get(key);
                }

                if (i % 15 == 0) {
                  map.remove(key);
                }
              }
            } finally {
              latch.countDown();
            }
          });
    }

    assertTrue(latch.await(10, TimeUnit.SECONDS));
    executor.shutdown();
    assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));

    // Size should not exceed capacity
    assertTrue(map.size() <= 100, "Size should not exceed capacity, was: " + map.size());
  }

  @Test
  void testConcurrency_SimultaneousInsertsAtCapacity() throws InterruptedException {
    CappedConcurrentHashMap<Integer, String> map = new CappedConcurrentHashMap<>(10);
    int numThreads = 20;
    ExecutorService executor = Executors.newFixedThreadPool(numThreads);
    CountDownLatch startLatch = new CountDownLatch(1);
    CountDownLatch doneLatch = new CountDownLatch(numThreads);

    for (int t = 0; t < numThreads; t++) {
      final int threadId = t;
      executor.submit(
          () -> {
            try {
              startLatch.await(); // Wait for all threads to be ready
              map.put(threadId, "value" + threadId);
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
            } finally {
              doneLatch.countDown();
            }
          });
    }

    startLatch.countDown(); // Start all threads simultaneously
    assertTrue(doneLatch.await(10, TimeUnit.SECONDS));
    executor.shutdown();
    assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));

    // Size should not exceed capacity
    assertTrue(map.size() <= 10, "Size should not exceed capacity, was: " + map.size());
  }

  @Test
  void testOverflow_ManyRapidInserts() {
    CappedConcurrentHashMap<Integer, Integer> map = new CappedConcurrentHashMap<>(10);

    // Rapidly insert 1000 elements
    for (int i = 0; i < 1000; i++) {
      map.put(i, i);
      // Verify size never exceeds capacity by much (some tolerance for concurrency)
      assertTrue(map.size() <= 15, "Size overflow detected at iteration " + i + ": " + map.size());
    }

    // Final size should be at or below capacity
    assertTrue(map.size() <= 10, "Final size should be <= capacity, was: " + map.size());
  }

  @Test
  void testOverflow_RepeatedCapacityExceeding() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(5);

    // Exceed capacity multiple times
    for (int round = 0; round < 10; round++) {
      for (int i = 0; i < 20; i++) {
        String key = "round" + round + "_key" + i;
        map.put(key, i);
      }
      assertTrue(map.size() <= 5, "Size should stay at capacity after round " + round);
    }
  }

  @Test
  void testEviction_VerifyOnlyOldestEvicted() {
    CappedConcurrentHashMap<Integer, Integer> map = new CappedConcurrentHashMap<>(10);

    // Add 10 elements
    for (int i = 0; i < 10; i++) {
      map.put(i, i);
    }

    Set<Integer> expectedKeys = new HashSet<>();
    for (int i = 0; i < 10; i++) {
      expectedKeys.add(i);
    }

    // Verify all initial keys present
    for (Integer key : expectedKeys) {
      assertTrue(map.containsKey(key));
    }

    // Add 5 more elements - should evict 0-4
    for (int i = 10; i < 15; i++) {
      map.put(i, i);
    }

    // Keys 0-4 should be evicted
    for (int i = 0; i < 5; i++) {
      assertFalse(map.containsKey(i), "Key " + i + " should be evicted");
    }

    // Keys 5-14 should remain
    for (int i = 5; i < 15; i++) {
      assertTrue(map.containsKey(i), "Key " + i + " should be present");
    }
  }

  @Test
  void testEviction_UpdateDoesNotChangeOrder() {
    CappedConcurrentHashMap<String, Integer> map = new CappedConcurrentHashMap<>(3);

    map.put("key1", 1);
    map.put("key2", 2);
    map.put("key3", 3);

    // Update key1 - should not change its position in eviction queue
    map.put("key1", 100);

    // Add key4 - should still evict key1 (oldest insertion)
    map.put("key4", 4);

    assertFalse(map.containsKey("key1"), "key1 should be evicted despite update");
    assertTrue(map.containsKey("key2"));
    assertTrue(map.containsKey("key3"));
    assertTrue(map.containsKey("key4"));
  }

  @Test
  void testBoundary_ExactlyAtCapacity() {
    CappedConcurrentHashMap<Integer, Integer> map = new CappedConcurrentHashMap<>(10);

    // Fill to exact capacity
    for (int i = 0; i < 10; i++) {
      map.put(i, i);
    }

    assertEquals(10, map.size());

    // All keys should be present
    for (int i = 0; i < 10; i++) {
      assertTrue(map.containsKey(i));
    }

    // One more should trigger eviction
    map.put(10, 10);
    assertEquals(10, map.size());
    assertFalse(map.containsKey(0)); // First one evicted
  }

  @Test
  void testDifferentTypes_StringToObject() {
    CappedConcurrentHashMap<String, Object> map = new CappedConcurrentHashMap<>(5);

    map.put("int", 123);
    map.put("string", "hello");
    map.put("list", new ArrayList<>());
    map.put("null_would_fail", "not_null");

    assertEquals(123, map.get("int"));
    assertEquals("hello", map.get("string"));
    assertNotNull(map.get("list"));
  }

  @Test
  void testStressTest_RapidInsertRemove() {
    CappedConcurrentHashMap<Integer, Integer> map = new CappedConcurrentHashMap<>(20);

    for (int iteration = 0; iteration < 100; iteration++) {
      // Rapid inserts
      for (int i = 0; i < 50; i++) {
        map.put(iteration * 100 + i, i);
      }

      // Some removals
      for (int i = 0; i < 10; i++) {
        map.remove(iteration * 100 + i);
      }

      // Verify capacity maintained
      assertTrue(map.size() <= 20, "Capacity exceeded at iteration " + iteration);
    }
  }
}
