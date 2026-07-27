/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.util;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(1)
public class CappedConcurrentHashMapBenchmark {

  @State(Scope.Benchmark)
  public static class ReadState {
    @Param({"ringBufferMap", "syncQueueRemove"})
    public String implementation;

    @Param({"10000"})
    public int capacity;

    private BenchMap<Integer, Integer> map;
    private AtomicInteger nextKey;

    @Setup(Level.Trial)
    public void setup() {
      map = newMap(implementation, capacity);
      fillMap(map, capacity);
      nextKey = new AtomicInteger();
    }
  }

  @State(Scope.Benchmark)
  public static class ReplaceState {
    @Param({"ringBufferMap", "syncQueueRemove"})
    public String implementation;

    @Param({"10000"})
    public int capacity;

    private BenchMap<Integer, Integer> map;
    private AtomicInteger nextKey;

    @Setup(Level.Trial)
    public void setup() {
      map = newMap(implementation, capacity);
      fillMap(map, capacity);
      nextKey = new AtomicInteger();
    }
  }

  @State(Scope.Benchmark)
  public static class ChurnState {
    @Param({"ringBufferMap", "syncQueueRemove"})
    public String implementation;

    @Param({"10000"})
    public int capacity;

    private BenchMap<Integer, Integer> map;
    private ConcurrentLinkedQueue<Integer> liveKeys;
    private AtomicInteger nextInsertKey;

    @Setup(Level.Trial)
    public void setup() {
      map = newMap(implementation, capacity);
      liveKeys = new ConcurrentLinkedQueue<>();
      for (int i = 0; i < capacity; i++) {
        map.put(i, i);
        liveKeys.offer(i);
      }
      nextInsertKey = new AtomicInteger(capacity);
    }
  }

  @Benchmark
  @Threads(100)
  public void benchmarkSharedGet(ReadState state, Blackhole blackhole) {
    int key = state.nextKey.getAndIncrement() % state.capacity;
    blackhole.consume(state.map.get(key));
  }

  @Benchmark
  @Threads(100)
  public void benchmarkSharedReplaceExisting(ReplaceState state, Blackhole blackhole) {
    int key = state.nextKey.getAndIncrement() % state.capacity;
    blackhole.consume(state.map.put(key, key));
  }

  @Benchmark
  @Threads(100)
  public void benchmarkRemoveThenPutAtCapacity(ChurnState state, Blackhole blackhole) {
    Integer removeKey = state.liveKeys.poll();
    if (removeKey != null) {
      blackhole.consume(state.map.remove(removeKey));
    }
    int newKey = state.nextInsertKey.getAndIncrement();
    blackhole.consume(state.map.put(newKey, newKey));
    state.liveKeys.offer(newKey);
  }

  @Benchmark
  @Threads(100)
  public void benchmarkPutThenRemoveEmptyMap(ChurnState state, Blackhole blackhole) {
    int newKey = state.nextInsertKey.getAndIncrement();
    blackhole.consume(state.map.put(newKey, newKey));
    blackhole.consume(state.map.remove(newKey));
  }

  private static BenchMap<Integer, Integer> newMap(String implementation, int capacity) {
    if ("ringBufferMap".equals(implementation)) {
      return new CappedConcurrentHashMapBenchMap<Integer, Integer>(capacity);
    }
    if ("syncQueueRemove".equals(implementation)) {
      return new SyncQueueRemoveBenchMap<Integer, Integer>(capacity);
    }
    throw new IllegalArgumentException("Unknown implementation: " + implementation);
  }

  private static void fillMap(BenchMap<Integer, Integer> map, int capacity) {
    for (int i = 0; i < capacity; i++) {
      map.put(i, i);
    }
  }

  private interface BenchMap<K, V> {
    V put(K key, V value);

    V get(K key);

    V remove(K key);
  }

  private static final class CappedConcurrentHashMapBenchMap<K, V> implements BenchMap<K, V> {
    private final CappedConcurrentHashMap<K, V> map;

    private CappedConcurrentHashMapBenchMap(int capacity) {
      this.map = new CappedConcurrentHashMap<K, V>(capacity);
    }

    @Override
    public V put(K key, V value) {
      return map.put(key, value);
    }

    @Override
    public V get(K key) {
      return map.get(key);
    }

    @Override
    public V remove(K key) {
      return map.remove(key);
    }
  }

  private static final class SyncQueueRemoveBenchMap<K, V> implements BenchMap<K, V> {
    private final int capacity;
    private final Object mutationLock;
    private final ConcurrentHashMap<K, V> map;
    private final ConcurrentLinkedQueue<K> queue;

    private SyncQueueRemoveBenchMap(int capacity) {
      this.capacity = capacity;
      this.mutationLock = new Object();
      this.map = new ConcurrentHashMap<K, V>();
      this.queue = new ConcurrentLinkedQueue<K>();
    }

    @Override
    public V put(K key, V value) {
      if (key == null || value == null) {
        return null;
      }

      synchronized (mutationLock) {
        V previous = map.put(key, value);
        if (previous == null) {
          queue.add(key);
          evictIfNeeded();
        }
        return previous;
      }
    }

    @Override
    public V get(K key) {
      return map.get(key);
    }

    @Override
    public V remove(K key) {
      synchronized (mutationLock) {
        V removed = map.remove(key);
        if (removed != null) {
          queue.remove(key);
        }
        return removed;
      }
    }

    private void evictIfNeeded() {
      while (map.size() > capacity) {
        K oldest = queue.poll();
        if (oldest == null) {
          break;
        }
        map.remove(oldest);
      }
    }
  }
}
