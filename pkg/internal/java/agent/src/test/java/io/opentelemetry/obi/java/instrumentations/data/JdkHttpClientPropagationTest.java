/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.BiConsumer;
import org.junit.jupiter.api.Test;

class JdkHttpClientPropagationTest {
  @Test
  void listenerRegistrationFailureCannotRetireAnUnfinishedTransport() throws Exception {
    java.lang.reflect.Field available =
        JdkHttpClientPropagation.class.getDeclaredField("available");
    java.lang.reflect.Field scopes =
        JdkHttpClientPropagation.class.getDeclaredField("requestScopes");
    available.setAccessible(true);
    scopes.setAccessible(true);
    Map<?, ?> tracked = (Map<?, ?>) scopes.get(null);
    String syncCapability = System.getProperty(JdkHttpClientPropagation.PROPERTY);
    String asyncCapability = System.getProperty(JdkHttpClientPropagation.ASYNC_PROPERTY);
    Object request = new Object();
    JdkHttpClientPropagation scope = JdkHttpClientPropagation.enterAsync();
    CompletableFuture<Object> transport =
        new CompletableFuture<Object>() {
          @Override
          public CompletableFuture<Object> whenComplete(
              BiConsumer<? super Object, ? super Throwable> callback) {
            throw new IllegalStateException("listener registration failed");
          }
        };
    try {
      JdkHttpClientPropagation.register(request, new Object[0], true);
      JdkHttpClientPropagation.trackTransport(request, transport);
      JdkHttpClientPropagation.exit(scope);
      assertTrue(tracked.containsKey(request));
      assertFalse(JdkHttpClientPropagation.contains(request));
      assertFalse(transport.isDone());
      transport.complete("original result");
      assertEquals("original result", transport.join());
      scope.accept(null, null);
      assertFalse(tracked.containsKey(request));
    } finally {
      scope.accept(null, null);
      available.setBoolean(null, true);
      if (syncCapability == null) {
        System.clearProperty(JdkHttpClientPropagation.PROPERTY);
      } else {
        System.setProperty(JdkHttpClientPropagation.PROPERTY, syncCapability);
      }
      if (asyncCapability == null) {
        System.clearProperty(JdkHttpClientPropagation.ASYNC_PROPERTY);
      } else {
        System.setProperty(JdkHttpClientPropagation.ASYNC_PROPERTY, asyncCapability);
      }
    }
  }

  @Test
  void rejectsIncompleteOrInvalidNativeResponses() {
    String valid = "00-11111111111111111111111111111111-2222222222222222-01";
    assertTrue(JdkHttpClientPropagation.validTraceparent(buffer(valid), 0));
    assertFalse(JdkHttpClientPropagation.validTraceparent(ByteBuffer.allocate(55), 0));
    assertFalse(JdkHttpClientPropagation.validTraceparent(buffer(valid.replace('1', '0')), 0));
    assertFalse(JdkHttpClientPropagation.validTraceparent(buffer(valid.replace('2', '0')), 0));
    assertFalse(JdkHttpClientPropagation.validTraceparent(buffer(valid.substring(0, 54) + "Z"), 0));
  }

  @Test
  void boundsTrackingAndMakesCapacityAvailableAfterCleanup() {
    JdkHttpClientPropagation scope = JdkHttpClientPropagation.enter();
    Object overflow = new Object();
    try {
      for (int i = 0; i < 10_000; i++) {
        JdkHttpClientPropagation.register(new Object(), new Object[0], true);
      }
      JdkHttpClientPropagation.register(overflow, new Object[0], true);
      assertFalse(JdkHttpClientPropagation.contains(overflow));
    } finally {
      JdkHttpClientPropagation.exit(scope);
    }
    scope = JdkHttpClientPropagation.enter();
    try {
      JdkHttpClientPropagation.register(overflow, new Object[0], true);
      assertTrue(JdkHttpClientPropagation.contains(overflow));
    } finally {
      JdkHttpClientPropagation.exit(scope);
    }
  }

  @Test
  void skipsHeadersBeyondThePlaintextCaptureLimit() {
    char[] value = new char[16 * 1024];
    Arrays.fill(value, 'x');
    assertNull(
        JdkHttpClientPropagation.prepareHeaders(
            Collections.singletonList(
                buffer("GET / HTTP/1.1\r\nX-Large: " + new String(value) + "\r\n\r\n"))));
  }

  @Test
  void preservesApplicationHeadersAcrossBuffers() {
    assertNull(
        JdkHttpClientPropagation.prepareHeaders(
            Arrays.asList(buffer("GET / HTTP/1.1\r\nTrAcEpAr"), buffer("EnT: invalid\r\n\r\n"))));
    assertNull(
        JdkHttpClientPropagation.prepareHeaders(
            Collections.singletonList(
                buffer("GET / HTTP/1.1\r\ntraceparent:\r\ntraceparent: value\r\n\r\n"))));
  }

  @Test
  void readsCompleteHeadersWithoutConsumingBuffers() {
    ByteBuffer buffer = buffer("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    ByteBuffer prepared =
        JdkHttpClientPropagation.prepareHeaders(Collections.singletonList(buffer));
    assertNotNull(prepared);
    assertEquals(
        "GET / HTTP/1.1\r\nHost: localhost\r\ntraceparent: ",
        new String(prepared.array(), 0, prepared.position(), StandardCharsets.ISO_8859_1));
    assertEquals(
        "\r\n\r\n",
        new String(prepared.array(), prepared.capacity() - 4, 4, StandardCharsets.ISO_8859_1));
    assertEquals(0, buffer.position());
    assertNull(
        JdkHttpClientPropagation.prepareHeaders(
            Collections.singletonList(buffer("GET / HTTP/1.1\r\nHost: localhost\r\n"))));
  }

  @Test
  void scopesRequestsByIdentityAndCleansUpNestedSends() {
    Object first = new String("same request");
    Object second = new String("same request");
    JdkHttpClientPropagation.register(first, new Object[0], true);
    assertFalse(JdkHttpClientPropagation.contains(first));

    JdkHttpClientPropagation entered = JdkHttpClientPropagation.enter();
    try {
      assertNotNull(entered);
      JdkHttpClientPropagation.register(first, new Object[0], true);
      assertTrue(JdkHttpClientPropagation.contains(first));
      assertFalse(JdkHttpClientPropagation.contains(second));
      JdkHttpClientPropagation nested = JdkHttpClientPropagation.enter();
      assertNotSame(entered, nested);
      JdkHttpClientPropagation.register(second, new Object[0], true);
      JdkHttpClientPropagation.exit(nested);
      assertTrue(JdkHttpClientPropagation.contains(first));
      assertFalse(JdkHttpClientPropagation.contains(second));
    } finally {
      JdkHttpClientPropagation.exit(entered);
    }
    assertFalse(JdkHttpClientPropagation.contains(first));
  }

  @Test
  void asyncReturnRestoresTheSynchronousScopeUntilTransportCompletes() {
    Object sync = new Object();
    Object async = new Object();
    JdkHttpClientPropagation scope = JdkHttpClientPropagation.enter();
    try {
      JdkHttpClientPropagation asynchronous = JdkHttpClientPropagation.enterAsync();
      CompletableFuture<Object> transport = new CompletableFuture<>();
      try {
        JdkHttpClientPropagation.register(async, new Object[0], true);
        JdkHttpClientPropagation.trackTransport(async, transport);
      } finally {
        JdkHttpClientPropagation.exit(asynchronous);
      }
      assertTrue(JdkHttpClientPropagation.contains(async));
      JdkHttpClientPropagation.register(sync, new Object[0], true);
      assertTrue(JdkHttpClientPropagation.contains(sync));
      transport.complete(null);
      assertFalse(JdkHttpClientPropagation.contains(async));
      assertTrue(JdkHttpClientPropagation.contains(sync));
    } finally {
      JdkHttpClientPropagation.exit(scope);
    }
    assertFalse(JdkHttpClientPropagation.contains(sync));
  }

  @Test
  void publicFutureCancellationCannotReleaseTransportOwnership() {
    Object request = new Object();
    Object copy = new Object();
    CompletableFuture<Object> transport = new CompletableFuture<>();
    CompletableFuture<Object> application = transport.thenApply(value -> value);
    JdkHttpClientPropagation scope = JdkHttpClientPropagation.enterAsync();
    JdkHttpClientPropagation.register(request, new Object[0], true);
    JdkHttpClientPropagation.trackTransport(request, transport);
    JdkHttpClientPropagation.exit(scope);
    assertTrue(application.cancel(false));
    assertFalse(transport.isDone());
    JdkHttpClientPropagation.register(copy, new Object[] {request}, false);
    assertTrue(JdkHttpClientPropagation.contains(copy));
    transport.complete(null);
    assertTrue(application.isCancelled());
    assertFalse(JdkHttpClientPropagation.contains(request));
    assertFalse(JdkHttpClientPropagation.contains(copy));
  }

  @Test
  void immediatelyCompletedAndFailedTransportsWaitForCallerExit() {
    for (boolean exceptional : new boolean[] {false, true}) {
      Object request = new Object();
      CompletableFuture<Object> transport = new CompletableFuture<>();
      if (exceptional) {
        transport.completeExceptionally(new IllegalStateException("transport failure"));
      } else {
        transport.complete("original response");
      }
      JdkHttpClientPropagation scope = JdkHttpClientPropagation.enterAsync();
      JdkHttpClientPropagation.register(request, new Object[0], true);
      JdkHttpClientPropagation.trackTransport(request, transport);
      assertTrue(JdkHttpClientPropagation.contains(request));
      JdkHttpClientPropagation.exit(scope);
      assertFalse(JdkHttpClientPropagation.contains(request));
      assertEquals(exceptional, transport.isCompletedExceptionally());
      if (!exceptional) {
        assertEquals("original response", transport.join());
      }
    }
  }

  @Test
  void asyncThrowBeforeTransportAndRepeatedCleanupAreSafe() {
    Object request = new Object();
    JdkHttpClientPropagation scope = JdkHttpClientPropagation.enterAsync();
    JdkHttpClientPropagation.register(request, new Object[0], true);
    JdkHttpClientPropagation.exit(scope);
    scope.accept(null, new IllegalArgumentException("synchronous throw"));
    assertFalse(JdkHttpClientPropagation.contains(request));
    JdkHttpClientPropagation replacement = JdkHttpClientPropagation.enter();
    try {
      JdkHttpClientPropagation.register(request, new Object[0], true);
      scope.accept(null, null);
      assertTrue(JdkHttpClientPropagation.contains(request));
    } finally {
      JdkHttpClientPropagation.exit(replacement);
    }
  }

  @Test
  void completionNeverInstallsContextOnExecutorThreads() throws Exception {
    ExecutorService executor = Executors.newSingleThreadExecutor();
    Object request = new Object();
    Object unrelated = new Object();
    CompletableFuture<Object> transport = new CompletableFuture<>();
    JdkHttpClientPropagation scope = JdkHttpClientPropagation.enterAsync();
    JdkHttpClientPropagation.register(request, new Object[0], true);
    JdkHttpClientPropagation.trackTransport(request, transport);
    JdkHttpClientPropagation.exit(scope);
    try {
      executor
          .submit(
              () -> {
                JdkHttpClientPropagation workerScope = JdkHttpClientPropagation.enter();
                try {
                  transport.completeExceptionally(new IllegalStateException("failed"));
                  JdkHttpClientPropagation.register(unrelated, new Object[0], true);
                  assertTrue(JdkHttpClientPropagation.contains(unrelated));
                } finally {
                  JdkHttpClientPropagation.exit(workerScope);
                }
                JdkHttpClientPropagation.register(new Object(), new Object[0], true);
              })
          .get();
      assertFalse(JdkHttpClientPropagation.contains(request));
      assertFalse(JdkHttpClientPropagation.contains(unrelated));
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  void completionRacesWithCallerExitAndLateCopies() throws Exception {
    ExecutorService executor = Executors.newFixedThreadPool(2);
    try {
      for (int i = 0; i < 200; i++) {
        Object request = new Object();
        Object copy = new Object();
        JdkHttpClientPropagation scope = JdkHttpClientPropagation.enterAsync();
        CompletableFuture<Object> transport = new CompletableFuture<>();
        JdkHttpClientPropagation.register(request, new Object[0], true);
        JdkHttpClientPropagation.trackTransport(request, transport);
        CompletableFuture<Void> copies =
            CompletableFuture.runAsync(
                () -> JdkHttpClientPropagation.register(copy, new Object[] {request}, false),
                executor);
        CompletableFuture<Void> completion =
            CompletableFuture.runAsync(() -> transport.complete(null), executor);
        JdkHttpClientPropagation.exit(scope);
        copies.get();
        completion.get();
        assertFalse(JdkHttpClientPropagation.contains(request));
        assertFalse(JdkHttpClientPropagation.contains(copy));
      }
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  void abandonedAsyncTrackingIsBoundedWithoutEvictingLiveRequests() {
    Object request = new Object();
    Object overflow = new Object();
    CompletableFuture<Object> transport = new CompletableFuture<>();
    JdkHttpClientPropagation scope = JdkHttpClientPropagation.enterAsync();
    JdkHttpClientPropagation.register(request, new Object[0], true);
    for (int i = 1; i < 10_000; i++) {
      JdkHttpClientPropagation.register(new Object(), new Object[] {request}, false);
    }
    JdkHttpClientPropagation.trackTransport(request, transport);
    JdkHttpClientPropagation.exit(scope);
    JdkHttpClientPropagation next = JdkHttpClientPropagation.enterAsync();
    try {
      JdkHttpClientPropagation.register(overflow, new Object[0], true);
      assertFalse(JdkHttpClientPropagation.contains(overflow));
      assertTrue(JdkHttpClientPropagation.contains(request));
      transport.complete(null);
      JdkHttpClientPropagation.register(overflow, new Object[0], true);
      assertTrue(JdkHttpClientPropagation.contains(overflow));
    } finally {
      transport.complete(null);
      JdkHttpClientPropagation.exit(next);
    }
  }

  @Test
  void immutableUserRequestReuseKeepsIndependentInternalOwners() {
    Object userRequest = new Object();
    Object first = new Object();
    Object second = new Object();
    CompletableFuture<Object> firstTransport = new CompletableFuture<>();
    CompletableFuture<Object> secondTransport = new CompletableFuture<>();
    JdkHttpClientPropagation firstScope = JdkHttpClientPropagation.enterAsync();
    JdkHttpClientPropagation.register(first, new Object[] {userRequest}, true);
    JdkHttpClientPropagation.trackTransport(first, firstTransport);
    JdkHttpClientPropagation secondScope = JdkHttpClientPropagation.enterAsync();
    JdkHttpClientPropagation.register(second, new Object[] {userRequest}, true);
    JdkHttpClientPropagation.trackTransport(second, secondTransport);
    JdkHttpClientPropagation.exit(secondScope);
    JdkHttpClientPropagation.exit(firstScope);
    secondTransport.complete(null);
    assertTrue(JdkHttpClientPropagation.contains(first));
    assertFalse(JdkHttpClientPropagation.contains(second));
    firstTransport.complete(null);
    assertFalse(JdkHttpClientPropagation.contains(first));
    assertFalse(JdkHttpClientPropagation.contains(userRequest));
  }

  @Test
  void tracksRedirectCopiesOnWorkerThreadsUntilSendExits() throws Exception {
    Object original = new Object();
    Object redirect = new Object();
    Object late = new Object();
    JdkHttpClientPropagation scope = JdkHttpClientPropagation.enter();
    java.util.concurrent.ExecutorService executor =
        java.util.concurrent.Executors.newSingleThreadExecutor();
    try {
      JdkHttpClientPropagation.register(original, new Object[0], true);
      executor
          .submit(() -> JdkHttpClientPropagation.register(redirect, new Object[] {original}, false))
          .get();
      assertTrue(JdkHttpClientPropagation.contains(redirect));
    } finally {
      JdkHttpClientPropagation.exit(scope);
      executor.shutdownNow();
    }
    JdkHttpClientPropagation.register(late, new Object[] {redirect}, false);
    assertFalse(JdkHttpClientPropagation.contains(original));
    assertFalse(JdkHttpClientPropagation.contains(redirect));
    assertFalse(JdkHttpClientPropagation.contains(late));
  }

  @Test
  void copiesKeepTheirOwnerAcrossNestedCallsAndCannotReviveAnExpiredSend() {
    Object original = new Object();
    Object copy = new Object();
    Object late = new Object();
    JdkHttpClientPropagation outer = JdkHttpClientPropagation.enter();
    JdkHttpClientPropagation.register(original, new Object[0], true);
    JdkHttpClientPropagation inner = JdkHttpClientPropagation.enter();
    try {
      JdkHttpClientPropagation.register(copy, new Object[] {original}, false);
    } finally {
      JdkHttpClientPropagation.exit(inner);
    }
    assertTrue(JdkHttpClientPropagation.contains(copy));
    JdkHttpClientPropagation.exit(outer);
    assertFalse(JdkHttpClientPropagation.contains(copy));
    JdkHttpClientPropagation unrelated = JdkHttpClientPropagation.enter();
    try {
      JdkHttpClientPropagation.register(late, new Object[] {original}, false);
      assertFalse(JdkHttpClientPropagation.contains(late));
    } finally {
      JdkHttpClientPropagation.exit(unrelated);
    }
  }

  @Test
  void scansEveryBufferBoundaryAndPreservesRawBytes() {
    byte[] original =
        "GET / HTTP/1.1\r\nX-Value: caf\u00e9\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
    for (int split = 0; split <= original.length; split++) {
      ByteBuffer first = ByteBuffer.wrap(original, 0, split).asReadOnlyBuffer();
      ByteBuffer second = ByteBuffer.allocateDirect(original.length - split);
      second.put(original, split, original.length - split);
      ((java.nio.Buffer) second).flip();
      ByteBuffer prepared = JdkHttpClientPropagation.prepareHeaders(Arrays.asList(first, second));
      assertNotNull(prepared);
      assertArrayEquals(
          Arrays.copyOf(original, original.length - 2),
          Arrays.copyOf(prepared.array(), original.length - 2));
      assertEquals(0, second.position());
      assertEquals(split, first.limit());
    }
    assertNull(
        JdkHttpClientPropagation.prepareHeaders(
            Collections.singletonList(buffer("GET / HTTP/1.1\r\n\r\nX-After: value\r\n\r\n"))));
  }

  private static ByteBuffer buffer(String text) {
    return ByteBuffer.wrap(text.getBytes(StandardCharsets.ISO_8859_1));
  }
}
