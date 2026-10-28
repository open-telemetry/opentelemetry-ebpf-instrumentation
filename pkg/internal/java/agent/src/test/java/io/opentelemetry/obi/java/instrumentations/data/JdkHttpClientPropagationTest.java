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
import org.junit.jupiter.api.Test;

class JdkHttpClientPropagationTest {
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
  void excludesAsyncCallsAndRestoresTheSynchronousScope() {
    Object sync = new Object();
    Object async = new Object();
    JdkHttpClientPropagation scope = JdkHttpClientPropagation.enter();
    try {
      JdkHttpClientPropagation suspended = JdkHttpClientPropagation.suspend();
      try {
        JdkHttpClientPropagation.register(async, new Object[0], true);
        assertFalse(JdkHttpClientPropagation.contains(async));
      } finally {
        JdkHttpClientPropagation.restore(suspended);
      }
      JdkHttpClientPropagation.register(sync, new Object[0], true);
      assertTrue(JdkHttpClientPropagation.contains(sync));
    } finally {
      JdkHttpClientPropagation.exit(scope);
    }
    assertFalse(JdkHttpClientPropagation.contains(sync));
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
