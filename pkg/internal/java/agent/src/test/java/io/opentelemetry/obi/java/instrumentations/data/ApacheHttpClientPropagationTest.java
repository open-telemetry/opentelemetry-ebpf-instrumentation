/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import static net.bytebuddy.matcher.ElementMatchers.isAbstract;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static org.junit.jupiter.api.Assertions.*;

import io.opentelemetry.obi.java.instrumentations.util.ByteBufferExtractor;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.implementation.InvocationHandlerAdapter;
import net.bytebuddy.implementation.StubMethod;
import org.junit.jupiter.api.Test;

class ApacheHttpClientPropagationTest {
  private static final String TRACEPARENT =
      "00-11111111111111111111111111111111-2222222222222222-01";

  @Test
  void copiesOnlyTheSelectedSliceAndPreservesBodyAndUnrelatedHeaders() {
    String body = "GET /body HTTP/1.1\r\ntraceparent: body-owned\r\n\r\n";
    String headers =
        "POST / HTTP/1.1\r\nX-Unrelated: value\r\nContent-Length: " + body.length() + "\r\n";
    String request = headers + "\r\n" + body;
    byte[] original = bytes("prefix" + request + "suffix");
    byte[] saved = original.clone();
    ByteBuffer prepared = ApacheHttpClientPropagation.prepareHeaders(original, 6, request.length());
    assertNotNull(prepared);
    prepared.put(bytes(TRACEPARENT));
    assertEquals(
        headers + "traceparent: " + TRACEPARENT + "\r\n\r\n" + body,
        new String(prepared.array(), StandardCharsets.US_ASCII));
    assertArrayEquals(saved, original);
  }

  @Test
  void preservesBinaryBodyBytes() {
    byte[] body = {0, (byte) 0x80, (byte) 0xff, '\r', '\n'};
    byte[] headers = bytes("POST / HTTP/1.1\r\nContent-Length: " + body.length + "\r\n\r\n");
    byte[] request = Arrays.copyOf(headers, headers.length + body.length);
    System.arraycopy(body, 0, request, headers.length, body.length);
    ByteBuffer prepared = ApacheHttpClientPropagation.prepareHeaders(request, 0, request.length);
    assertNotNull(prepared);
    prepared.put(bytes(TRACEPARENT));
    assertArrayEquals(
        body,
        Arrays.copyOfRange(
            prepared.array(), prepared.capacity() - body.length, prepared.capacity()));
  }

  @Test
  void leavesEveryApplicationOwnedHeaderUnchanged() {
    for (String owned :
        Arrays.asList(
            "TrAcEpArEnT: " + TRACEPARENT,
            "traceparent:",
            "TRACEPARENT: invalid",
            "traceparent: first\r\nTraceparent: second")) {
      byte[] request = bytes("POST / HTTP/1.1\r\n" + owned + "\r\n\r\n");
      byte[] saved = request.clone();
      assertNull(ApacheHttpClientPropagation.prepareHeaders(request, 0, request.length));
      assertArrayEquals(saved, request);
    }
  }

  @Test
  void rejectsSplitHeadersOtherProtocolsAndInvalidSlices() {
    for (String value :
        Arrays.asList(
            "",
            "POST / HTTP/1.1\r\nHost: proxy\r\n",
            "POST / HTTP/1.1\r\nExPeCt: 100-continue\r\n\r\n",
            "POST / HTTP/1.0\r\n\r\n",
            "HTTP/1.1 200 OK\r\n\r\n",
            "PRI * HTTP/2.0\r\n\r\n")) {
      byte[] request = bytes(value);
      assertNull(ApacheHttpClientPropagation.prepareHeaders(request, 0, request.length));
    }
    byte[] request = bytes("GET / HTTP/1.1\r\n\r\n");
    assertNull(ApacheHttpClientPropagation.prepareHeaders(request, -1, request.length));
    assertNull(ApacheHttpClientPropagation.prepareHeaders(request, 1, request.length));
    assertNull(ApacheHttpClientPropagation.prepareHeaders(request, 0, -1));
  }

  @Test
  void boundsTheEntireInjectedWriteToTheExistingCaptureLimit() {
    byte[] headers = bytes("POST / HTTP/1.1\r\n\r\n");
    ByteBuffer prepared = ApacheHttpClientPropagation.prepareHeaders(headers, 0, headers.length);
    assertNotNull(prepared);
    int added = prepared.capacity() - headers.length;
    byte[] maximum = Arrays.copyOf(headers, ByteBufferExtractor.MAX_SIZE - added);
    Arrays.fill(maximum, headers.length, maximum.length, (byte) 'x');
    prepared = ApacheHttpClientPropagation.prepareHeaders(maximum, 0, maximum.length);
    assertNotNull(prepared);
    assertEquals(ByteBufferExtractor.MAX_SIZE, prepared.capacity());
    byte[] oversized = Arrays.copyOf(maximum, maximum.length + 1);
    assertNull(ApacheHttpClientPropagation.prepareHeaders(oversized, 0, oversized.length));
  }

  @Test
  void scopesOverloadsAttemptsAndThreadsAndCleansUpAfterExit() throws Exception {
    Socket socket = SSLSocketFactory.getDefault().createSocket();
    assertNull(ApacheHttpClientPropagation.beginAttempt(new Object()));
    assertNull(ApacheHttpClientPropagation.beginAttempt(socket));
    ApacheHttpClientPropagation scope = ApacheHttpClientPropagation.enter();
    assertNotNull(scope);
    try {
      ApacheHttpClientPropagation nested = ApacheHttpClientPropagation.enter();
      assertNotSame(scope, nested);
      ApacheHttpClientPropagation.exit(nested);
      assertNull(ApacheHttpClientPropagation.beginAttempt(null));
      assertSame(scope, ApacheHttpClientPropagation.beginAttempt(socket));
      assertNull(ApacheHttpClientPropagation.beginAttempt(socket));
      ApacheHttpClientPropagation.endAttempt(null);
      assertNull(ApacheHttpClientPropagation.beginAttempt(socket));
      ApacheHttpClientPropagation.endAttempt(scope);
      assertSame(scope, ApacheHttpClientPropagation.beginAttempt(socket));
      CompletableFuture.runAsync(
              () -> {
                assertNull(ApacheHttpClientPropagation.beginAttempt(socket));
                ApacheHttpClientPropagation other = ApacheHttpClientPropagation.enter();
                try {
                  assertNotNull(other);
                  assertNotSame(scope, other);
                  assertSame(other, ApacheHttpClientPropagation.beginAttempt(socket));
                } finally {
                  ApacheHttpClientPropagation.exit(other);
                }
                assertNull(ApacheHttpClientPropagation.beginAttempt(socket));
              })
          .get();
    } finally {
      ApacheHttpClientPropagation.exit(scope);
      socket.close();
    }
    assertNull(ApacheHttpClientPropagation.beginAttempt(socket));
    long[] outcomes = ApacheHttpClientPropagation.outcomes();
    assertEquals(0, outcomes[outcomes.length - 1]);
    ApacheHttpClientPropagation next = ApacheHttpClientPropagation.enter();
    try {
      assertNotNull(next);
    } finally {
      ApacheHttpClientPropagation.exit(next);
    }
  }

  @Test
  void ignoresAnotherSocketWithoutConsumingTheRequestAndSkipsLaterBodyWrites() throws Exception {
    AtomicInteger inspected = new AtomicInteger();
    Class<? extends SSLSocket> socketType =
        new ByteBuddy()
            .subclass(SSLSocket.class)
            .method(isAbstract())
            .intercept(StubMethod.INSTANCE)
            .method(named("getLocalAddress"))
            .intercept(
                InvocationHandlerAdapter.of(
                    (proxy, method, arguments) -> {
                      inspected.incrementAndGet();
                      return null;
                    }))
            .make()
            .load(getClass().getClassLoader())
            .getLoaded();
    try (Socket socket = socketType.getDeclaredConstructor().newInstance();
        Socket other = SSLSocketFactory.getDefault().createSocket()) {
      byte[] request = bytes("GET / HTTP/1.1\r\n\r\n");
      ApacheHttpClientPropagation scope = ApacheHttpClientPropagation.enter();
      try {
        assertSame(scope, ApacheHttpClientPropagation.beginAttempt(socket));
        assertNull(ApacheHttpClientPropagation.inject(request, 0, request.length, other));
        assertNull(ApacheHttpClientPropagation.inject(request, 0, request.length, socket));
        assertEquals(1, inspected.get());
        assertNull(ApacheHttpClientPropagation.inject(request, 0, request.length, socket));
        assertEquals(1, inspected.get());
      } finally {
        ApacheHttpClientPropagation.exit(scope);
      }
    }
  }

  @Test
  void aSplitOrSingleByteWriteCannotMakeALaterBodyLookLikeHeaders() throws Exception {
    try (Socket socket = SSLSocketFactory.getDefault().createSocket()) {
      ApacheHttpClientPropagation scope = ApacheHttpClientPropagation.enter();
      try {
        ApacheHttpClientPropagation.beginAttempt(socket);
        byte[] split = bytes("GET / HTTP/1.1\r\nHost: proxy\r\n");
        assertNull(ApacheHttpClientPropagation.inject(split, 0, split.length, socket));
        byte[] body = bytes("GET /body HTTP/1.1\r\n\r\n");
        assertNull(ApacheHttpClientPropagation.inject(body, 0, body.length, socket));
        ApacheHttpClientPropagation.endAttempt(scope);
        ApacheHttpClientPropagation.beginAttempt(socket);
        ApacheHttpClientPropagation.skipWrite(socket);
        assertNull(ApacheHttpClientPropagation.inject(body, 0, body.length, socket));
      } finally {
        ApacheHttpClientPropagation.exit(scope);
      }
    }
  }

  @Test
  void attemptsOwnIndependentParentCopiesAndReleaseAtEveryBoundary() throws Exception {
    java.lang.reflect.Field parent = JdkHttpClientPropagation.class.getDeclaredField("parent");
    parent.setAccessible(true);
    JdkHttpClientPropagation owner = JdkHttpClientPropagation.enter();
    byte[] captured = new byte[] {1, 2, 3};
    parent.set(owner, captured);
    try {
      for (int i = 0; i < 20_000; i++) {
        JdkHttpClientPropagation attempt = JdkHttpClientPropagation.attempt(owner);
        byte[] copy = (byte[]) parent.get(attempt);
        assertArrayEquals(captured, copy);
        assertNotSame(captured, copy);
        copy[0] = 0;
        attempt.release();
      }
      assertEquals(1, captured[0]);
    } finally {
      JdkHttpClientPropagation.exit(owner);
    }
  }

  @Test
  void ignoresTlsWritesOutsideSynchronousApacheExecution() {
    byte[] request = bytes("GET / HTTP/1.1\r\n\r\n");
    assertNull(ApacheHttpClientPropagation.inject(request, 0, request.length, null));
  }

  private static byte[] bytes(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }
}
