/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import io.opentelemetry.obi.java.Agent;
import io.opentelemetry.obi.java.ebpf.ConnectionInfo;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import io.opentelemetry.obi.java.instrumentations.util.ByteBufferExtractor;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiConsumer;

/**
 * One instance owns a send's propagation state. The caller captures its parent; workers find the
 * same state through internal request identity. Async ownership ends with the internal exchange,
 * independently of cancellation or completion of the application's future.
 */
public final class JdkHttpClientPropagation implements BiConsumer<Object, Throwable> {
  public static final String PROPERTY = "otel.obi.java.agent.httpclient.propagation";
  public static final String ASYNC_PROPERTY = "otel.obi.java.agent.httpclient.async.propagation";
  private static final int MAX_TRACKED_REQUESTS = 10_000;
  private static final int CONNECTION_SIZE = 36;
  private static final int TRACE_ID_SIZE = 16;
  private static final int SPAN_ID_SIZE = 8;
  private static final int TRACE_ID_OFFSET = 3;
  private static final int SPAN_ID_OFFSET = TRACE_ID_OFFSET + TRACE_ID_SIZE * 2 + 1;
  private static final int FLAGS_OFFSET = SPAN_ID_OFFSET + SPAN_ID_SIZE * 2 + 1;
  private static final int TRACEPARENT_SIZE = FLAGS_OFFSET + 2;
  // Shared with the reserve/release packet layout in bpf/generictracer/java_tls.c.
  private static final int PACKET_CONNECTION_OFFSET = 1;
  private static final int PACKET_VALUE_OFFSET_FIELD = PACKET_CONNECTION_OFFSET + CONNECTION_SIZE;
  private static final int PACKET_TRACEPARENT_OFFSET = PACKET_VALUE_OFFSET_FIELD + Integer.BYTES;
  private static final int PACKET_PARENT_OFFSET = PACKET_TRACEPARENT_OFFSET + TRACEPARENT_SIZE;
  private static final int PARENT_SIZE = TRACE_ID_SIZE + SPAN_ID_SIZE + 2;
  private static final int REQUEST_ID_SIZE = Long.BYTES;
  private static final byte[] HEADER = "traceparent: ".getBytes(StandardCharsets.US_ASCII);
  private static final int HEADER_NAME_LENGTH = HEADER.length - 2; // exclude colon and space
  private static final int CRLF_SIZE = 2;
  private static final int HEADER_TERMINATOR_SIZE = 2 * CRLF_SIZE;
  private static final ThreadLocal<JdkHttpClientPropagation> currentSend = new ThreadLocal<>();
  private static final Map<Object, JdkHttpClientPropagation> requestScopes =
      Collections.synchronizedMap(new IdentityHashMap<>());
  private static int retainedReservations;

  // Resolved inside the JDK module by the inlined advice, then published together.
  public static final int IS_SECURE_METHOD = 0;
  public static final int CHANNEL_METHOD = 1;
  public static final int EXPECT_CONTINUE_METHOD = 2;
  public static volatile Method[] connectionMethods;
  private static volatile boolean available = true;

  private JdkHttpClientPropagation previousScope;
  private final List<Object> trackedRequests = new ArrayList<>();
  private final List<NativeMemory> reservations = new ArrayList<>();
  private byte[] parent;
  private boolean active = true;
  private boolean asynchronous;
  private boolean callerExited;
  private boolean transportAttached;
  private boolean transportCompleted;

  private JdkHttpClientPropagation(JdkHttpClientPropagation previousScope) {
    this.previousScope = previousScope;
  }

  public static JdkHttpClientPropagation enter() {
    if (!available) {
      return null;
    }
    JdkHttpClientPropagation scope = new JdkHttpClientPropagation(currentSend.get());
    currentSend.set(scope);
    return scope;
  }

  public static JdkHttpClientPropagation enterAsync() {
    JdkHttpClientPropagation scope = enter();
    if (scope != null) {
      scope.asynchronous = true;
    }
    return scope;
  }

  public static JdkHttpClientPropagation suspend() {
    JdkHttpClientPropagation scope = currentSend.get();
    currentSend.remove();
    return scope;
  }

  public static void captureParent(JdkHttpClientPropagation scope) {
    if (scope == null) {
      return;
    }
    try {
      NativeMemory packet = new NativeMemory(1 + PARENT_SIZE);
      packet.setByte(0, OperationType.HTTP1_PARENT.code);
      Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
      if (packet.getBuffer().get(0) != 0) {
        scope.active = false;
        return;
      }
      scope.parent = new byte[PARENT_SIZE];
      ByteBuffer value = packet.getBuffer().duplicate();
      ((java.nio.Buffer) value).position(1);
      value.get(scope.parent);
    } catch (Throwable error) {
      scope.active = false;
      disable(error);
    }
  }

  public static void restore(JdkHttpClientPropagation scope) {
    if (scope != null) {
      currentSend.set(scope);
    }
  }

  public static void register(Object request, Object[] arguments, boolean initial) {
    JdkHttpClientPropagation scope = initial ? currentSend.get() : null;
    if (!initial) {
      for (Object argument : arguments) {
        scope = requestScopes.get(argument);
        if (scope != null) {
          break;
        }
      }
    }
    if (scope == null) {
      return;
    }
    synchronized (scope) {
      synchronized (requestScopes) {
        if (scope.active
            && requestScopes.size() < MAX_TRACKED_REQUESTS
            && !requestScopes.containsKey(request)) {
          requestScopes.put(request, scope);
          scope.trackedRequests.add(request);
        }
      }
    }
  }

  public static boolean contains(Object request) {
    return available && requestScopes.containsKey(request);
  }

  public static void exit(JdkHttpClientPropagation scope) {
    if (scope == null) {
      return;
    }
    currentSend.remove();
    restore(scope.previousScope);
    synchronized (scope) {
      scope.previousScope = null;
      scope.callerExited = true;
      if (!scope.transportAttached || scope.transportCompleted) {
        scope.release();
      }
    }
  }

  public static void trackTransport(Object request, CompletableFuture<?> future) {
    JdkHttpClientPropagation scope = requestScopes.get(request);
    if (scope == null || !scope.asynchronous || future == null) {
      return;
    }
    synchronized (scope) {
      if (!scope.active || scope.transportAttached) {
        return;
      }
      scope.transportAttached = true;
    }
    // Observe the internal future, never the cancellable application-facing dependent stage.
    try {
      future.whenComplete(scope);
    } catch (Throwable error) {
      disable(error);
      // A failed listener registration must not retire state still needed by transport.
      if (future.isDone()) {
        scope.accept(null, error);
      }
    }
  }

  @Override
  public void accept(Object response, Throwable failure) {
    synchronized (this) {
      transportCompleted = true;
      if (callerExited) {
        release();
      }
    }
  }

  private void release() {
    active = false;
    for (Object request : trackedRequests) {
      requestScopes.remove(request);
    }
    for (NativeMemory packet : reservations) {
      try {
        packet.setByte(0, OperationType.HTTP1_TRACEPARENT_RELEASE.code);
        Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
      } catch (Throwable error) {
        disable(error);
      }
    }
    synchronized (requestScopes) {
      retainedReservations -= reservations.size();
    }
    trackedRequests.clear();
    reservations.clear();
  }

  public static synchronized void disable(Throwable error) {
    if (available) {
      available = false;
      try {
        System.setProperty(PROPERTY, "false");
        System.setProperty(ASYNC_PROPERTY, "false");
      } catch (SecurityException ignored) {
      }
      if (SSLStorage.debugOn) {
        System.err.println(
            "[OBI] Java HttpClient header propagation disabled: " + error.getClass().getName());
      }
    }
  }

  static ByteBuffer prepareHeaders(List<ByteBuffer> buffers) {
    int length = 0;
    for (ByteBuffer buffer : buffers) {
      if (buffer == null
          || buffer.remaining()
              > ByteBufferExtractor.MAX_SIZE
                  - HEADER.length
                  - TRACEPARENT_SIZE
                  - CRLF_SIZE
                  - length) {
        return null;
      }
      length += buffer.remaining();
    }
    if (length < HEADER_TERMINATOR_SIZE) {
      return null;
    }
    ByteBuffer result = ByteBuffer.allocate(length + HEADER.length + TRACEPARENT_SIZE + CRLF_SIZE);
    for (ByteBuffer buffer : buffers) {
      result.put(buffer.duplicate());
    }
    byte[] bytes = result.array();
    if (bytes[length - 4] != '\r'
        || bytes[length - 3] != '\n'
        || bytes[length - 2] != '\r'
        || bytes[length - 1] != '\n') {
      return null;
    }
    int start = 0;
    for (int end = 1; end < length; end++) {
      if (bytes[end - 1] != '\r' || bytes[end] != '\n') {
        continue;
      }
      if (end - 1 == start && end != length - 1) {
        return null;
      }
      if (isTraceparentHeader(bytes, start, end - 1)) {
        return null;
      }
      start = end + 1;
    }
    ((java.nio.Buffer) result).position(length - CRLF_SIZE);
    result.put(HEADER);
    int valueOffset = result.position();
    ((java.nio.Buffer) result).position(valueOffset + TRACEPARENT_SIZE);
    result.put((byte) '\r').put((byte) '\n').put((byte) '\r').put((byte) '\n');
    ((java.nio.Buffer) result).position(valueOffset);
    return result;
  }

  private static boolean isTraceparentHeader(byte[] headers, int start, int end) {
    if (end - start < HEADER_NAME_LENGTH + 1 || headers[start + HEADER_NAME_LENGTH] != ':') {
      return false;
    }
    for (int i = 0; i < HEADER_NAME_LENGTH; i++) {
      // HTTP field names are ASCII and case insensitive.
      if ((headers[start + i] | 0x20) != HEADER[i]) {
        return false;
      }
    }
    return true;
  }

  static boolean validTraceparent(ByteBuffer packet, int offset) {
    if (packet.get(offset) != '0' || packet.get(offset + 1) != '0') {
      return false;
    }
    boolean trace = false;
    boolean span = false;
    for (int i = TRACE_ID_OFFSET - 1; i < TRACEPARENT_SIZE; i++) {
      if (i == TRACE_ID_OFFSET - 1 || i == SPAN_ID_OFFSET - 1 || i == FLAGS_OFFSET - 1) {
        if (packet.get(offset + i) != '-') {
          return false;
        }
        continue;
      }
      byte value = packet.get(offset + i);
      if (!(value >= '0' && value <= '9') && !(value >= 'a' && value <= 'f')) {
        return false;
      }
      trace |= i < SPAN_ID_OFFSET - 1 && value != '0';
      span |= i >= SPAN_ID_OFFSET && i < FLAGS_OFFSET - 1 && value != '0';
    }
    return trace && span;
  }

  public static List<ByteBuffer> inject(
      Object request, SocketChannel channel, List<ByteBuffer> buffers) throws Exception {
    JdkHttpClientPropagation scope = requestScopes.get(request);
    if (scope == null) {
      return buffers;
    }
    ByteBuffer headers = prepareHeaders(buffers);
    if (headers == null) {
      return buffers;
    }
    InetSocketAddress local = (InetSocketAddress) channel.getLocalAddress();
    InetSocketAddress remote = (InetSocketAddress) channel.getRemoteAddress();
    Connection connection =
        new Connection(local.getAddress(), local.getPort(), remote.getAddress(), remote.getPort());
    synchronized (scope) {
      if (!scope.active || scope.parent == null) {
        return buffers;
      }
      NativeMemory packet = scope.reserveClientSpan(connection, headers.position());
      if (packet == null) {
        return buffers;
      }
      ByteBuffer value = packet.getBuffer().duplicate();
      ((java.nio.Buffer) value).position(PACKET_PARENT_OFFSET);
      value.get(scope.parent);
      ((java.nio.Buffer) value).limit(PACKET_PARENT_OFFSET);
      ((java.nio.Buffer) value).position(PACKET_TRACEPARENT_OFFSET);
      headers.put(value);
      ((java.nio.Buffer) headers).position(0);
      return Collections.singletonList(headers);
    }
  }

  // Called with this send's monitor held, so exit() cannot release a packet mid-injection.
  private NativeMemory reserveClientSpan(Connection connection, int headerValueOffset) {
    NativeMemory packet = new NativeMemory(PACKET_PARENT_OFFSET + PARENT_SIZE + REQUEST_ID_SIZE);
    packet.setByte(0, OperationType.HTTP1_TRACEPARENT.code);
    ConnectionInfo.writeSendConnectionInfo(packet, PACKET_CONNECTION_OFFSET, connection);
    packet.setInt(PACKET_VALUE_OFFSET_FIELD, headerValueOffset);
    packet.write(PACKET_PARENT_OFFSET, parent, 0, parent.length);
    synchronized (requestScopes) {
      if (retainedReservations >= MAX_TRACKED_REQUESTS) {
        return null;
      }
      reservations.add(packet);
      retainedReservations++;
    }
    Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
    if (packet.getBuffer().get(0) != 0
        || !validTraceparent(packet.getBuffer(), PACKET_TRACEPARENT_OFFSET)) {
      reservations.remove(packet);
      synchronized (requestScopes) {
        retainedReservations--;
      }
      return null;
    }
    return packet;
  }
}
