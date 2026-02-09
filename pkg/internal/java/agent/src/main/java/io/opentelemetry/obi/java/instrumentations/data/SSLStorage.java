/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import io.opentelemetry.obi.java.instrumentations.util.CappedConcurrentHashMap;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import javax.net.ssl.SSLEngine;

public class SSLStorage {
  public static Method bootExtractMethod = null;
  public static Field bootNettyConnectionField = null;

  public static boolean debugOn = false;

  public static Field bootDebugOn = null;

  private static final int MAX_CONCURRENT = 10_000;
  private static final CappedConcurrentHashMap<SSLEngine, Connection> sslConnections =
      new CappedConcurrentHashMap<>(MAX_CONCURRENT);
  private static final CappedConcurrentHashMap<String, BytesWithLen> bufToBuf =
      new CappedConcurrentHashMap<>(MAX_CONCURRENT);

  private static final CappedConcurrentHashMap<String, Connection> bufConn =
      new CappedConcurrentHashMap<>(MAX_CONCURRENT);

  private static final CappedConcurrentHashMap<Connection, Connection> activeConnections =
      new CappedConcurrentHashMap<>(MAX_CONCURRENT);

  private static final CappedConcurrentHashMap<Integer, Long> tasks =
      new CappedConcurrentHashMap<>(MAX_CONCURRENT);

  public static final ThreadLocal<BytesWithLen> unencrypted = new ThreadLocal<>();

  public static final ThreadLocal<Object> nettyConnection = new ThreadLocal<>();

  public static Connection getConnectionForSession(SSLEngine session) {
    return sslConnections.get(session);
  }

  public static void setConnectionForSession(SSLEngine session, Connection c) {
    sslConnections.put(session, c);
  }

  public static Connection getConnectionForBuf(String buf) {
    return bufConn.get(buf);
  }

  public static boolean connectionUntracked(Connection c) {
    return activeConnections.get(c) == null;
  }

  public static Connection getActiveConnection(Connection c) {
    return activeConnections.get(c);
  }

  public static void setConnectionForBuf(String buf, Connection c) {
    c.setBufferKey(buf);
    bufConn.put(buf, c);
    activeConnections.put(c, c);
  }

  public static void cleanupConnectionBufMapping(Connection c) {
    bufConn.remove(c.getBufferKey());
    activeConnections.remove(c);
  }

  public static void setBufferMapping(String encrypted, BytesWithLen plain) {
    bufToBuf.put(encrypted, plain);
  }

  public static BytesWithLen getUnencryptedBuffer(String encrypted) {
    return bufToBuf.get(encrypted);
  }

  public static void removeBufferMapping(String encrypted) {
    bufToBuf.remove(encrypted);
  }

  // These boot finder methods are here to help us find the version of the methods/classes that are
  // loaded
  // on the boot class loader. Since we use multiple class loaders, we need to be able to find a
  // specific version
  // of the class.
  public static Method getBootExtractMethod() {
    if (bootExtractMethod == null) {
      try {
        Class<?> extractorClass =
            Class.forName(
                "io.opentelemetry.obi.java.instrumentations.util.NettyChannelExtractor",
                true,
                null); // null for bootstrap loader
        bootExtractMethod =
            extractorClass.getMethod("extractConnectionFromChannelHandlerContext", Object.class);
      } catch (Exception x) {
        System.err.println("[SSLStorage] Failed to get boot extract method " + x);
      }
    }
    return bootExtractMethod;
  }

  public static Field getBootNettyConnectionField() {
    if (bootNettyConnectionField == null) {
      try {
        Class<?> sslStorageClass =
            Class.forName("io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
        bootNettyConnectionField = sslStorageClass.getDeclaredField("nettyConnection");
      } catch (Exception x) {
        System.err.println("[SSLStorage] Failed to get boot netty connection field " + x);
      }
    }

    return bootNettyConnectionField;
  }

  public static Field getBootDebugOn() {
    if (bootDebugOn == null) {
      try {
        Class<?> sslStorageClass =
            Class.forName("io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
        bootDebugOn = sslStorageClass.getDeclaredField("debugOn");
      } catch (Exception x) {
        System.err.println("[SSLStorage] Failed to get boot debug on " + x);
      }
    }

    return bootDebugOn;
  }

  public static Object bootDebugOn() {
    try {
      Field debugOn = getBootDebugOn();
      if (debugOn == null) {
        return false;
      }
      return debugOn.get(null);
    } catch (Exception x) {
      System.err.println("[SSLStorage] Failed to get boot debug on " + x);
    }

    return false;
  }

  public static void trackTask(long threadId, Object task) {
    if (task == null) {
      return;
    }
    tasks.put(System.identityHashCode(task), threadId);
  }

  public static void untrackTask(Object task) {
    if (task == null) {
      return;
    }
    tasks.remove(System.identityHashCode(task));
  }

  public static Long parentThreadId(Object task) {
    if (task == null) {
      return null;
    }

    return tasks.get(System.identityHashCode(task));
  }
}
