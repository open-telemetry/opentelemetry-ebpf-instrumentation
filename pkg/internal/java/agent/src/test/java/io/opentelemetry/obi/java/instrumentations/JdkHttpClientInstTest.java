/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.opentelemetry.obi.java.instrumentations.data.JdkHttpClientPropagation;
import java.nio.channels.SocketChannel;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.pool.TypePool;
import org.junit.jupiter.api.Test;

class JdkHttpClientInstTest {
  @Test
  void checksTheJdkLayoutBeforeInstallingPropagation() {
    assumeTrue(loadClass("java.net.http.HttpClient") != null);
    assertTrue(JdkHttpClientInst.propagationCompatible());
    String previous = System.getProperty(JdkHttpClientPropagation.PROPERTY);
    String previousAsync = System.getProperty(JdkHttpClientPropagation.ASYNC_PROPERTY);
    try {
      JdkHttpClientInst.transformer(true);
      assertTrue(Boolean.parseBoolean(System.getProperty(JdkHttpClientPropagation.PROPERTY)));
      assertTrue(Boolean.parseBoolean(System.getProperty(JdkHttpClientPropagation.ASYNC_PROPERTY)));
      JdkHttpClientInst.transformer(false);
      assertFalse(Boolean.parseBoolean(System.getProperty(JdkHttpClientPropagation.PROPERTY)));
      assertFalse(
          Boolean.parseBoolean(System.getProperty(JdkHttpClientPropagation.ASYNC_PROPERTY)));
    } finally {
      if (previous == null) {
        System.clearProperty(JdkHttpClientPropagation.PROPERTY);
      } else {
        System.setProperty(JdkHttpClientPropagation.PROPERTY, previous);
      }
      if (previousAsync == null) {
        System.clearProperty(JdkHttpClientPropagation.ASYNC_PROPERTY);
      } else {
        System.setProperty(JdkHttpClientPropagation.ASYNC_PROPERTY, previousAsync);
      }
    }
  }

  @Test
  void rejectsAnUnavailableAsyncLifetimeHook() {
    assumeTrue(loadClass("java.net.http.HttpClient") != null);
    TypeDescription impl =
        TypePool.Default.ofSystemLoader()
            .describe("jdk.internal.net.http.HttpClientImpl")
            .resolve();
    assertFalse(
        JdkHttpClientInst.asyncCompatible(impl, new TypeDescription.ForLoadedType(Object.class)));
  }

  @Test
  void rejectsChangedConnectionSignatures() {
    assertTrue(
        JdkHttpClientInst.connectionCompatible(
            new TypeDescription.ForLoadedType(Connection.class)));
    assertFalse(
        JdkHttpClientInst.connectionCompatible(
            new TypeDescription.ForLoadedType(ChangedSecure.class)));
    assertFalse(
        JdkHttpClientInst.connectionCompatible(
            new TypeDescription.ForLoadedType(ChangedChannel.class)));
    assertFalse(
        JdkHttpClientInst.headersCompatible(new TypeDescription.ForLoadedType(Object.class)));
  }

  abstract static class Connection {
    abstract boolean isSecure();

    abstract SocketChannel channel();
  }

  abstract static class ChangedSecure {
    abstract boolean isSecure(boolean option);

    abstract SocketChannel channel();
  }

  abstract static class ChangedChannel {
    abstract boolean isSecure();

    abstract Object channel();
  }

  @Test
  void matchesJdkHttpClient() throws ClassNotFoundException {
    Class<?> httpClient = loadClass("java.net.http.HttpClient");
    assumeTrue(httpClient != null);

    assertTrue(JdkHttpClientInst.matches(httpClient));
    assertTrue(
        JdkHttpClientInst.matches(
            Class.forName("jdk.internal.net.http.HttpClientImpl$SelectorManager")));
    assertTrue(JdkHttpClientInst.matches(Class.forName("jdk.internal.net.http.AsyncEvent")));
    assertTrue(JdkHttpClientInst.matches(Class.forName("jdk.internal.net.http.HttpRequestImpl")));
    assertTrue(JdkHttpClientInst.matches(Class.forName("jdk.internal.net.http.Http1Request")));
    assertTrue(JdkHttpClientInst.matches(Class.forName("jdk.internal.net.http.MultiExchange")));
    assertFalse(JdkHttpClientInst.matches(Object.class));
  }

  private static Class<?> loadClass(String className) {
    try {
      return Class.forName(className);
    } catch (ClassNotFoundException ignored) {
      return null;
    }
  }
}
