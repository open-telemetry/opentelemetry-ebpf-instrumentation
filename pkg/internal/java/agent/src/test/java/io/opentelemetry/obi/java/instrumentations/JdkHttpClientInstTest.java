/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import org.junit.jupiter.api.Test;

class JdkHttpClientInstTest {
  @Test
  void matchesJdkHttpClient() throws ClassNotFoundException {
    Class<?> httpClient = loadClass("java.net.http.HttpClient");
    assumeTrue(httpClient != null);

    assertTrue(JdkHttpClientInst.matches(httpClient));
    assertTrue(
        JdkHttpClientInst.matches(
            Class.forName("jdk.internal.net.http.HttpClientImpl$SelectorManager")));
    assertTrue(JdkHttpClientInst.matches(Class.forName("jdk.internal.net.http.AsyncEvent")));
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
