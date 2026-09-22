/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class JdkHttpClientInstTest {
  @Test
  void matchesJdkHttpClient() throws ClassNotFoundException {
    assertTrue(JdkHttpClientInst.matches(Class.forName("java.net.http.HttpClient")));
    assertTrue(
        JdkHttpClientInst.matches(
            Class.forName("jdk.internal.net.http.HttpClientImpl$SelectorManager")));
    assertTrue(JdkHttpClientInst.matches(Class.forName("jdk.internal.net.http.AsyncEvent")));
    assertFalse(JdkHttpClientInst.matches(Object.class));
  }
}
