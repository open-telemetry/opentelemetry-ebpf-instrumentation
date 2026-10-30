/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.*;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.type.TypeDescription;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HttpRequestExecutor;
import org.junit.jupiter.api.Test;

class ApacheHttpClientInstTest {
  @Test
  void transformsRealApacheMethodsWithoutMatchingOverloadsOrBridges() throws Exception {
    assertTrue(ApacheHttpClientInst.compatible(getClass().getClassLoader()));
    try (CloseableHttpClient client = HttpClients.createDefault()) {
      Class<?> implementation = client.getClass();
      assertTrue(ApacheHttpClientInst.matches(implementation));
      TypeDescription type = new TypeDescription.ForLoadedType(implementation);
      assertEquals(1, type.getDeclaredMethods().filter(ApacheHttpClientInst.execution()).size());
      for (Class<?> target : new Class<?>[] {implementation, HttpRequestExecutor.class}) {
        net.bytebuddy.dynamic.DynamicType.Builder<?> builder = new ByteBuddy().redefine(target);
        assertSame(
            builder,
            ApacheHttpClientInst.transformer(false)
                .transform(
                    builder, builder.toTypeDescription(), target.getClassLoader(), null, null));
        assertTrue(
            ApacheHttpClientInst.transformer(true)
                    .transform(
                        builder, builder.toTypeDescription(), target.getClassLoader(), null, null)
                    .make()
                    .getBytes()
                    .length
                > 0);
      }
    }
    TypeDescription base = new TypeDescription.ForLoadedType(CloseableHttpClient.class);
    assertTrue(base.getDeclaredMethods().filter(ApacheHttpClientInst.execution()).isEmpty());
  }

  @Test
  void rejectsOtherClientsAndMissingLayouts() {
    assertFalse(ApacheHttpClientInst.matches(Object.class));
    assertFalse(ApacheHttpClientInst.compatible(new ClassLoader(null) {}));
    for (String name :
        new String[] {
          "org.apache.hc.client5.http.impl.classic.CloseableHttpClient",
          "org.apache.http.impl.nio.client.CloseableHttpAsyncClient",
          "java.net.http.HttpClient"
        }) {
      assertFalse(
          ApacheHttpClientInst.type()
              .matches(new ByteBuddy().subclass(Object.class).name(name).toTypeDescription()));
    }
  }
}
