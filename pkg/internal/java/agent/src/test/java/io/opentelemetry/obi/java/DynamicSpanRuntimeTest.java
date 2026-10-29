/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.example.DynamicSpanFixture;
import com.example.Nested;
import com.example.OtherFixture;
import com.example.ambiguous.AmbiguousFixture;
import com.example.reload.ReloadFixture;
import io.opentelemetry.obi.java.instrumentations.DynamicSpanInst;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import net.bytebuddy.agent.ByteBuddyAgent;
import net.bytebuddy.agent.builder.AgentBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class DynamicSpanRuntimeTest {
  @AfterEach
  void reset() {
    DynamicSpanRuntime.resetForTest();
  }

  @Test
  void instrumentsClassAndMethodGlobsAndIsolatesResolutionFailures() throws Exception {
    List<byte[]> payloads = new ArrayList<>();
    DynamicSpanRuntime.setEmitterForTest(payloads::add);
    List<DynamicSpanDefinition> definitions =
        Arrays.asList(
            new DynamicSpanDefinition("glob.span", "com.example.DynamicSpan*#run*()"),
            new DynamicSpanDefinition(
                "typed.overload", "com.example.DynamicSpanFixture#overloaded(int)"),
            new DynamicSpanDefinition(
                "array.signature", "com.example.DynamicSpanFixture#array(java.lang.String[])"),
            new DynamicSpanDefinition(
                "nested.parameter", "com.example.Nested#accept(com.example.Nested.Value)"),
            new DynamicSpanDefinition("valid.sibling", "com.example.OtherFixture#ok()"),
            new DynamicSpanDefinition(
                "ambiguous.class", "com.example.ambiguous.AmbiguousFixture#run()"),
            new DynamicSpanDefinition(
                "unresolved.sibling", "com.example.DynamicSpanFixture#missing()"),
            new DynamicSpanDefinition(
                "ambiguous.overload", "com.example.DynamicSpanFixture#overloaded"));

    Instrumentation instrumentation = ByteBuddyAgent.install();
    DynamicSpanRuntime.configure(definitions, instrumentation);
    new AgentBuilder.Default()
        .disableClassFormatChanges()
        .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
        .type(DynamicSpanInst.type(definitions))
        .transform(DynamicSpanInst.transformer(definitions))
        .installOn(instrumentation);

    assertEquals("run", DynamicSpanFixture.run());
    assertEquals("sibling", DynamicSpanFixture.runSibling());
    assertEquals("5", DynamicSpanFixture.overloaded(5));
    assertEquals("first", DynamicSpanFixture.array(new String[] {"first"}));
    assertEquals("accepted", Nested.accept(new Nested.Value()));
    assertEquals("ok", OtherFixture.ok());
    assertEquals(6, payloads.size());
    String joined = "";
    for (byte[] payload : payloads) {
      joined += new String(payload, StandardCharsets.UTF_8);
    }
    assertTrue(joined.contains("glob.span"));
    assertTrue(joined.contains("typed.overload"));
    assertTrue(joined.contains("array.signature"));
    assertTrue(joined.contains("nested.parameter"));
    assertTrue(joined.contains("valid.sibling"));
    assertFalse(joined.contains("unresolved.sibling"));
    assertFalse(joined.contains("ambiguous.overload"));

    Method run = AmbiguousFixture.class.getDeclaredMethod("run");
    DynamicSpanRuntime.SpanState[] beforeDuplicate = DynamicSpanRuntime.enter(run);
    assertNotNull(beforeDuplicate);
    DynamicSpanRuntime.exit(beforeDuplicate, null);

    Class<?> duplicate =
        new DuplicateFixtureLoader()
            .loadFixture(AmbiguousFixture.class.getName(), AmbiguousFixture.class);
    assertEquals(AmbiguousFixture.class.getName(), duplicate.getName());
    DynamicSpanRuntime.refreshForTest();
    assertNull(DynamicSpanRuntime.enter(run));
    assertNotNull(DynamicSpanRuntime.enter(OtherFixture.class.getDeclaredMethod("ok")));
    int beforeAmbiguousCall = payloads.size();
    assertEquals("run", duplicate.getDeclaredMethod("run").invoke(null));
    assertEquals(beforeAmbiguousCall, payloads.size());
  }

  @Test
  void reevaluatesWhenDuplicateClassLoaderDefinitionUnloads() throws Exception {
    Class<?> duplicate =
        new DuplicateFixtureLoader()
            .loadFixture(ReloadFixture.class.getName(), ReloadFixture.class);
    AtomicReference<Class<?>[]> loaded =
        new AtomicReference<>(new Class<?>[] {ReloadFixture.class, duplicate});
    AtomicInteger retransforms = new AtomicInteger();
    Instrumentation instrumentation =
        (Instrumentation)
            Proxy.newProxyInstance(
                Instrumentation.class.getClassLoader(),
                new Class<?>[] {Instrumentation.class},
                (proxy, method, arguments) -> {
                  if (method.getName().equals("getAllLoadedClasses")) {
                    return loaded.get();
                  }
                  if (method.getName().equals("isModifiableClass")) {
                    return true;
                  }
                  if (method.getName().equals("retransformClasses")) {
                    retransforms.incrementAndGet();
                    return null;
                  }
                  throw new UnsupportedOperationException(method.getName());
                });
    List<DynamicSpanDefinition> definitions =
        Arrays.asList(
            new DynamicSpanDefinition("reloadable", "com.example.reload.ReloadFixture#run()"));
    DynamicSpanRuntime.configure(definitions, instrumentation);
    Method run = ReloadFixture.class.getDeclaredMethod("run");
    assertNull(DynamicSpanRuntime.enter(run));

    loaded.set(new Class<?>[] {ReloadFixture.class});
    DynamicSpanRuntime.refreshForTest();

    assertNotNull(DynamicSpanRuntime.enter(run));
    assertTrue(retransforms.get() > 0);
  }

  private static final class DuplicateFixtureLoader extends ClassLoader {
    private DuplicateFixtureLoader() {
      super(DynamicSpanRuntimeTest.class.getClassLoader());
    }

    Class<?> loadFixture(String name, Class<?> source) throws Exception {
      String resource = "/" + name.replace('.', '/') + ".class";
      try (InputStream input = source.getResourceAsStream(resource);
          ByteArrayOutputStream output = new ByteArrayOutputStream()) {
        byte[] buffer = new byte[1024];
        int read;
        while ((read = input.read(buffer)) >= 0) {
          output.write(buffer, 0, read);
        }
        byte[] bytecode = output.toByteArray();
        return defineClass(name, bytecode, 0, bytecode.length);
      }
    }
  }
}
