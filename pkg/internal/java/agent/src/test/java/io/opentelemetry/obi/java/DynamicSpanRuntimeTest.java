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
import com.example.Nested.ActiveValue;
import com.example.OtherFixture;
import com.example.Outer;
import com.example.StringValue;
import com.example.ambiguous.AmbiguousFixture;
import com.example.reload.ReloadFixture;
import io.opentelemetry.obi.java.instrumentations.DynamicSpanInst;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.agent.ByteBuddyAgent;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.dynamic.loading.ClassLoadingStrategy;
import net.bytebuddy.implementation.StubMethod;
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
                "hotspot.full", "com/example/DynamicSpanFixture.run()Ljava/lang/String;"),
            new DynamicSpanDefinition(
                "hotspot.partial", "com.example.DynamicSpanFixture::overloaded(I)"),
            new DynamicSpanDefinition("nested.canonical", "com.example.Nested.ActiveValue#ping()"),
            new DynamicSpanDefinition("nested.binary", "com.example.Nested$ActiveValue::ping()V"),
            new DynamicSpanDefinition(
                "typed.overload", "com.example.DynamicSpanFixture#overloaded(int)"),
            new DynamicSpanDefinition(
                "array.signature", "com.example.DynamicSpanFixture#array(java.lang.String[])"),
            new DynamicSpanDefinition(
                "nested.parameter", "com.example.Nested#accept(com.example.Nested.Value)"),
            new DynamicSpanDefinition(
                "nested.binary.array",
                "com.example.DynamicSpanFixture#nestedArray(com.example.Nested$ActiveValue[])"),
            new DynamicSpanDefinition(
                "primitive.array", "com.example.DynamicSpanFixture#primitiveArray(int[])"),
            new DynamicSpanDefinition("valid.sibling", "com.example.OtherFixture#ok()"),
            new DynamicSpanDefinition(
                "all.loader.copies", "com.example.ambiguous.AmbiguousFixture#run()"),
            new DynamicSpanDefinition(
                "unresolved.sibling", "com.example.DynamicSpanFixture#missing()"),
            new DynamicSpanDefinition(
                "all.overloads", "com.example.DynamicSpanFixture#overloaded"));

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
    assertEquals("first", DynamicSpanFixture.overloaded("first"));
    assertEquals("first", DynamicSpanFixture.array(new String[] {"first"}));
    assertEquals(1, DynamicSpanFixture.nestedArray(new ActiveValue[] {new ActiveValue()}));
    assertEquals(2, DynamicSpanFixture.primitiveArray(new int[] {1, 2}));
    assertEquals("accepted", Nested.accept(new Nested.Value()));
    new ActiveValue().ping();
    assertEquals("ok", OtherFixture.ok());
    assertEquals(14, payloads.size());
    String joined = "";
    for (byte[] payload : payloads) {
      joined += new String(payload, StandardCharsets.UTF_8);
    }
    assertTrue(joined.contains("glob.span"));
    assertTrue(joined.contains("hotspot.full"));
    assertTrue(joined.contains("hotspot.partial"));
    assertTrue(joined.contains("nested.canonical"));
    assertTrue(joined.contains("nested.binary"));
    assertTrue(joined.contains("typed.overload"));
    assertTrue(joined.contains("array.signature"));
    assertTrue(joined.contains("nested.parameter"));
    assertTrue(joined.contains("nested.binary.array"));
    assertTrue(joined.contains("primitive.array"));
    assertTrue(joined.contains("valid.sibling"));
    assertTrue(joined.contains("all.overloads"));
    assertFalse(joined.contains("unresolved.sibling"));

    Method run = AmbiguousFixture.class.getDeclaredMethod("run");
    DynamicSpanRuntime.SpanState[] firstLoader = DynamicSpanRuntime.enter(run);
    assertNotNull(firstLoader);
    DynamicSpanRuntime.exit(firstLoader, null);

    Class<?> duplicate =
        new DuplicateFixtureLoader()
            .loadFixture(AmbiguousFixture.class.getName(), AmbiguousFixture.class);
    assertEquals(AmbiguousFixture.class.getName(), duplicate.getName());
    DynamicSpanRuntime.refreshForTest();
    assertNotNull(DynamicSpanRuntime.enter(run));
    Method duplicateRun = duplicate.getDeclaredMethod("run");
    assertNotNull(DynamicSpanRuntime.enter(duplicateRun));
    assertNotNull(DynamicSpanRuntime.enter(OtherFixture.class.getDeclaredMethod("ok")));
    int beforeSecondLoaderCall = payloads.size();
    assertEquals("run", duplicateRun.invoke(null));
    assertTrue(payloads.size() > beforeSecondLoaderCall);
  }

  @Test
  void reevaluatesWhenDuplicateClassLoaderDefinitionUnloads() throws Exception {
    Class<?> duplicate =
        new DuplicateFixtureLoader()
            .loadFixture(ReloadFixture.class.getName(), ReloadFixture.class);
    AtomicReference<Class<?>[]> loaded =
        new AtomicReference<>(new Class<?>[] {ReloadFixture.class, duplicate});
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
                  if (method.getName().equals("retransformClasses")) return null;
                  throw new UnsupportedOperationException(method.getName());
                });
    List<DynamicSpanDefinition> definitions =
        Arrays.asList(
            new DynamicSpanDefinition("reloadable", "com.example.reload.ReloadFixture#run()"));
    DynamicSpanRuntime.configure(definitions, instrumentation);
    Method run = ReloadFixture.class.getDeclaredMethod("run");
    assertNotNull(DynamicSpanRuntime.enter(run));
    assertNotNull(DynamicSpanRuntime.enter(duplicate.getDeclaredMethod("run")));

    loaded.set(new Class<?>[] {ReloadFixture.class});
    DynamicSpanRuntime.refreshForTest();

    assertNotNull(DynamicSpanRuntime.enter(run));
    assertNull(DynamicSpanRuntime.enter(duplicate.getDeclaredMethod("run")));
  }

  @Test
  void dynamicEntryAndExitWorkDoesNotSuppressNestedApplicationSpans() {
    List<byte[]> payloads = new ArrayList<>();
    DynamicSpanRuntime.setEmitterForTest(payloads::add);
    List<DynamicSpanDefinition> definitions =
        Arrays.asList(
            new DynamicSpanDefinition("outer.span", "com.example.DynamicSpanFixture#outer()"),
            new DynamicSpanDefinition("inner.span", "com.example.DynamicSpanFixture#inner()"));

    Instrumentation instrumentation = ByteBuddyAgent.install();
    DynamicSpanRuntime.configure(definitions, instrumentation);
    new AgentBuilder.Default()
        .disableClassFormatChanges()
        .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
        .type(DynamicSpanInst.type(definitions))
        .transform(DynamicSpanInst.transformer(definitions))
        .installOn(instrumentation);

    assertEquals("nested", DynamicSpanFixture.outer());
    assertEquals(2, payloads.size());
    String joined =
        payloads.stream()
            .map(payload -> new String(payload, StandardCharsets.UTF_8))
            .reduce("", String::concat);
    assertTrue(joined.contains("outer.span"));
    assertTrue(joined.contains("inner.span"));
  }

  @Test
  void internalWorkGuardIsClearedAfterRefreshAndEmitterFailures() throws Exception {
    Method run = DynamicSpanFixture.class.getDeclaredMethod("run");
    List<DynamicSpanDefinition> definitions =
        Arrays.asList(
            new DynamicSpanDefinition("run.span", "com.example.DynamicSpanFixture#run()"));
    int[] loadedClassCalls = {0};
    Instrumentation instrumentation =
        (Instrumentation)
            Proxy.newProxyInstance(
                Instrumentation.class.getClassLoader(),
                new Class<?>[] {Instrumentation.class},
                (proxy, method, arguments) -> {
                  if (method.getName().equals("getAllLoadedClasses")) {
                    if (++loadedClassCalls[0] > 1) {
                      throw new IllegalStateException("simulated refresh failure");
                    }
                    return new Class<?>[] {DynamicSpanFixture.class};
                  }
                  if (method.getName().equals("isModifiableClass")) return true;
                  if (method.getName().equals("retransformClasses")) return null;
                  throw new UnsupportedOperationException(method.getName());
                });
    DynamicSpanRuntime.configure(definitions, instrumentation);

    assertNull(DynamicSpanRuntime.enter(OtherFixture.class, "missing", "()V"));
    DynamicSpanRuntime.setEmitterForTest(
        payload -> {
          throw new AssertionError("simulated emitter failure");
        });
    DynamicSpanRuntime.SpanState[] first = DynamicSpanRuntime.enter(run);
    assertNotNull(first);
    DynamicSpanRuntime.exit(first, null);

    DynamicSpanRuntime.SpanState[] second = DynamicSpanRuntime.enter(run);
    assertNotNull(second);
    DynamicSpanRuntime.exit(second, null);
  }

  @Test
  void secureRandomSelectedMethodDoesNotRecursivelyInstrumentRuntimeInternals() {
    SecureRandom random = new SecureRandom();
    List<byte[]> payloads = new ArrayList<>();
    AtomicReference<DynamicSpanRuntime.SpanState[]> reentrantDuringRefresh =
        new AtomicReference<>();
    AtomicReference<DynamicSpanRuntime.SpanState[]> reentrantDuringEmit = new AtomicReference<>();
    Method nextBytes;
    try {
      nextBytes = SecureRandom.class.getDeclaredMethod("nextBytes", byte[].class);
    } catch (NoSuchMethodException error) {
      throw new AssertionError(error);
    }
    List<DynamicSpanDefinition> definitions =
        Arrays.asList(
            new DynamicSpanDefinition(
                "secure.random", "java.security.SecureRandom#nextBytes(byte[])"));
    int[] loadedClassCalls = {0};
    Instrumentation instrumentation =
        (Instrumentation)
            Proxy.newProxyInstance(
                Instrumentation.class.getClassLoader(),
                new Class<?>[] {Instrumentation.class},
                (proxy, method, arguments) -> {
                  if (method.getName().equals("getAllLoadedClasses")) {
                    if (++loadedClassCalls[0] > 1) {
                      reentrantDuringRefresh.set(
                          DynamicSpanRuntime.enter(
                              nextBytes.getDeclaringClass(), nextBytes.getName(), "([B)V"));
                      random.nextBytes(new byte[8]);
                    }
                    return new Class<?>[] {SecureRandom.class};
                  }
                  if (method.getName().equals("isModifiableClass")) return true;
                  if (method.getName().equals("retransformClasses")) return null;
                  throw new UnsupportedOperationException(method.getName());
                });
    DynamicSpanRuntime.configure(definitions, instrumentation);
    DynamicSpanRuntime.setEmitterForTest(
        payload -> {
          payloads.add(payload);
          random.nextBytes(new byte[8]);
          reentrantDuringEmit.set(
              DynamicSpanRuntime.enter(
                  nextBytes.getDeclaringClass(), nextBytes.getName(), "([B)V"));
        });

    assertNull(DynamicSpanRuntime.enter(OtherFixture.class, "missing", "()V"));
    assertNull(reentrantDuringRefresh.get());
    DynamicSpanRuntime.SpanState[] states = DynamicSpanRuntime.enter(nextBytes);
    assertNotNull(states);
    DynamicSpanRuntime.exit(states, null);

    assertEquals(1, payloads.size());
    assertTrue(new String(payloads.get(0), StandardCharsets.UTF_8).contains("secure.random"));
    assertNull(reentrantDuringEmit.get());
  }

  @Test
  void broadMethodReferenceSkipsBridgeButExactDescriptorSelectsIt() {
    List<byte[]> payloads = new ArrayList<>();
    DynamicSpanRuntime.setEmitterForTest(payloads::add);
    List<DynamicSpanDefinition> definitions =
        Arrays.asList(
            new DynamicSpanDefinition("broad.get", "com.example.StringValue#get"),
            new DynamicSpanDefinition(
                "bridge.get", "com/example/StringValue.get()Ljava/lang/Object;"));

    Instrumentation instrumentation = ByteBuddyAgent.install();
    DynamicSpanRuntime.configure(definitions, instrumentation);
    new AgentBuilder.Default()
        .disableClassFormatChanges()
        .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
        .type(DynamicSpanInst.type(definitions))
        .transform(DynamicSpanInst.transformer(definitions))
        .installOn(instrumentation);

    Supplier<String> value = new StringValue();
    Method bridge =
        Arrays.stream(StringValue.class.getDeclaredMethods())
            .filter(Method::isBridge)
            .findFirst()
            .orElseThrow(AssertionError::new);
    assertNotNull(DynamicSpanRuntime.enter(bridge));
    assertEquals("value", value.get());
    String joined =
        payloads.stream()
            .map(payload -> new String(payload, StandardCharsets.UTF_8))
            .reduce("", String::concat);
    assertEquals(2, payloads.size(), joined);
    assertTrue(joined.contains("broad.get"));
    assertTrue(joined.contains("bridge.get"));
  }

  @Test
  void canonicalClassSelectorMatchesBothNestedAndTopLevelMetadataNames() throws Exception {
    List<byte[]> payloads = new ArrayList<>();
    DynamicSpanRuntime.setEmitterForTest(payloads::add);
    Class<?> topLevelCollision =
        new ByteBuddy()
            .subclass(Object.class)
            .name("com.example.Outer.Inner")
            .defineMethod(
                "run",
                void.class,
                java.lang.reflect.Modifier.PUBLIC | java.lang.reflect.Modifier.STATIC)
            .intercept(StubMethod.INSTANCE)
            .make()
            .load(Outer.class.getClassLoader(), ClassLoadingStrategy.Default.INJECTION)
            .getLoaded();
    assertEquals(Outer.Inner.class.getCanonicalName(), topLevelCollision.getCanonicalName());
    List<DynamicSpanDefinition> definitions =
        Arrays.asList(new DynamicSpanDefinition("both.types", "com.example.Outer.Inner#run()"));

    Instrumentation instrumentation = ByteBuddyAgent.install();
    DynamicSpanRuntime.configure(definitions, instrumentation);
    new AgentBuilder.Default()
        .disableClassFormatChanges()
        .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
        .type(DynamicSpanInst.type(definitions))
        .transform(DynamicSpanInst.transformer(definitions))
        .installOn(instrumentation);

    Outer.Inner.run();
    topLevelCollision.getDeclaredMethod("run").invoke(null);
    assertEquals(2, payloads.size());
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
