/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import io.opentelemetry.obi.java.ebpf.CustomSpanPacket;
import io.opentelemetry.obi.java.instrumentations.JavaMethodReference;
import java.lang.instrument.Instrumentation;
import java.lang.invoke.MethodType;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/** Bootstrap-visible state and custom-span emitter used by dynamic method advice. */
public final class DynamicSpanRuntime {
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final Object LOCK = new Object();
  private static volatile List<DynamicSpanDefinition> definitions = Collections.emptyList();
  private static volatile Map<Class<?>, Map<String, List<String>>> spansByClass =
      Collections.synchronizedMap(new WeakHashMap<>());
  private static volatile Set<String> reportedResolutionErrors = Collections.emptySet();
  private static volatile Instrumentation instrumentation;
  private static final Map<Class<?>, String> desiredTransformations = new WeakHashMap<>();
  private static volatile ScheduledExecutorService refresher;
  private static volatile Consumer<byte[]> emitter = CustomSpanPacket::emit;

  private DynamicSpanRuntime() {}

  public static void configure(List<DynamicSpanDefinition> configured, Instrumentation inst) {
    if (configured == null || configured.isEmpty()) {
      return;
    }
    synchronized (LOCK) {
      definitions = Collections.unmodifiableList(new ArrayList<>(configured));
      instrumentation = inst;
      refresh();
      if (refresher == null) {
        refresher =
            Executors.newSingleThreadScheduledExecutor(
                runnable -> {
                  Thread thread = new Thread(runnable, "obi-dynamic-span-resolution");
                  thread.setDaemon(true);
                  return thread;
                });
        refresher.scheduleWithFixedDelay(DynamicSpanRuntime::refreshSafely, 1, 1, TimeUnit.SECONDS);
      }
    }
  }

  private static void refreshSafely() {
    try {
      synchronized (LOCK) {
        refresh();
      }
    } catch (Throwable error) {
      if (Agent.debugOn) {
        System.err.println("Failed to refresh dynamic Java method references: " + error);
      }
    }
  }

  private static void refresh() {
    Instrumentation inst = instrumentation;
    if (inst == null) {
      return;
    }

    Class<?>[] loadedClasses = inst.getAllLoadedClasses();
    Map<Class<?>, Map<String, List<String>>> next = new WeakHashMap<>();
    Set<String> errors = new HashSet<>();
    for (DynamicSpanDefinition definition : definitions) {
      JavaMethodReference reference = definition.reference();
      for (Class<?> targetClass : loadedClasses) {
        String canonicalName = null;
        try {
          canonicalName = targetClass.getCanonicalName();
        } catch (LinkageError | SecurityException ignored) {
          // Binary and internal selectors can still resolve without canonical metadata.
        }
        if (!reference.matchesClass(
            targetClass.getName().replace('.', '/'), targetClass.getName(), canonicalName)) {
          continue;
        }
        List<Method> matches;
        try {
          matches = matchingMethods(targetClass, reference);
        } catch (LinkageError | SecurityException error) {
          errors.add(
              resolutionError(definition, targetClass, "could not inspect methods: " + error));
          continue;
        }
        if (matches.isEmpty()) {
          errors.add(resolutionError(definition, targetClass, "unresolved method reference"));
          continue;
        }
        for (Method method : matches) {
          String signature = methodSignature(method);
          next.computeIfAbsent(targetClass, ignored -> new HashMap<>())
              .computeIfAbsent(signature, ignored -> new ArrayList<>())
              .add(definition.name());
        }
      }
    }

    Map<Class<?>, Map<String, List<String>>> resolved = freezeByClass(next);
    spansByClass = resolved;

    List<Class<?>> retransform = new ArrayList<>();
    Set<Class<?>> stillLoaded = new HashSet<>();
    for (Class<?> type : loadedClasses) {
      stillLoaded.add(type);
      String desired = transformationSignature(type, resolved);
      String previous = desiredTransformations.put(type, desired);
      if (previous != null && !previous.equals(desired)) {
        retransform.add(type);
      }
    }
    desiredTransformations.keySet().removeIf(type -> !stillLoaded.contains(type));
    retransformClasses(inst, retransform);

    Set<String> newErrors = new HashSet<>(errors);
    newErrors.removeAll(reportedResolutionErrors);
    for (String error : newErrors) {
      System.err.println("Dynamic Java span resolution: " + error);
    }
    reportedResolutionErrors = errors;
  }

  public static SpanState[] enter(Method method) {
    if (method == null) {
      return null;
    }
    return enter(method.getDeclaringClass(), method.getName(), methodDescriptor(method));
  }

  public static SpanState[] enter(Class<?> declaringClass, String methodName, String descriptor) {
    List<String> names = namesFor(declaringClass, methodName + descriptor);
    if (names == null && !definitions.isEmpty()) {
      refreshSafely();
      names = namesFor(declaringClass, methodName + descriptor);
    }
    if (names == null || names.isEmpty()) {
      return null;
    }
    long startWall = System.currentTimeMillis() * 1_000_000L;
    long startMono = System.nanoTime();
    SpanState[] states = new SpanState[names.size()];
    for (int i = 0; i < names.size(); i++) {
      states[i] = new SpanState(names.get(i), startWall, startMono, randomId(16), randomId(8));
    }
    return states;
  }

  public static void exit(SpanState[] states, Throwable error) {
    if (states == null) {
      return;
    }
    long end = states[0].startWallNanos + Math.max(1, System.nanoTime() - states[0].startMonoNanos);
    for (SpanState state : states) {
      try {
        emitter.accept(encode(state, end, error));
      } catch (Throwable emitError) {
        if (Agent.debugOn) {
          System.err.println("Failed to emit dynamic Java span: " + emitError);
        }
      }
    }
  }

  private static List<String> namesFor(Class<?> declaringClass, String signature) {
    Map<String, List<String>> methods = spansByClass.get(declaringClass);
    return methods == null ? null : methods.get(signature);
  }

  private static Map<Class<?>, Map<String, List<String>>> freezeByClass(
      Map<Class<?>, Map<String, List<String>>> methodsByClass) {
    Map<Class<?>, Map<String, List<String>>> weak =
        Collections.synchronizedMap(new WeakHashMap<>());
    for (Map.Entry<Class<?>, Map<String, List<String>>> entry : methodsByClass.entrySet()) {
      Map<String, List<String>> methods = new HashMap<>();
      for (Map.Entry<String, List<String>> method : entry.getValue().entrySet()) {
        List<String> names = method.getValue();
        Collections.sort(names);
        methods.put(method.getKey(), Collections.unmodifiableList(new ArrayList<>(names)));
      }
      weak.put(entry.getKey(), Collections.unmodifiableMap(methods));
    }
    return weak;
  }

  private static String transformationSignature(
      Class<?> type, Map<Class<?>, Map<String, List<String>>> resolved) {
    List<String> methods = new ArrayList<>();
    Map<String, List<String>> resolvedMethods = resolved.get(type);
    if (resolvedMethods == null) {
      return "";
    }
    try {
      for (Method method : type.getDeclaredMethods()) {
        String signature = methodSignature(method);
        List<String> names = resolvedMethods.get(signature);
        if (names != null) {
          methods.add(signature + "=" + names);
        }
      }
    } catch (LinkageError | SecurityException ignored) {
      return "";
    }
    Collections.sort(methods);
    return String.join(";", methods);
  }

  private static void retransformClasses(Instrumentation inst, List<Class<?>> classes) {
    for (Class<?> type : classes) {
      try {
        if (inst.isModifiableClass(type)) {
          inst.retransformClasses(type);
        }
      } catch (Throwable error) {
        if (Agent.debugOn) {
          System.err.println(
              "Failed to refresh dynamic Java span methods on " + type + ": " + error);
        }
      }
    }
  }

  private static byte[] encode(SpanState state, long endNanos, Throwable error) {
    StringBuilder json = new StringBuilder(384);
    json.append("{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":[{\"traceId\":\"")
        .append(state.traceId)
        .append("\",\"spanId\":\"")
        .append(state.spanId)
        .append("\",\"name\":\"")
        .append(escape(state.name))
        .append("\",\"kind\":1,\"startTimeUnixNano\":\"")
        .append(state.startWallNanos)
        .append("\",\"endTimeUnixNano\":\"")
        .append(endNanos)
        .append("\",\"attributes\":[]");
    if (error != null) {
      json.append(",\"status\":{\"code\":2,\"message\":\"")
          .append(
              escape(error.getMessage() == null ? error.getClass().getName() : error.getMessage()))
          .append("\"}");
    }
    json.append("}]}]}]}");
    return json.toString().getBytes(StandardCharsets.UTF_8);
  }

  private static String randomId(int bytes) {
    byte[] value = new byte[bytes];
    RANDOM.nextBytes(value);
    StringBuilder result = new StringBuilder(bytes * 2);
    for (byte b : value) {
      result.append(String.format("%02x", b & 0xff));
    }
    return result.toString();
  }

  private static String escape(String value) {
    StringBuilder escaped = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case '"':
          escaped.append("\\\"");
          break;
        case '\\':
          escaped.append("\\\\");
          break;
        case '\n':
          escaped.append("\\n");
          break;
        case '\r':
          escaped.append("\\r");
          break;
        case '\t':
          escaped.append("\\t");
          break;
        default:
          if (c < 0x20) {
            escaped.append(String.format("\\u%04x", (int) c));
          } else {
            escaped.append(c);
          }
      }
    }
    return escaped.toString();
  }

  private static List<Method> matchingMethods(Class<?> type, JavaMethodReference reference) {
    List<Method> matches = new ArrayList<>();
    for (Method method : type.getDeclaredMethods()) {
      if (Modifier.isAbstract(method.getModifiers())) {
        continue;
      }
      if (!reference.matchesMethod(
          method.getName(),
          canonicalParameterNames(method.getParameterTypes()),
          binaryParameterNames(method.getParameterTypes()),
          parameterDescriptors(method.getParameterTypes()),
          typeDescriptor(method.getReturnType()),
          method.isBridge())) {
        continue;
      }
      matches.add(method);
    }
    matches.sort(Comparator.comparing(DynamicSpanRuntime::methodSignature));
    return matches;
  }

  private static String[] canonicalParameterNames(Class<?>[] parameters) {
    String[] names = new String[parameters.length];
    for (int i = 0; i < parameters.length; i++) {
      names[i] = sourceTypeName(parameters[i], true);
    }
    return names;
  }

  private static String[] binaryParameterNames(Class<?>[] parameters) {
    String[] names = new String[parameters.length];
    for (int i = 0; i < parameters.length; i++) {
      names[i] = sourceTypeName(parameters[i], false);
    }
    return names;
  }

  private static String[] parameterDescriptors(Class<?>[] parameters) {
    String[] descriptors = new String[parameters.length];
    for (int i = 0; i < parameters.length; i++) {
      descriptors[i] = typeDescriptor(parameters[i]);
    }
    return descriptors;
  }

  private static String sourceTypeName(Class<?> type, boolean canonical) {
    if (type.isArray()) {
      return sourceTypeName(type.getComponentType(), canonical) + "[]";
    }
    String name = canonical ? type.getCanonicalName() : type.getName();
    return name == null ? "" : name;
  }

  private static String methodSignature(Method method) {
    return method.getName() + methodDescriptor(method);
  }

  private static String methodDescriptor(Method method) {
    return MethodType.methodType(method.getReturnType(), method.getParameterTypes())
        .toMethodDescriptorString();
  }

  private static String typeDescriptor(Class<?> type) {
    if (type.isArray()) return type.getName().replace('.', '/');
    if (!type.isPrimitive()) return "L" + type.getName().replace('.', '/') + ";";
    if (type == void.class) return "V";
    if (type == boolean.class) return "Z";
    if (type == byte.class) return "B";
    if (type == char.class) return "C";
    if (type == short.class) return "S";
    if (type == int.class) return "I";
    if (type == long.class) return "J";
    if (type == float.class) return "F";
    if (type == double.class) return "D";
    throw new IllegalArgumentException("unsupported Java type " + type);
  }

  private static String resolutionError(
      DynamicSpanDefinition definition, Class<?> targetClass, String state) {
    ClassLoader classLoader = targetClass.getClassLoader();
    String loader =
        classLoader == null
            ? "bootstrap"
            : classLoader.getClass().getName() + "@" + System.identityHashCode(classLoader);
    return definition.name() + " on " + targetClass.getName() + " from " + loader + " is " + state;
  }

  static void setEmitterForTest(Consumer<byte[]> testEmitter) {
    emitter = testEmitter;
  }

  static void refreshForTest() {
    refreshSafely();
  }

  static void resetForTest() {
    synchronized (LOCK) {
      if (refresher != null) {
        refresher.shutdownNow();
        refresher = null;
      }
      definitions = Collections.emptyList();
      spansByClass = Collections.synchronizedMap(new WeakHashMap<>());
      reportedResolutionErrors = Collections.emptySet();
      instrumentation = null;
      desiredTransformations.clear();
      emitter = CustomSpanPacket::emit;
    }
  }

  public static final class SpanState {
    private final String name;
    private final long startWallNanos;
    private final long startMonoNanos;
    private final String traceId;
    private final String spanId;

    private SpanState(
        String name, long startWallNanos, long startMonoNanos, String traceId, String spanId) {
      this.name = name;
      this.startWallNanos = startWallNanos;
      this.startMonoNanos = startMonoNanos;
      this.traceId = traceId;
      this.spanId = spanId;
    }
  }
}
