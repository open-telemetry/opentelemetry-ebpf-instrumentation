/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import io.opentelemetry.obi.java.ebpf.CustomSpanPacket;
import io.opentelemetry.obi.java.instrumentations.JavaMethodReference;
import java.lang.instrument.Instrumentation;
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
import java.util.regex.Pattern;

/** Bootstrap-visible state and custom-span emitter used by dynamic method advice. */
public final class DynamicSpanRuntime {
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final Object LOCK = new Object();
  private static volatile List<DynamicSpanDefinition> definitions = Collections.emptyList();
  private static volatile Map<String, List<String>> spansByMethod = Collections.emptyMap();
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

    Map<String, List<Class<?>>> classesByName = new HashMap<>();
    for (Class<?> type : inst.getAllLoadedClasses()) {
      String name = canonicalName(type);
      if (name != null) {
        classesByName.computeIfAbsent(name, ignored -> new ArrayList<>()).add(type);
      }
    }

    Map<String, List<String>> next = new HashMap<>();
    Set<String> errors = new HashSet<>();
    for (DynamicSpanDefinition definition : definitions) {
      JavaMethodReference reference = definition.reference();
      for (Map.Entry<String, List<Class<?>>> entry : classesByName.entrySet()) {
        String className = entry.getKey();
        if (!globMatches(reference.classSelector(), className)) {
          continue;
        }
        if (entry.getValue().size() != 1) {
          errors.add(resolutionError(definition, className, "ambiguous classloader definitions"));
          continue;
        }

        Class<?> targetClass = entry.getValue().get(0);
        List<Method> matches;
        try {
          matches = matchingMethods(targetClass, reference);
        } catch (LinkageError | SecurityException error) {
          errors.add(resolutionError(definition, className, "could not inspect methods: " + error));
          continue;
        }
        if (matches.isEmpty()) {
          errors.add(resolutionError(definition, className, "unresolved method reference"));
          continue;
        }
        for (Method method : matches) {
          String key = methodKey(method);
          next.computeIfAbsent(key, ignored -> new ArrayList<>()).add(definition.name());
        }
      }
    }

    for (List<String> names : next.values()) {
      Collections.sort(names);
    }
    Map<String, List<String>> immutable = new HashMap<>();
    for (Map.Entry<String, List<String>> entry : next.entrySet()) {
      immutable.put(entry.getKey(), Collections.unmodifiableList(entry.getValue()));
    }
    spansByMethod = Collections.unmodifiableMap(immutable);

    List<Class<?>> retransform = new ArrayList<>();
    Set<Class<?>> stillLoaded = new HashSet<>();
    for (List<Class<?>> definitionsForName : classesByName.values()) {
      for (Class<?> type : definitionsForName) {
        stillLoaded.add(type);
        String desired = transformationSignature(type, immutable);
        String previous = desiredTransformations.put(type, desired);
        if (previous != null && !previous.equals(desired)) {
          retransform.add(type);
        }
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
    List<String> names = spansByMethod.get(methodKey(method));
    if (names == null && !definitions.isEmpty()) {
      refreshSafely();
      names = spansByMethod.get(methodKey(method));
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

  public static boolean isClassloaderUnique(String className, ClassLoader classLoader) {
    Instrumentation inst = instrumentation;
    if (inst == null) {
      return true;
    }
    int definitionsFound = 0;
    boolean currentLoaderFound = false;
    for (Class<?> loaded : inst.getAllLoadedClasses()) {
      if (!className.equals(canonicalName(loaded))) {
        continue;
      }
      definitionsFound++;
      if (loaded.getClassLoader() == classLoader) {
        currentLoaderFound = true;
      }
      if (definitionsFound > 1) {
        return false;
      }
    }
    return definitionsFound == 0 || currentLoaderFound;
  }

  private static String transformationSignature(Class<?> type, Map<String, List<String>> resolved) {
    List<String> methods = new ArrayList<>();
    try {
      for (Method method : type.getDeclaredMethods()) {
        List<String> names = resolved.get(methodKey(method));
        if (names != null) {
          methods.add(methodKey(method) + "=" + names);
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
      if (method.isSynthetic() || method.isBridge() || Modifier.isAbstract(method.getModifiers())) {
        continue;
      }
      if (!globMatches(reference.methodSelector(), method.getName())) {
        continue;
      }
      if (reference.hasParameterList()
          && !parametersMatch(method.getParameterTypes(), reference.parameterTypes())) {
        continue;
      }
      matches.add(method);
    }
    matches.sort(Comparator.comparing(DynamicSpanRuntime::methodKey));
    return matches;
  }

  private static boolean parametersMatch(Class<?>[] actual, List<String> expected) {
    if (actual.length != expected.size()) {
      return false;
    }
    for (int i = 0; i < actual.length; i++) {
      if (!expected.get(i).equals(typeName(actual[i]))) {
        return false;
      }
    }
    return true;
  }

  private static String methodKey(Method method) {
    StringBuilder key =
        new StringBuilder(canonicalName(method.getDeclaringClass()))
            .append('#')
            .append(method.getName())
            .append('(');
    Class<?>[] parameters = method.getParameterTypes();
    for (int i = 0; i < parameters.length; i++) {
      if (i > 0) {
        key.append(',');
      }
      key.append(typeName(parameters[i]));
    }
    return key.append(')').toString();
  }

  private static String typeName(Class<?> type) {
    if (type.isArray()) {
      return typeName(type.getComponentType()) + "[]";
    }
    String name = type.getCanonicalName();
    return name == null ? type.getName().replace('$', '.') : name;
  }

  private static String canonicalName(Class<?> type) {
    return type.getName().replace('$', '.');
  }

  private static String resolutionError(
      DynamicSpanDefinition definition, String className, String state) {
    return definition.name() + " on " + className + " is " + state;
  }

  public static boolean globMatches(String pattern, String value) {
    StringBuilder regex = new StringBuilder("^");
    for (int i = 0; i < pattern.length(); i++) {
      char c = pattern.charAt(i);
      if (c == '*') {
        regex.append(".*");
      } else if (c == '?') {
        regex.append('.');
      } else {
        if ("\\.[]{}()+-^$|".indexOf(c) >= 0) {
          regex.append('\\');
        }
        regex.append(c);
      }
    }
    regex.append('$');
    return Pattern.matches(regex.toString(), value);
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
      spansByMethod = Collections.emptyMap();
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
