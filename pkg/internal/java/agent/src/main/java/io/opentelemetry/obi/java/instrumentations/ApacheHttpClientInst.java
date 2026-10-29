/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.instrumentations.data.ApacheHttpClientPropagation;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.pool.TypePool;

public class ApacheHttpClientInst {
  public static final String PROPERTY = ApacheHttpClientPropagation.PROPERTY;
  private static final String CLIENT = "org.apache.http.impl.client.CloseableHttpClient";
  private static final String EXECUTOR = "org.apache.http.protocol.HttpRequestExecutor";

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.hasSuperType(ElementMatchers.named(CLIENT))
        .or(ElementMatchers.named(EXECUTOR));
  }

  public static boolean matches(Class<?> clazz) {
    for (Class<?> type = clazz; type != null; type = type.getSuperclass()) {
      if (CLIENT.equals(type.getName()) || EXECUTOR.equals(type.getName())) {
        return true;
      }
    }
    return false;
  }

  static ElementMatcher.Junction<MethodDescription> execution() {
    return ElementMatchers.named("doExecute")
        .and(ElementMatchers.not(ElementMatchers.isAbstract()))
        .and(ElementMatchers.not(ElementMatchers.isBridge()))
        .and(ElementMatchers.takesArguments(3))
        .and(ElementMatchers.takesArgument(0, ElementMatchers.named("org.apache.http.HttpHost")))
        .and(ElementMatchers.takesArgument(1, ElementMatchers.named("org.apache.http.HttpRequest")))
        .and(
            ElementMatchers.takesArgument(
                2, ElementMatchers.named("org.apache.http.protocol.HttpContext")))
        .and(
            ElementMatchers.returns(
                ElementMatchers.named("org.apache.http.client.methods.CloseableHttpResponse")));
  }

  static ElementMatcher.Junction<MethodDescription> attempt() {
    return ElementMatchers.named("doSendRequest")
        .and(ElementMatchers.takesArguments(3))
        .and(ElementMatchers.takesArgument(0, ElementMatchers.named("org.apache.http.HttpRequest")))
        .and(
            ElementMatchers.takesArgument(
                1, ElementMatchers.named("org.apache.http.HttpClientConnection")))
        .and(
            ElementMatchers.takesArgument(
                2, ElementMatchers.named("org.apache.http.protocol.HttpContext")))
        .and(ElementMatchers.returns(ElementMatchers.named("org.apache.http.HttpResponse")));
  }

  static boolean compatible(ClassLoader loader) {
    try {
      TypePool pool = TypePool.Default.of(loader);
      return !pool.describe(CLIENT)
              .resolve()
              .getDeclaredMethods()
              .filter(ElementMatchers.named("doExecute").and(ElementMatchers.takesArguments(3)))
              .isEmpty()
          && !pool.describe(EXECUTOR).resolve().getDeclaredMethods().filter(attempt()).isEmpty()
          && !pool.describe("org.apache.http.conn.ManagedHttpClientConnection")
              .resolve()
              .getDeclaredMethods()
              .filter(
                  ElementMatchers.named("getSocket")
                      .and(ElementMatchers.takesArguments(0))
                      .and(ElementMatchers.returns(java.net.Socket.class)))
              .isEmpty();
    } catch (Throwable ignored) {
      return false;
    }
  }

  public static AgentBuilder.Transformer transformer(boolean propagation) {
    report(propagation ? "not-loaded" : "disabled");
    return (builder, type, classLoader, module, protectionDomain) -> {
      if (!propagation) {
        return builder;
      }
      if (!compatible(classLoader)) {
        report("unsupported-layout");
        return builder;
      }
      report("available");
      if (EXECUTOR.equals(type.getName())) {
        return builder.visit(Advice.to(SendAdvice.class).on(attempt()));
      }
      return builder.visit(Advice.to(ExecuteAdvice.class).on(execution()));
    };
  }

  private static void report(String status) {
    try {
      if (!"unavailable-foundation".equals(System.getProperty(PROPERTY))) {
        System.setProperty(PROPERTY, status);
      }
    } catch (SecurityException ignored) {
    }
  }

  public static final class ExecuteAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static ApacheHttpClientPropagation enter() {
      ApacheHttpClientPropagation scope = ApacheHttpClientPropagation.enter();
      ApacheHttpClientPropagation.captureParent(scope);
      return scope;
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter ApacheHttpClientPropagation scope) {
      ApacheHttpClientPropagation.exit(scope);
    }
  }

  public static final class SendAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static ApacheHttpClientPropagation enter(@Advice.Argument(1) Object connection)
        throws Exception {
      return ApacheHttpClientPropagation.beginAttempt(connection);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter ApacheHttpClientPropagation scope) {
      ApacheHttpClientPropagation.endAttempt(scope);
    }
  }
}
