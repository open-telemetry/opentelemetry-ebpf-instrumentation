/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.Agent;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class JdkHttpClientInst {
  private static final String HTTP_CLIENT_CLASS = "java.net.http.HttpClient";
  private static final String SELECTOR_MANAGER_CLASS =
      "jdk.internal.net.http.HttpClientImpl$SelectorManager";
  private static final String ASYNC_EVENT_CLASS = "jdk.internal.net.http.AsyncEvent";

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.hasSuperType(ElementMatchers.named(HTTP_CLIENT_CLASS))
        .or(ElementMatchers.named(SELECTOR_MANAGER_CLASS))
        .or(ElementMatchers.hasSuperType(ElementMatchers.named(ASYNC_EVENT_CLASS)));
  }

  public static boolean matches(Class<?> clazz) {
    if (SELECTOR_MANAGER_CLASS.equals(clazz.getName())) {
      return true;
    }
    for (Class<?> current = clazz; current != null; current = current.getSuperclass()) {
      if (HTTP_CLIENT_CLASS.equals(current.getName())
          || ASYNC_EVENT_CLASS.equals(current.getName())) {
        return true;
      }
    }
    return false;
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(SendAdvice.class)
                    .on(
                        ElementMatchers.namedOneOf("send", "sendAsync")
                            .and(ElementMatchers.isPublic())))
            .visit(
                Advice.to(RegisterEventAdvice.class)
                    .on(
                        ElementMatchers.namedOneOf("register", "eventUpdated")
                            .and(ElementMatchers.takesArguments(1))))
            .visit(
                Advice.to(HandleEventAdvice.class)
                    .on(
                        ElementMatchers.named("handleEvent")
                            .and(ElementMatchers.takesArguments(2))))
            .visit(
                Advice.to(HandleAsyncEventAdvice.class)
                    .on(
                        ElementMatchers.named("handle")
                            .and(ElementMatchers.takesArguments(0))
                            .and(ElementMatchers.not(ElementMatchers.isAbstract()))));
  }

  @SuppressWarnings("unused")
  public static final class SendAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static long enter() {
      long threadId = Agent.NativeLib.gettid();
      return SSLStorage.enterJdkHttpClientContext(threadId);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter long previousContext) {
      SSLStorage.restoreJdkHttpClientContext(previousContext);
    }
  }

  @SuppressWarnings("unused")
  public static final class RegisterEventAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.Argument(0) Object event) {
      SSLStorage.trackJdkHttpClientEvent(event);
    }
  }

  @SuppressWarnings("unused")
  public static final class HandleEventAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static long enter(@Advice.Argument(0) Object event) {
      return SSLStorage.enterJdkHttpClientEvent(event);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter long previousContext) {
      SSLStorage.restoreJdkHttpClientContext(previousContext);
    }
  }

  @SuppressWarnings("unused")
  public static final class HandleAsyncEventAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static long enter(@Advice.This Object event) {
      return SSLStorage.enterJdkHttpClientEvent(event);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter long previousContext) {
      SSLStorage.restoreJdkHttpClientContext(previousContext);
    }
  }
}
