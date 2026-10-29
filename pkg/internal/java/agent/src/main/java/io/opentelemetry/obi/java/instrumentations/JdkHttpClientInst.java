/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.Agent;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.JdkHttpClientPropagation;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.List;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.pool.TypePool;

public class JdkHttpClientInst {
  private static final String HTTP_CLIENT_CLASS = "java.net.http.HttpClient";
  private static final String SELECTOR_MANAGER_CLASS =
      "jdk.internal.net.http.HttpClientImpl$SelectorManager";
  private static final String ASYNC_EVENT_CLASS = "jdk.internal.net.http.AsyncEvent";
  private static final String HTTP_REQUEST_CLASS = "jdk.internal.net.http.HttpRequestImpl";
  private static final String HTTP1_REQUEST_CLASS = "jdk.internal.net.http.Http1Request";

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.hasSuperType(ElementMatchers.named(HTTP_CLIENT_CLASS))
        .or(ElementMatchers.named(SELECTOR_MANAGER_CLASS))
        .or(ElementMatchers.named(HTTP_REQUEST_CLASS))
        .or(ElementMatchers.named(HTTP1_REQUEST_CLASS))
        .or(ElementMatchers.hasSuperType(ElementMatchers.named(ASYNC_EVENT_CLASS)));
  }

  public static boolean matches(Class<?> clazz) {
    if (SELECTOR_MANAGER_CLASS.equals(clazz.getName())
        || HTTP_REQUEST_CLASS.equals(clazz.getName())
        || HTTP1_REQUEST_CLASS.equals(clazz.getName())) {
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

  public static AgentBuilder.Transformer transformer(boolean propagation) {
    final boolean enabled = propagation && propagationCompatible();
    try {
      System.setProperty(JdkHttpClientPropagation.PROPERTY, Boolean.toString(enabled));
    } catch (SecurityException ignored) {
    }
    return (builder, type, classLoader, module, protectionDomain) -> {
      if (enabled) {
        builder =
            builder
                .visit(
                    Advice.to(SynchronousSendAdvice.class)
                        .on(
                            ElementMatchers.named("send")
                                .and(
                                    ElementMatchers.isDeclaredBy(
                                        ElementMatchers.named(
                                            "jdk.internal.net.http.HttpClientImpl")))
                                .and(ElementMatchers.takesArguments(2))
                                .and(
                                    ElementMatchers.takesArgument(
                                        0, ElementMatchers.named("java.net.http.HttpRequest")))
                                .and(
                                    ElementMatchers.takesArgument(
                                        1,
                                        ElementMatchers.named(
                                            "java.net.http.HttpResponse$BodyHandler")))
                                .and(
                                    ElementMatchers.returns(
                                        ElementMatchers.named("java.net.http.HttpResponse")))))
                .visit(
                    Advice.to(AsynchronousSendAdvice.class)
                        .on(
                            ElementMatchers.named("sendAsync")
                                .and(ElementMatchers.isPublic())
                                .and(
                                    ElementMatchers.isDeclaredBy(
                                        ElementMatchers.named(
                                            "jdk.internal.net.http.HttpClientImpl")))))
                .visit(
                    Advice.to(RequestAdvice.class)
                        .on(
                            ElementMatchers.isConstructor()
                                .and(
                                    ElementMatchers.isDeclaredBy(
                                        ElementMatchers.named(HTTP_REQUEST_CLASS)))))
                .visit(
                    Advice.to(HeadersAdvice.class)
                        .on(
                            ElementMatchers.named("headers")
                                .and(ElementMatchers.takesArguments(0))
                                .and(ElementMatchers.returns(List.class))
                                .and(
                                    ElementMatchers.isDeclaredBy(
                                        ElementMatchers.named(HTTP1_REQUEST_CLASS)))));
      }
      return builder
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
                  .on(ElementMatchers.named("handleEvent").and(ElementMatchers.takesArguments(2))))
          .visit(
              Advice.to(HandleAsyncEventAdvice.class)
                  .on(
                      ElementMatchers.named("handle")
                          .and(ElementMatchers.takesArguments(0))
                          .and(ElementMatchers.not(ElementMatchers.isAbstract()))));
    };
  }

  static boolean propagationCompatible() {
    try {
      TypePool pool = TypePool.Default.ofSystemLoader();
      if (!pool.describe(HTTP_CLIENT_CLASS).isResolved()) {
        return false;
      }
      boolean compatible =
          headersCompatible(pool.describe(HTTP1_REQUEST_CLASS).resolve())
              && connectionCompatible(
                  pool.describe("jdk.internal.net.http.HttpConnection").resolve());
      TypeDescription impl = pool.describe("jdk.internal.net.http.HttpClientImpl").resolve();
      compatible &=
          !pool.describe(HTTP_REQUEST_CLASS)
              .resolve()
              .getDeclaredMethods()
              .filter(
                  ElementMatchers.isConstructor()
                      .and(ElementMatchers.takesArguments(2))
                      .and(
                          ElementMatchers.takesArgument(
                              0, ElementMatchers.named("java.net.http.HttpRequest")))
                      .and(
                          ElementMatchers.takesArgument(
                              1, ElementMatchers.named("java.net.ProxySelector"))))
              .isEmpty();
      compatible &=
          !impl.getDeclaredMethods()
              .filter(
                  ElementMatchers.named("send")
                      .and(ElementMatchers.takesArguments(2))
                      .and(
                          ElementMatchers.takesArgument(
                              0, ElementMatchers.named("java.net.http.HttpRequest")))
                      .and(
                          ElementMatchers.takesArgument(
                              1, ElementMatchers.named("java.net.http.HttpResponse$BodyHandler")))
                      .and(
                          ElementMatchers.returns(
                              ElementMatchers.named("java.net.http.HttpResponse"))))
              .isEmpty();
      // send() delegates to a private overload; public sendAsync() must be excluded.
      compatible &=
          !impl.getDeclaredMethods()
              .filter(
                  ElementMatchers.named("sendAsync")
                      .and(ElementMatchers.isPrivate())
                      .and(ElementMatchers.takesArguments(4)))
              .isEmpty();
      if (compatible) {
        return true;
      }
    } catch (Throwable ignored) {
    }
    if (Agent.debugOn) {
      System.err.println(
          "[OBI] Java HttpClient header propagation disabled: unsupported JDK HTTP client layout");
    }
    return false;
  }

  static boolean connectionCompatible(TypeDescription type) {
    return !type.getDeclaredMethods()
            .filter(
                ElementMatchers.named("isSecure")
                    .and(ElementMatchers.takesArguments(0))
                    .and(ElementMatchers.returns(boolean.class)))
            .isEmpty()
        && !type.getDeclaredMethods()
            .filter(
                ElementMatchers.named("channel")
                    .and(ElementMatchers.takesArguments(0))
                    .and(ElementMatchers.returns(SocketChannel.class)))
            .isEmpty();
  }

  static boolean headersCompatible(TypeDescription type) {
    return !type.getDeclaredFields()
            .filter(
                ElementMatchers.named("request")
                    .and(ElementMatchers.fieldType(ElementMatchers.named(HTTP_REQUEST_CLASS))))
            .isEmpty()
        && !type.getDeclaredFields()
            .filter(
                ElementMatchers.named("connection")
                    .and(
                        ElementMatchers.fieldType(
                            ElementMatchers.named("jdk.internal.net.http.HttpConnection"))))
            .isEmpty()
        && !type.getDeclaredMethods()
            .filter(
                ElementMatchers.named("headers")
                    .and(ElementMatchers.takesArguments(0))
                    .and(ElementMatchers.returns(List.class)))
            .isEmpty();
  }

  public static final class SynchronousSendAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static JdkHttpClientPropagation enter() {
      JdkHttpClientPropagation scope = JdkHttpClientPropagation.enter();
      JdkHttpClientPropagation.captureParent(scope);
      return scope;
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter JdkHttpClientPropagation scope) {
      JdkHttpClientPropagation.exit(scope);
    }
  }

  public static final class AsynchronousSendAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static JdkHttpClientPropagation enter() {
      return JdkHttpClientPropagation.suspend();
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter JdkHttpClientPropagation scope) {
      JdkHttpClientPropagation.restore(scope);
    }
  }

  public static final class RequestAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void exit(
        @Advice.This Object request,
        @Advice.AllArguments Object[] arguments,
        @Advice.Origin("#d") String descriptor) {
      JdkHttpClientPropagation.register(
          request,
          arguments,
          descriptor.equals("(Ljava/net/http/HttpRequest;Ljava/net/ProxySelector;)V"));
    }
  }

  public static final class HeadersAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void exit(
        @Advice.FieldValue("request") Object request,
        @Advice.FieldValue("connection") Object connection,
        @Advice.Return(readOnly = false) List<ByteBuffer> headers)
        throws Exception {
      if (connection == null || !JdkHttpClientPropagation.contains(request)) {
        return;
      }
      try {
        Method[] methods = JdkHttpClientPropagation.connectionMethods;
        if (methods == null) {
          Class<?> type =
              Class.forName(
                  "jdk.internal.net.http.HttpConnection",
                  false,
                  connection.getClass().getClassLoader());
          Method secure = type.getDeclaredMethod("isSecure");
          Method channel = type.getDeclaredMethod("channel");
          secure.setAccessible(true);
          channel.setAccessible(true);
          Method expectContinue =
              Class.forName(
                      "java.net.http.HttpRequest", false, connection.getClass().getClassLoader())
                  .getMethod("expectContinue");
          methods = new Method[] {secure, channel, expectContinue};
          JdkHttpClientPropagation.connectionMethods = methods;
        }
        // A final response can complete send() before the header's plaintext notification.
        if (Boolean.TRUE.equals(
            methods[JdkHttpClientPropagation.EXPECT_CONTINUE_METHOD].invoke(request))) {
          return;
        }
        if (Boolean.TRUE.equals(
            methods[JdkHttpClientPropagation.IS_SECURE_METHOD].invoke(connection))) {
          SocketChannel channel =
              (SocketChannel) methods[JdkHttpClientPropagation.CHANNEL_METHOD].invoke(connection);
          if (channel != null && channel.isConnected()) {
            headers = JdkHttpClientPropagation.inject(request, channel, headers);
          }
        }
      } catch (Throwable error) {
        if (!(error instanceof java.io.IOException)) {
          JdkHttpClientPropagation.disable(error);
        }
      }
    }
  }

  @SuppressWarnings("unused")
  public static final class SendAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static long enter() {
      long threadId = ThreadInfo.currentTid();
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
