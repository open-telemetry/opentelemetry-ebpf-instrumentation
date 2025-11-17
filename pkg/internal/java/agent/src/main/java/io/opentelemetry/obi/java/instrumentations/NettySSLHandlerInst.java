/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class NettySSLHandlerInst {
  private static final String instClassName = "io.netty.handler.ssl.SslHandler";
  private static final Logger logger = Logger.getLogger("NettySSLHandlerInst");

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.named(instClassName);
  }

  public static boolean matches(Class<?> clazz) {
    return clazz.getName().equals(instClassName);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(UnwrapAdvice.class)
                    .on(ElementMatchers.named("unwrap").and(ElementMatchers.takesArguments(3))))
            .visit(
                Advice.to(WrapAdvice.class)
                    .on(ElementMatchers.named("wrap").and(ElementMatchers.takesArguments(2))));
  }

  public static final class UnwrapAdvice {
    @Advice.OnMethodEnter // (suppress = Throwable.class)
    public static void unwrap(@Advice.Argument(0) final Object ctx) {
      try {
        if (SSLStorage.getBootDebugOn().get(null).equals(true)) {
          logger.info("Netty SSL handler unwrap");
        }

        Object c =
            SSLStorage.getBootExtractMethod()
                .invoke(null, ctx); // static method, so null as instance

        @SuppressWarnings("unchecked")
        ThreadLocal<Object> threadLocal =
            (ThreadLocal<Object>)
                SSLStorage.getBootNettyConnectionField()
                    .get(null); // static field, so null as instance
        threadLocal.set(c);
      } catch (Exception x) {
        logger.log(Level.SEVERE, "Failed unwrap enter", x);
      }
    }

    @Advice.OnMethodExit // (suppress = Throwable.class)
    public static void unwrap() {
      try {
        @SuppressWarnings("unchecked")
        ThreadLocal<Object> threadLocal =
            (ThreadLocal<Object>)
                SSLStorage.getBootNettyConnectionField()
                    .get(null); // static field, so null as instance
        threadLocal.remove();
      } catch (Exception x) {
        logger.log(Level.SEVERE, "Failed unwrap exit", x);
      }
    }
  }

  public static final class WrapAdvice {
    @Advice.OnMethodEnter // (suppress = Throwable.class)
    public static void wrap(@Advice.Argument(0) final Object ctx) {
      try {
        if (SSLStorage.getBootDebugOn().get(null).equals(true)) {
          logger.info("Netty SSL handler wrap");
        }
        Object c =
            SSLStorage.getBootExtractMethod()
                .invoke(null, ctx); // static method, so null as instance

        @SuppressWarnings("unchecked")
        ThreadLocal<Object> threadLocal =
            (ThreadLocal<Object>)
                SSLStorage.getBootNettyConnectionField()
                    .get(null); // static field, so null as instance
        threadLocal.set(c);
      } catch (Exception x) {
        logger.log(Level.SEVERE, "Failed wrap enter", x);
      }
    }

    @Advice.OnMethodExit // (suppress = Throwable.class)
    public static void wrap() {
      try {
        @SuppressWarnings("unchecked")
        ThreadLocal<Object> threadLocal =
            (ThreadLocal<Object>)
                SSLStorage.getBootNettyConnectionField()
                    .get(null); // static field, so null as instance
        threadLocal.remove();
      } catch (Exception x) {
        logger.log(Level.SEVERE, "Failed wrap exit", x);
      }
    }
  }
}
