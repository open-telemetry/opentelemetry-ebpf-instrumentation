/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static net.bytebuddy.matcher.ElementMatchers.isProtected;
import static net.bytebuddy.matcher.ElementMatchers.isPublic;
import static net.bytebuddy.matcher.ElementMatchers.isStatic;
import static net.bytebuddy.matcher.ElementMatchers.isSubTypeOf;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.not;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;

public class ClassLoaderInst {
  public static ElementMatcher<? super TypeDescription> type() {
    return isSubTypeOf(ClassLoader.class);
  }

  public static boolean matches(Class<?> clazz) {
    return ClassLoader.class.isAssignableFrom(clazz);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, typeDescription, classLoader, module, protectionDomain) ->
        builder.visit(
            Advice.to(LoadClassAdvice.class)
                .on(
                    named("loadClass")
                        .and(
                            takesArguments(1)
                                .and(takesArgument(0, String.class))
                                .or(
                                    takesArguments(2)
                                        .and(takesArgument(0, String.class))
                                        .and(takesArgument(1, boolean.class))))
                        .and(isPublic().or(isProtected()))
                        .and(not(isStatic()))));
  }

  public static class LoadClassAdvice {
    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class, suppress = Throwable.class)
    public static Class<?> onEnter(@Advice.Argument(0) String name) {
      if (!name.startsWith("io.opentelemetry.obi.java.")) {
        return null;
      }

      try {
        return Class.forName(name, false, null);
      } catch (ClassNotFoundException ignored) {
        return null;
      }
    }

    @Advice.OnMethodExit
    public static void onExit(
        @Advice.Enter Class<?> bootstrapClass,
        @Advice.Return(readOnly = false) Class<?> loadedClass) {
      if (bootstrapClass != null) {
        loadedClass = bootstrapClass;
      }
    }
  }
}
