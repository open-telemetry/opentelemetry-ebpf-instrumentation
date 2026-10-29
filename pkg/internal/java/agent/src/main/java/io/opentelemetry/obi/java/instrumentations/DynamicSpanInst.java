/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.DynamicSpanDefinition;
import io.opentelemetry.obi.java.DynamicSpanRuntime;
import java.util.List;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

/** Byte Buddy matchers for configured dynamic Java method references. */
public final class DynamicSpanInst {
  private DynamicSpanInst() {}

  public static ElementMatcher<? super TypeDescription> type(List<DynamicSpanDefinition> spans) {
    return new ElementMatcher.Junction.AbstractBase<TypeDescription>() {
      @Override
      public boolean matches(TypeDescription type) {
        String name = canonicalName(type);
        for (DynamicSpanDefinition span : spans) {
          if (DynamicSpanRuntime.globMatches(span.reference().classSelector(), name)) {
            return true;
          }
        }
        return false;
      }
    };
  }

  public static AgentBuilder.Transformer transformer(List<DynamicSpanDefinition> spans) {
    return (builder, type, classLoader, module, protectionDomain) -> {
      String className = canonicalName(type);
      if (!DynamicSpanRuntime.isClassloaderUnique(className, classLoader)) {
        return builder;
      }
      ElementMatcher.Junction<MethodDescription> methods = ElementMatchers.none();
      boolean selected = false;
      for (DynamicSpanDefinition span : spans) {
        JavaMethodReference reference = span.reference();
        if (!DynamicSpanRuntime.globMatches(reference.classSelector(), className)) {
          continue;
        }
        int matches = matchingMethods(type, reference);
        if (matches == 0) {
          continue;
        }
        selected = true;
        methods = methods.or(method(reference));
      }
      if (!selected) {
        return builder;
      }
      return builder.visit(Advice.to(DynamicSpanAdvice.class).on(methods));
    };
  }

  private static int matchingMethods(TypeDescription type, JavaMethodReference reference) {
    int count = 0;
    for (MethodDescription method : type.getDeclaredMethods()) {
      if (method.isMethod()
          && !method.isSynthetic()
          && !method.isBridge()
          && matchesMethod(method, reference)) {
        count++;
      }
    }
    return count;
  }

  private static ElementMatcher.Junction<MethodDescription> method(JavaMethodReference reference) {
    ElementMatcher.Junction<MethodDescription> matcher =
        ElementMatchers.isMethod()
            .and(ElementMatchers.not(ElementMatchers.isSynthetic()))
            .and(ElementMatchers.not(ElementMatchers.isBridge()))
            .and(
                new ElementMatcher.Junction.AbstractBase<MethodDescription>() {
                  @Override
                  public boolean matches(MethodDescription method) {
                    return matchesMethod(method, reference);
                  }
                });
    return matcher;
  }

  private static boolean matchesMethod(MethodDescription method, JavaMethodReference reference) {
    if (!DynamicSpanRuntime.globMatches(reference.methodSelector(), method.getName())) {
      return false;
    }
    if (!reference.hasParameterList()) {
      return true;
    }
    if (method.getParameters().size() != reference.parameterTypes().size()) {
      return false;
    }
    for (int i = 0; i < method.getParameters().size(); i++) {
      TypeDescription parameterType = method.getParameters().get(i).getType().asErasure();
      String actual = parameterType.getCanonicalName();
      if (actual == null) {
        actual = parameterType.getActualName().replace('$', '.');
      }
      if (!reference.parameterTypes().get(i).equals(actual)) {
        return false;
      }
    }
    return true;
  }

  private static String canonicalName(TypeDescription type) {
    return type.getName().replace('$', '.');
  }
}
