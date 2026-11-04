/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.DynamicSpanDefinition;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.field.FieldDescription;
import net.bytebuddy.description.field.FieldList;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.pool.TypePool;

/** Byte Buddy matchers for configured dynamic Java method references. */
public final class DynamicSpanInst {
  private DynamicSpanInst() {}

  public static ElementMatcher<? super TypeDescription> type(List<DynamicSpanDefinition> spans) {
    return new ElementMatcher.Junction.AbstractBase<TypeDescription>() {
      @Override
      public boolean matches(TypeDescription type) {
        for (DynamicSpanDefinition span : spans) {
          if (matchesClass(span.reference(), type)) {
            return true;
          }
        }
        return false;
      }
    };
  }

  public static AgentBuilder.Transformer transformer(List<DynamicSpanDefinition> spans) {
    return (builder, type, classLoader, module, protectionDomain) -> {
      ElementMatcher.Junction<MethodDescription> methods = ElementMatchers.none();
      boolean selected = false;
      for (DynamicSpanDefinition span : spans) {
        JavaMethodReference reference = span.reference();
        if (!matchesClass(reference, type)) {
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
      Set<String> selectedBridges = selectedBridgeSignatures(type, spans);
      return builder
          .visit(Advice.to(DynamicSpanAdvice.class).on(methods))
          .visit(bridgeAdvice(type, selectedBridges));
    };
  }

  private static Set<String> selectedBridgeSignatures(
      TypeDescription type, List<DynamicSpanDefinition> spans) {
    Set<String> selected = new HashSet<>();
    for (MethodDescription method : type.getDeclaredMethods()) {
      if (!method.isBridge() || method.isAbstract()) continue;
      for (DynamicSpanDefinition span : spans) {
        if (matchesClass(span.reference(), type) && matchesMethod(method, span.reference())) {
          selected.add(method.getName() + method.getDescriptor());
          break;
        }
      }
    }
    return selected;
  }

  private static AsmVisitorWrapper bridgeAdvice(
      TypeDescription type, Set<String> selectedBridgeSignatures) {
    Map<String, MethodDescription> methods = new HashMap<>();
    for (MethodDescription method : type.getDeclaredMethods()) {
      if (method.isBridge()) methods.put(method.getName() + method.getDescriptor(), method);
    }
    Advice advice = Advice.to(DynamicSpanAdvice.class);
    return new AsmVisitorWrapper.AbstractBase() {
      @Override
      public ClassVisitor wrap(
          TypeDescription instrumentedType,
          ClassVisitor classVisitor,
          Implementation.Context implementationContext,
          TypePool typePool,
          FieldList<FieldDescription.InDefinedShape> fields,
          MethodList<?> declaredMethods,
          int writerFlags,
          int readerFlags) {
        return new ClassVisitor(Opcodes.ASM9, classVisitor) {
          @Override
          public MethodVisitor visitMethod(
              int access, String name, String descriptor, String signature, String[] exceptions) {
            MethodVisitor visitor =
                super.visitMethod(access, name, descriptor, signature, exceptions);
            String methodKey = name + descriptor;
            if ((access & Opcodes.ACC_BRIDGE) == 0
                || !selectedBridgeSignatures.contains(methodKey)) {
              return visitor;
            }
            MethodDescription method = methods.get(methodKey);
            return advice.wrap(
                instrumentedType,
                method,
                visitor,
                implementationContext,
                typePool,
                writerFlags,
                readerFlags);
          }
        };
      }
    };
  }

  private static int matchingMethods(TypeDescription type, JavaMethodReference reference) {
    int count = 0;
    for (MethodDescription method : type.getDeclaredMethods()) {
      if (method.isMethod() && !method.isAbstract() && matchesMethod(method, reference)) {
        count++;
      }
    }
    return count;
  }

  private static ElementMatcher.Junction<MethodDescription> method(JavaMethodReference reference) {
    ElementMatcher.Junction<MethodDescription> matcher =
        ElementMatchers.not(ElementMatchers.isConstructor())
            .and(ElementMatchers.not(ElementMatchers.isTypeInitializer()))
            .and(ElementMatchers.not(ElementMatchers.isBridge()))
            .and(ElementMatchers.not(ElementMatchers.isAbstract()))
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
    int size = method.getParameters().size();
    String[] canonicalNames = new String[size];
    String[] binaryNames = new String[size];
    String[] descriptors = new String[size];
    for (int i = 0; i < size; i++) {
      TypeDescription parameterType = method.getParameters().get(i).getType().asErasure();
      canonicalNames[i] = parameterName(parameterType, true);
      binaryNames[i] = parameterName(parameterType, false);
      descriptors[i] = parameterType.getDescriptor();
    }
    TypeDescription returnType = method.getReturnType().asErasure();
    return reference.matchesMethod(
        method.getName(),
        canonicalNames,
        binaryNames,
        descriptors,
        returnType.getDescriptor(),
        method.isBridge());
  }

  private static boolean matchesClass(JavaMethodReference reference, TypeDescription type) {
    String canonicalName;
    try {
      canonicalName = type.getCanonicalName();
    } catch (RuntimeException | LinkageError error) {
      canonicalName = null;
    }
    return reference.matchesClass(type.getInternalName(), type.getName(), canonicalName);
  }

  private static String parameterName(TypeDescription type, boolean canonical) {
    if (type.isArray()) return parameterName(type.getComponentType(), canonical) + "[]";
    String name = canonical ? type.getCanonicalName() : type.getName();
    return name == null ? "" : name;
  }
}
