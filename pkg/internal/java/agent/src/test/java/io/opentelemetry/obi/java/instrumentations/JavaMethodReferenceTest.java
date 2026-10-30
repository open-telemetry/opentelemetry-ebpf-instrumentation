/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

class JavaMethodReferenceTest {
  @Test
  void parsesExactReferenceWithoutParameters() {
    JavaMethodReference reference =
        JavaMethodReference.parse("io.opentelemetry.contrib.PolicyProviderConfig#create");

    assertEquals("io.opentelemetry.contrib.PolicyProviderConfig", reference.classSelector());
    assertEquals("create", reference.methodSelector());
    assertFalse(reference.isClassGlob());
    assertFalse(reference.isMethodGlob());
    assertFalse(reference.hasParameterList());
    assertTrue(reference.parameterTypes().isEmpty());
  }

  @Test
  void parsesClassAndMethodGlobs() {
    JavaMethodReference reference =
        JavaMethodReference.parse("com.example.*Repository#find?By*(java.lang.String)");

    assertEquals("com.example.*Repository", reference.classSelector());
    assertEquals("find?By*", reference.methodSelector());
    assertTrue(reference.isClassGlob());
    assertTrue(reference.isMethodGlob());
    assertTrue(reference.hasParameterList());
    assertEquals(Arrays.asList("java.lang.String"), reference.parameterTypes());
  }

  @Test
  void parsesEmptyParameterList() {
    JavaMethodReference reference = JavaMethodReference.parse("com.example.Service#start()");

    assertTrue(reference.hasParameterList());
    assertTrue(reference.parameterTypes().isEmpty());
  }

  @Test
  void parsesPrimitiveAndArrayParameterTypes() {
    JavaMethodReference reference =
        JavaMethodReference.parse("com.example.Service#run(boolean,int[],java.lang.String[][])");

    assertEquals(
        Arrays.asList("boolean", "int[]", "java.lang.String[][]"), reference.parameterTypes());
  }

  @Test
  void parameterTypesCannotBeModified() {
    JavaMethodReference reference = JavaMethodReference.parse("com.example.Service#run()");

    assertThrows(UnsupportedOperationException.class, () -> reference.parameterTypes().add("int"));
  }

  @Test
  void rejectsKeywordsInExactIdentifiers() {
    for (String value :
        Arrays.asList(
            "com.example.class#run()",
            "com.example.Service#static()",
            "com.example.Service#run(com.example.interface)",
            "com.example.true.Service#run()",
            "com.example.false.Service#run()",
            "com.example.Service#true()",
            "com.example.Service#false()",
            "com.example.Service#null()",
            "com.example.Service#run(com.example._)")) {
      assertThrows(IllegalArgumentException.class, () -> JavaMethodReference.parse(value), value);
    }
  }

  @Test
  void acceptsContextualIdentifiers() {
    JavaMethodReference reference =
        JavaMethodReference.parse("com.example.record.Service#yield(com.example.var)");

    assertEquals("com.example.record.Service", reference.classSelector());
    assertEquals("yield", reference.methodSelector());
    assertEquals(Arrays.asList("com.example.var"), reference.parameterTypes());
  }

  @Test
  void rejectsMalformedReferences() {
    for (String value :
        Arrays.asList(
            null,
            "",
            "Service#run",
            "com.example.Service",
            "com.example.Service##run",
            "com.example.Service#",
            "com.example.Service#run(",
            "com.example.Service#run)",
            "com.example.Service#run()tail",
            "com.example.Service#run(int,,long)",
            "com.example.Service#run(String)",
            "com.example.Service#run(void)",
            "com.example.Service#run(void[])",
            "com.example.Service#run(int[ ])",
            "com.example.Service#run(int[][]x)",
            "com.example.Service#run(java..lang.String)",
            "com/example/Service.run(Lcom/example/Type)V",
            "com/example/Service.run(V)V",
            "com/example/Service.run([V)V",
            "com/example/Service.run(I)VI",
            "com/example/Service.run(L;)V",
            "com/example/Service.run(I)?",
            "com/example/Service.run(I*)",
            "Service#run()",
            "com..example.Service#run()",
            "com.example.Service#run (int)",
            "com.example.Service#bad-name")) {
      assertThrows(IllegalArgumentException.class, () -> JavaMethodReference.parse(value), value);
    }
  }

  @Test
  void supportsHotSpotInternalAndBinaryClassNamesExactly() {
    JavaMethodReference internal = JavaMethodReference.parse("com/example/Outer$Inner.run(I)V");
    JavaMethodReference binary = JavaMethodReference.parse("com.example.Outer$Inner::run(I)V");
    assertTrue(
        internal.matchesClass(
            "com/example/Outer$Inner", "com.example.Outer$Inner", "com.example.Outer.Inner"));
    assertFalse(
        internal.matchesClass(
            "com/example/Outer/Inner", "com.example.Outer.Inner", "com.example.Outer.Inner"));
    assertTrue(
        binary.matchesClass(
            "com/example/Outer$Inner", "com.example.Outer$Inner", "com.example.Outer.Inner"));
    assertFalse(
        binary.matchesClass(
            "com/example/Outer/Inner", "com.example.Outer.Inner", "com.example.Outer.Inner"));
    assertTrue(
        internal.matchesMethod(
            "run", new String[] {"int"}, new String[] {"int"}, new String[] {"I"}, "V", false));
    assertFalse(
        internal.matchesMethod(
            "run", new String[] {"int"}, new String[] {"int"}, new String[] {"I"}, "J", false));
  }

  @Test
  void supportsDefaultPackageHotSpotNames() {
    JavaMethodReference internal = JavaMethodReference.parse("Foo.run()V");
    JavaMethodReference binary = JavaMethodReference.parse("Foo::run()V");
    assertTrue(internal.matchesClass("Foo", "Foo", "Foo"));
    assertTrue(binary.matchesClass("Foo", "Foo", "Foo"));
    assertTrue(
        internal.matchesMethod("run", new String[0], new String[0], new String[0], "V", false));
    assertTrue(
        binary.matchesMethod("run", new String[0], new String[0], new String[0], "V", false));
  }

  @Test
  void sourceSelectorMatchesCanonicalAndBinaryAliases() {
    JavaMethodReference reference =
        JavaMethodReference.parse("com.example.Outer.Inner#run(com.example.Outer.Inner)");
    assertTrue(
        reference.matchesClass(
            "com/example/Outer$Inner", "com.example.Outer$Inner", "com.example.Outer.Inner"));
    assertTrue(
        reference.matchesClass(
            "com/example/Outer/Inner", "com.example.Outer.Inner", "com.example.Outer.Inner"));
    assertTrue(
        reference.matchesMethod(
            "run",
            new String[] {"com.example.Outer.Inner"},
            new String[] {"com.example.Outer$Inner"},
            new String[] {"Lcom/example/Outer$Inner;"},
            "V",
            false));
  }

  @Test
  void sourceAndParameterOnlyReferencesDoNotConstrainReturnOrMatchBridges() {
    JavaMethodReference source = JavaMethodReference.parse("com.example.Service#get(int)");
    JavaMethodReference partial = JavaMethodReference.parse("com/example/Service.get(I)");
    assertTrue(
        source.matchesMethod(
            "get",
            new String[] {"int"},
            new String[] {"int"},
            new String[] {"I"},
            "Ljava/lang/String;",
            false));
    assertFalse(
        source.matchesMethod(
            "get",
            new String[] {"int"},
            new String[] {"int"},
            new String[] {"I"},
            "Ljava/lang/Object;",
            true));
    assertTrue(
        partial.matchesMethod(
            "get",
            new String[] {"int"},
            new String[] {"int"},
            new String[] {"I"},
            "Ljava/lang/String;",
            false));
    assertFalse(
        partial.matchesMethod(
            "get",
            new String[] {"int"},
            new String[] {"int"},
            new String[] {"I"},
            "Ljava/lang/Object;",
            true));
  }

  @Test
  void onlyExactFullDescriptorCanSelectBridge() {
    JavaMethodReference bridge =
        JavaMethodReference.parse("com/example/Service.get()Ljava/lang/Object;");
    assertTrue(
        bridge.matchesMethod(
            "get", new String[0], new String[0], new String[0], "Ljava/lang/Object;", true));
    assertFalse(
        bridge.matchesMethod(
            "get", new String[0], new String[0], new String[0], "Ljava/lang/String;", false));
  }
}
