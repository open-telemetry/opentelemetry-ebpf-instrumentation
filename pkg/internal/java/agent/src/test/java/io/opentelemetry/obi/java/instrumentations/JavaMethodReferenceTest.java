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
            "Service#run()",
            "com..example.Service#run()",
            "com.example.Service#run (int)",
            "com.example.Service#bad-name")) {
      assertThrows(IllegalArgumentException.class, () -> JavaMethodReference.parse(value), value);
    }
  }
}
