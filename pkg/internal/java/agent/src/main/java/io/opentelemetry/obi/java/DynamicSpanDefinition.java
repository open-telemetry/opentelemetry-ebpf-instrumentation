/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import io.opentelemetry.obi.java.instrumentations.JavaMethodReference;

/** One per-process dynamic span declaration passed from OBI to the Java agent. */
public final class DynamicSpanDefinition {
  private final String name;
  private final JavaMethodReference reference;

  public DynamicSpanDefinition(String name, String functionReference) {
    if (name == null || name.isEmpty()) {
      throw new IllegalArgumentException("dynamic span name must not be empty");
    }
    this.name = name;
    this.reference = JavaMethodReference.parse(functionReference);
  }

  public String name() {
    return name;
  }

  public JavaMethodReference reference() {
    return reference;
  }
}
