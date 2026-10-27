/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.DynamicSpanRuntime;
import java.lang.reflect.Method;
import net.bytebuddy.asm.Advice;

public final class DynamicSpanAdvice {
  private DynamicSpanAdvice() {}

  @Advice.OnMethodEnter(suppress = Throwable.class)
  public static DynamicSpanRuntime.SpanState[] enter(@Advice.Origin Method method) {
    return DynamicSpanRuntime.enter(method);
  }

  @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
  public static void exit(
      @Advice.Enter DynamicSpanRuntime.SpanState[] spans, @Advice.Thrown Throwable error) {
    DynamicSpanRuntime.exit(spans, error);
  }
}
