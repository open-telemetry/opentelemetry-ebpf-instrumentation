/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package testutil;

import java.util.concurrent.Callable;

/**
 * Creates lambda instances outside the io.opentelemetry.obi package. This is necessary because
 * Agent.builder() ignores classes starting with "io.opentelemetry.obi", which would prevent the
 * test's own lambdas from being retransformed.
 */
public final class LambdaFactory {
  private LambdaFactory() {}

  public static Runnable newRunnable() {
    return () -> {};
  }

  public static Callable<String> newCallable(String result) {
    return () -> result;
  }
}
