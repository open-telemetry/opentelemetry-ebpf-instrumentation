/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AgentOptionsTest {
  private static final long DEFAULT_INTERVAL_NANOS = 10_000_000_000L;

  @Test
  void readsPositiveLongOption() {
    Map<String, String> opts = new HashMap<>();
    opts.put("runtimeMetricsIntervalNanos", "2000000000");

    assertEquals(
        2_000_000_000L,
        Agent.positiveLongOpt(opts, "runtimeMetricsIntervalNanos", DEFAULT_INTERVAL_NANOS));
  }

  @Test
  void usesDefaultForMissingInvalidOrNonPositiveOption() {
    Map<String, String> opts = new HashMap<>();
    assertEquals(
        DEFAULT_INTERVAL_NANOS,
        Agent.positiveLongOpt(opts, "runtimeMetricsIntervalNanos", DEFAULT_INTERVAL_NANOS));

    opts.put("runtimeMetricsIntervalNanos", "invalid");
    assertEquals(
        DEFAULT_INTERVAL_NANOS,
        Agent.positiveLongOpt(opts, "runtimeMetricsIntervalNanos", DEFAULT_INTERVAL_NANOS));

    opts.put("runtimeMetricsIntervalNanos", "0");
    assertEquals(
        DEFAULT_INTERVAL_NANOS,
        Agent.positiveLongOpt(opts, "runtimeMetricsIntervalNanos", DEFAULT_INTERVAL_NANOS));
  }
}
