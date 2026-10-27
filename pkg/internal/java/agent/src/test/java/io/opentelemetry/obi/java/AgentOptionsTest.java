/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
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

  @Test
  void parsesEncodedDynamicSpans() {
    String name =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString("checkout.place_order".getBytes(StandardCharsets.UTF_8));
    String reference =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString("com.example.Checkout#placeOrder()".getBytes(StandardCharsets.UTF_8));

    List<DynamicSpanDefinition> spans = Agent.parseDynamicSpans(name + "." + reference);

    assertEquals(1, spans.size());
    assertEquals("checkout.place_order", spans.get(0).name());
    assertEquals("com.example.Checkout", spans.get(0).reference().classSelector());
    assertTrue(spans.get(0).reference().hasParameterList());
  }
}
