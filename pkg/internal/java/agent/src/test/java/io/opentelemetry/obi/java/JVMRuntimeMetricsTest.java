/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.obi.java.ebpf.JVMRuntimeMetricsPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class JVMRuntimeMetricsTest {
  @Test
  void sendsCollectedRuntimeSnapshot() {
    NativeMemory packet = new NativeMemory(JVMRuntimeMetricsPacket.PACKET_SIZE, true);
    AtomicReference<NativeMemory> sent = new AtomicReference<>();

    JVMRuntimeMetrics.collectAndSend(packet, sent::set);

    assertSame(packet, sent.get());
    assertEquals(OperationType.JVM_RUNTIME_SNAPSHOT.code, packet.getByte(0));
  }

  @Test
  void collectionFailureDoesNotEscapeSampler() {
    assertDoesNotThrow(
        () ->
            JVMRuntimeMetrics.runSafely(
                () -> {
                  throw new IllegalStateException("test failure");
                }));
  }

  @Test
  void collectsRuntimeSnapshot() {
    NativeMemory packet = new NativeMemory(JVMRuntimeMetricsPacket.PACKET_SIZE, true);

    JVMRuntimeMetrics.collect(packet);

    assertEquals(OperationType.JVM_RUNTIME_SNAPSHOT.code, packet.getByte(0));
    assertTrue(packet.getLong(1) > 0);
    assertTrue(packet.getLong(9) >= packet.getLong(1));
    assertTrue(packet.getLong(17) >= 0);
    assertTrue(packet.getLong(25) >= packet.getLong(33));
    assertTrue(packet.getLong(41) > 0);
    assertTrue(packet.getLong(49) >= -1);
    double utilization = Double.longBitsToDouble(packet.getLong(57));
    assertTrue(utilization == -1 || (utilization >= 0 && utilization <= 1));
  }
}
