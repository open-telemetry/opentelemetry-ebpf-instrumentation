/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import io.opentelemetry.obi.java.ebpf.JVMGCDurationPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class JVMGCMetricsTest {
  @Test
  void sendsGCDurationEvent() {
    NativeMemory packet = new NativeMemory(JVMGCDurationPacket.PACKET_SIZE, true);
    AtomicReference<NativeMemory> sent = new AtomicReference<>();

    JVMGCMetrics.writeAndSend(
        packet, "G1 Young Generation", "end of minor GC", 25_000_000, sent::set);

    assertSame(packet, sent.get());
    assertEquals(OperationType.JVM_GC_DURATION.code, packet.getByte(0));
    assertEquals(25_000_000, packet.getLong(1));
  }
}
