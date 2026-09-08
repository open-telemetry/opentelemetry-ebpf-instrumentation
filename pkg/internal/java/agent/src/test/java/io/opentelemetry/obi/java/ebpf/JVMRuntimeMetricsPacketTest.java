/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class JVMRuntimeMetricsPacketTest {
  @Test
  void hasFixedSize() {
    assertEquals(65, JVMRuntimeMetricsPacket.PACKET_SIZE);
  }

  @Test
  void writesSnapshotOperationType() {
    NativeMemory packet = new NativeMemory(JVMRuntimeMetricsPacket.PACKET_SIZE, true);

    JVMRuntimeMetricsPacket.writeSnapshot(packet, 11, 12, 13, 14, 15, 16, 17, 0.25);

    assertEquals(OperationType.JVM_RUNTIME_SNAPSHOT.code, packet.getByte(0));
    assertEquals(11, packet.getLong(1));
    assertEquals(12, packet.getLong(9));
    assertEquals(13, packet.getLong(17));
    assertEquals(14, packet.getLong(25));
    assertEquals(15, packet.getLong(33));
    assertEquals(16, packet.getLong(41));
    assertEquals(17, packet.getLong(49));
    assertEquals(0.25, Double.longBitsToDouble(packet.getLong(57)));
  }
}
