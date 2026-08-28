/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class JVMGCDurationPacketTest {
  @Test
  void writesGCDurationEvent() {
    NativeMemory packet = new NativeMemory(JVMGCDurationPacket.PACKET_SIZE, true);

    int length =
        JVMGCDurationPacket.write(packet, 25_000_000, "G1 Young Generation", "end of minor GC");

    assertEquals(137, JVMGCDurationPacket.PACKET_SIZE);
    assertEquals(JVMGCDurationPacket.PACKET_SIZE, length);
    assertEquals(OperationType.JVM_GC_DURATION.code, packet.getByte(0));
    assertEquals(25_000_000, packet.getLong(1));
    assertEquals("G1 Young Generation", readString(packet, 9));
    assertEquals("end of minor GC", readString(packet, 73));
  }

  @Test
  void clearsStringsWhenPacketIsReused() {
    NativeMemory packet = new NativeMemory(JVMGCDurationPacket.PACKET_SIZE, true);
    JVMGCDurationPacket.write(packet, 1, "long collector name", "long action name");

    JVMGCDurationPacket.write(packet, 2, "gc", "end");

    assertEquals("gc", readString(packet, 9));
    assertEquals("end", readString(packet, 73));
  }

  private static String readString(NativeMemory packet, int offset) {
    byte[] value = new byte[JVMGCDurationPacket.STRING_SIZE];
    for (int i = 0; i < value.length; i++) {
      value[i] = packet.getBuffer().get(offset + i);
      if (value[i] == 0) {
        return new String(value, 0, i, StandardCharsets.UTF_8);
      }
    }
    return new String(value, StandardCharsets.UTF_8);
  }
}
