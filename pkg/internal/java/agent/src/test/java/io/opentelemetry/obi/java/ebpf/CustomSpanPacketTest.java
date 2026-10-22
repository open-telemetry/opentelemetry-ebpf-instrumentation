/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class CustomSpanPacketTest {
  @Test
  void encodesOperationLengthAndPayload() {
    byte[] payload = "{\"resourceSpans\":[]}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    NativeMemory mem = new NativeMemory(8 + payload.length, true);

    assertEquals(8 + payload.length, CustomSpanPacket.write(mem, payload));
    assertEquals(OperationType.CUSTOM_SPAN.code, mem.getBuffer().get(0));
    assertEquals(payload.length, mem.getInt(4));
    byte[] actual = new byte[payload.length];
    mem.getBuffer().position(8);
    mem.getBuffer().get(actual);
    assertArrayEquals(payload, actual);
  }

  @Test
  void rejectsInvalidPayloadSizes() {
    NativeMemory mem = new NativeMemory(8, true);
    assertThrows(IllegalArgumentException.class, () -> CustomSpanPacket.write(mem, null));
    assertThrows(IllegalArgumentException.class, () -> CustomSpanPacket.write(mem, new byte[0]));
    assertThrows(
        IllegalArgumentException.class,
        () -> CustomSpanPacket.write(mem, new byte[CustomSpanPacket.MAX_PAYLOAD_SIZE + 1]));
  }
}
