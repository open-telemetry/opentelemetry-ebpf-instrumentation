/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import io.opentelemetry.obi.java.Agent;

/** Sends one completed OTLP JSON span to OBI's eBPF event pipeline. */
public final class CustomSpanPacket {
  public static final int MAX_PAYLOAD_SIZE = 16 * 1024;
  private static final int PAYLOAD_OFFSET = 8;

  private CustomSpanPacket() {}

  public static int write(NativeMemory mem, byte[] payload) {
    validate(payload);
    mem.setByte(0, OperationType.CUSTOM_SPAN.code);
    mem.setInt(4, payload.length);
    mem.write(PAYLOAD_OFFSET, payload, 0, payload.length);
    return PAYLOAD_OFFSET + payload.length;
  }

  public static int emit(byte[] payload) {
    validate(payload);
    NativeMemory packet = new NativeMemory(PAYLOAD_OFFSET + payload.length);
    write(packet, payload);
    return Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
  }

  private static void validate(byte[] payload) {
    if (payload == null || payload.length == 0 || payload.length > MAX_PAYLOAD_SIZE) {
      throw new IllegalArgumentException(
          "custom span payload size must be between 1 and 16384 bytes");
    }
  }
}
