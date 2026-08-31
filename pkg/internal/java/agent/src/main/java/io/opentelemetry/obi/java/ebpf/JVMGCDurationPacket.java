/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import java.nio.charset.StandardCharsets;

public final class JVMGCDurationPacket {
  public static final int STRING_SIZE = 64;
  public static final int PACKET_SIZE = 1 + Long.BYTES + (2 * STRING_SIZE);
  private static final byte[] EMPTY_STRING = new byte[STRING_SIZE];

  private JVMGCDurationPacket() {}

  public static int write(
      NativeMemory mem, long durationNanos, String collectorName, String action) {
    int offset = 0;
    mem.setByte(offset++, OperationType.JVM_GC_DURATION.code);
    mem.setLong(offset, durationNanos);
    offset += Long.BYTES;
    offset = writeString(mem, offset, collectorName);
    return writeString(mem, offset, action);
  }

  private static int writeString(NativeMemory mem, int offset, String value) {
    mem.write(offset, EMPTY_STRING, 0, EMPTY_STRING.length);
    byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
    int length = Math.min(encoded.length, STRING_SIZE - 1);
    mem.write(offset, encoded, 0, length);
    return offset + STRING_SIZE;
  }
}
