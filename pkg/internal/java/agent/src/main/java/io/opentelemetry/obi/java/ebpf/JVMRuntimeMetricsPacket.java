/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

public final class JVMRuntimeMetricsPacket {
  public static final int PACKET_SIZE = 1 + (8 * Long.BYTES);

  private JVMRuntimeMetricsPacket() {}

  public static int writeSnapshot(
      NativeMemory mem,
      long loadedClassCount,
      long totalLoadedClassCount,
      long unloadedClassCount,
      long threadCount,
      long daemonThreadCount,
      long cpuCount,
      long cpuTime,
      double recentCpuUtilization) {
    // Header
    int offset = 0;
    mem.setByte(offset++, OperationType.JVM_RUNTIME_SNAPSHOT.code);

    // Class loading
    mem.setLong(offset, loadedClassCount);
    offset += Long.BYTES;
    mem.setLong(offset, totalLoadedClassCount);
    offset += Long.BYTES;
    mem.setLong(offset, unloadedClassCount);
    offset += Long.BYTES;

    // Platform threads
    mem.setLong(offset, threadCount);
    offset += Long.BYTES;
    mem.setLong(offset, daemonThreadCount);
    offset += Long.BYTES;

    // Process CPU
    mem.setLong(offset, cpuCount);
    offset += Long.BYTES;
    mem.setLong(offset, cpuTime);
    offset += Long.BYTES;
    mem.setLong(offset, Double.doubleToRawLongBits(recentCpuUtilization));
    return offset + Long.BYTES;
  }
}
