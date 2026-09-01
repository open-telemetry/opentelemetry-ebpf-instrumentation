/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import io.opentelemetry.obi.java.ebpf.JVMRuntimeMetricsPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import java.lang.management.ClassLoadingMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.OperatingSystemMXBean;
import java.lang.management.ThreadMXBean;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.infra.Blackhole;

@State(Scope.Thread)
public class JVMRuntimeMetricsBenchmark {
  private final NativeMemory packet = new NativeMemory(JVMRuntimeMetricsPacket.PACKET_SIZE, true);

  @Benchmark
  public void collectAndEncodeSnapshot(Blackhole blackhole) {
    JVMRuntimeMetrics.collect(packet);
    blackhole.consume(packet.getLong(1));
  }

  @Benchmark
  public void readClassMetrics(Blackhole blackhole) {
    ClassLoadingMXBean classes = ManagementFactory.getClassLoadingMXBean();
    blackhole.consume(classes.getLoadedClassCount());
    blackhole.consume(classes.getTotalLoadedClassCount());
    blackhole.consume(classes.getUnloadedClassCount());
  }

  @Benchmark
  public void readThreadMetrics(Blackhole blackhole) {
    ThreadMXBean threads = ManagementFactory.getThreadMXBean();
    blackhole.consume(threads.getThreadCount());
    blackhole.consume(threads.getDaemonThreadCount());
  }

  @Benchmark
  public void readCpuMetrics(Blackhole blackhole) {
    OperatingSystemMXBean operatingSystem = ManagementFactory.getOperatingSystemMXBean();
    readCpuMetrics(operatingSystem, blackhole);
  }

  private static void readCpuMetrics(OperatingSystemMXBean operatingSystem, Blackhole blackhole) {
    blackhole.consume(operatingSystem.getAvailableProcessors());
    if (operatingSystem instanceof com.sun.management.OperatingSystemMXBean) {
      com.sun.management.OperatingSystemMXBean extendedOperatingSystem =
          (com.sun.management.OperatingSystemMXBean) operatingSystem;
      blackhole.consume(extendedOperatingSystem.getProcessCpuTime());
      blackhole.consume(extendedOperatingSystem.getProcessCpuLoad());
    }
  }

  @Benchmark
  public void encodeSnapshot(Blackhole blackhole) {
    JVMRuntimeMetricsPacket.writeSnapshot(packet, 1, 2, 3, 4, 5, 6, 7, 0.5);
    blackhole.consume(packet.getLong(1));
  }
}
