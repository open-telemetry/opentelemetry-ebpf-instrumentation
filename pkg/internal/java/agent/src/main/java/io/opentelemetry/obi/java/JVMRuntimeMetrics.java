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
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

final class JVMRuntimeMetrics {
  static final long DEFAULT_SAMPLING_INTERVAL_NANOS = TimeUnit.SECONDS.toNanos(10);
  private static final AtomicBoolean started = new AtomicBoolean();
  private static NativeMemory packet;

  private JVMRuntimeMetrics() {}

  static void start(long samplingIntervalNanos) {
    if (!started.compareAndSet(false, true)) {
      return;
    }

    runSafely(JVMGCMetrics::start);

    // Periodic snapshots
    ScheduledExecutorService sampler =
        Executors.newSingleThreadScheduledExecutor(
            runnable -> {
              Thread thread = new Thread(runnable, "obi-jvm-runtime-metrics");
              thread.setDaemon(true);
              return thread;
            });
    sampler.scheduleAtFixedRate(
        () -> runSafely(JVMRuntimeMetrics::collectAndSend),
        samplingIntervalNanos,
        samplingIntervalNanos,
        TimeUnit.NANOSECONDS);
  }

  static void runSafely(Runnable collection) {
    // Scheduled executors suppress later runs when a task lets an exception escape.
    try {
      collection.run();
    } catch (Throwable error) {
      System.err.println("Failed to collect JVM runtime metrics: " + error);
    }
  }

  private static void collectAndSend() {
    if (packet == null) {
      packet = new NativeMemory(JVMRuntimeMetricsPacket.PACKET_SIZE);
    }
    collectAndSend(
        packet, snapshot -> Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, snapshot.getAddress()));
  }

  static void collectAndSend(NativeMemory packet, Consumer<NativeMemory> sender) {
    collect(packet);
    sender.accept(packet);
  }

  static void collect(NativeMemory packet) {
    // Class loading
    ClassLoadingMXBean classes = ManagementFactory.getClassLoadingMXBean();
    long loadedClassCount = classes.getLoadedClassCount();
    long totalLoadedClassCount = classes.getTotalLoadedClassCount();
    long unloadedClassCount = classes.getUnloadedClassCount();

    // Platform threads
    ThreadMXBean threads = ManagementFactory.getThreadMXBean();
    long threadCount = threads.getThreadCount();
    long daemonThreadCount = threads.getDaemonThreadCount();

    // Process CPU
    OperatingSystemMXBean operatingSystem = ManagementFactory.getOperatingSystemMXBean();
    long cpuCount = operatingSystem.getAvailableProcessors();
    long cpuTime = -1;
    double recentCpuUtilization = -1;
    if (operatingSystem instanceof com.sun.management.OperatingSystemMXBean) {
      com.sun.management.OperatingSystemMXBean extendedOperatingSystem =
          (com.sun.management.OperatingSystemMXBean) operatingSystem;
      cpuTime = extendedOperatingSystem.getProcessCpuTime();
      recentCpuUtilization = extendedOperatingSystem.getProcessCpuLoad();
    }

    JVMRuntimeMetricsPacket.writeSnapshot(
        packet,
        loadedClassCount,
        totalLoadedClassCount,
        unloadedClassCount,
        threadCount,
        daemonThreadCount,
        cpuCount,
        cpuTime,
        recentCpuUtilization);
  }
}
