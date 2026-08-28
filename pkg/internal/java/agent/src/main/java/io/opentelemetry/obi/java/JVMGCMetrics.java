/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import com.sun.management.GarbageCollectionNotificationInfo;
import io.opentelemetry.obi.java.ebpf.JVMGCDurationPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import javax.management.Notification;
import javax.management.NotificationEmitter;
import javax.management.openmbean.CompositeData;

final class JVMGCMetrics {
  private static NativeMemory packet;

  private JVMGCMetrics() {}

  static void start() {
    if (!notificationClassAvailable()) {
      return;
    }

    for (GarbageCollectorMXBean bean : ManagementFactory.getGarbageCollectorMXBeans()) {
      if (!(bean instanceof NotificationEmitter)) {
        continue;
      }
      ((NotificationEmitter) bean)
          .addNotificationListener(
              JVMGCMetrics::handleNotification,
              notification ->
                  GarbageCollectionNotificationInfo.GARBAGE_COLLECTION_NOTIFICATION.equals(
                      notification.getType()),
              null);
    }
  }

  private static void handleNotification(Notification notification, Object handback) {
    JVMRuntimeMetrics.runSafely(
        () -> {
          GarbageCollectionNotificationInfo info =
              GarbageCollectionNotificationInfo.from((CompositeData) notification.getUserData());
          send(
              info.getGcName(),
              info.getGcAction(),
              TimeUnit.MILLISECONDS.toNanos(info.getGcInfo().getDuration()));
        });
  }

  private static synchronized void send(String collectorName, String action, long durationNanos) {
    if (packet == null) {
      packet = new NativeMemory(JVMGCDurationPacket.PACKET_SIZE);
    }
    writeAndSend(
        packet,
        collectorName,
        action,
        durationNanos,
        event -> Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, event.getAddress()));
  }

  static void writeAndSend(
      NativeMemory packet,
      String collectorName,
      String action,
      long durationNanos,
      Consumer<NativeMemory> sender) {
    JVMGCDurationPacket.write(packet, durationNanos, collectorName, action);
    sender.accept(packet);
  }

  private static boolean notificationClassAvailable() {
    try {
      Class.forName(
          "com.sun.management.GarbageCollectionNotificationInfo",
          false,
          GarbageCollectorMXBean.class.getClassLoader());
      return true;
    } catch (ClassNotFoundException ignored) {
      return false;
    }
  }
}
