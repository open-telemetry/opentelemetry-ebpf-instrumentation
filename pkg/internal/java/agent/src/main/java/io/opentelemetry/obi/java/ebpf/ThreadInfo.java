/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import io.opentelemetry.obi.java.Agent;

public class ThreadInfo {
  public static int writeThreadContext(NativeMemory mem, int off, long parentId) {
    mem.setLong(off, parentId);
    off += Long.BYTES;
    return off;
  }

  public static void sendParentThreadContext(long parentId) {
    NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize);
    IOCTLPacket.writePacket(p, 0, OperationType.THREAD, parentId);
    Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, p.getAddress());
  }
}
