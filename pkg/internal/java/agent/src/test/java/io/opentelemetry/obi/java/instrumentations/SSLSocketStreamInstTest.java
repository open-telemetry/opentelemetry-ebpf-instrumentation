/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.*;

import io.opentelemetry.obi.java.ebpf.IOCTLPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import java.net.Socket;
import org.junit.jupiter.api.Test;

class SSLSocketStreamInstTest {

  @Test
  void inputStreamReadPacketUsesBytesReadForPartialBuffer() {
    byte[] buffer = {10, 20, 30, 40, 50};
    int bytesRead = 3;
    NativeMemory packet = new NativeMemory(IOCTLPacket.packetPrefixSize + bytesRead + 1, true);

    // same call sequence the read advices inline
    int wOff =
        IOCTLPacket.writePacketPrefix(packet, 0, OperationType.RECEIVE, (Socket) null, bytesRead);
    int end = IOCTLPacket.writePacketBuffer(packet, wOff, buffer, 0, bytesRead);

    assertEquals(IOCTLPacket.packetPrefixSize + bytesRead, end);
    assertEquals(bytesRead, packet.getInt(IOCTLPacket.packetPrefixSize - Integer.BYTES));
    for (int i = 0; i < bytesRead; i++) {
      assertEquals(buffer[i], packet.getBuffer().get(IOCTLPacket.packetPrefixSize + i));
    }
    assertEquals(0, packet.getBuffer().get(IOCTLPacket.packetPrefixSize + bytesRead));
  }
}
