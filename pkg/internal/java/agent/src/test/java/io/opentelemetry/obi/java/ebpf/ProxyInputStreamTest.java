/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class ProxyInputStreamTest {

  @Test
  void readPacketUsesBytesReadForPartialBuffer() {
    byte[] buffer = {10, 20, 30, 40, 50};
    int bytesRead = 3;
    NativeMemory packet = new NativeMemory(IOCTLPacket.packetPrefixSize + bytesRead + 1, true);

    int end = ProxyInputStream.writeReadPacket(packet, null, buffer, 0, bytesRead);

    assertEquals(IOCTLPacket.packetPrefixSize + bytesRead, end);
    assertEquals(bytesRead, packet.getInt(IOCTLPacket.packetPrefixSize - Integer.BYTES));
    for (int i = 0; i < bytesRead; i++) {
      assertEquals(buffer[i], packet.getBuffer().get(IOCTLPacket.packetPrefixSize + i));
    }
    assertEquals(0, packet.getBuffer().get(IOCTLPacket.packetPrefixSize + bytesRead));
  }
}
