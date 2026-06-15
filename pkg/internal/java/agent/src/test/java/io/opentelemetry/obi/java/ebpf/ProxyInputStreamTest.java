/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Arrays;
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

  @Test
  void readByteArrayForwardsActualReadLength() throws Exception {
    CapturingProxyInputStream stream =
        new CapturingProxyInputStream(new ByteArrayInputStream(new byte[] {1, 2}));
    byte[] buffer = new byte[8];

    int bytesRead = stream.read(buffer);

    assertEquals(2, bytesRead);
    assertEquals(0, stream.forwardedOffset);
    assertEquals(2, stream.forwardedLength);
    assertArrayEquals(new byte[] {1, 2}, stream.forwardedBytes);
  }

  @Test
  void readByteArrayWithOffsetForwardsOffsetAndBytesRead() throws Exception {
    CapturingProxyInputStream stream =
        new CapturingProxyInputStream(new ByteArrayInputStream(new byte[] {3, 4}));
    byte[] buffer = new byte[8];

    int bytesRead = stream.read(buffer, 3, 4);

    assertEquals(2, bytesRead);
    assertEquals(3, stream.forwardedOffset);
    assertEquals(2, stream.forwardedLength);
    assertArrayEquals(new byte[] {3, 4}, stream.forwardedBytes);
  }

  private static class CapturingProxyInputStream extends ProxyInputStream {
    private int forwardedOffset = -1;
    private int forwardedLength = -1;
    private byte[] forwardedBytes;

    CapturingProxyInputStream(InputStream delegate) {
      super(delegate, null);
    }

    @Override
    void forwardRead(byte[] b, int off, int len) {
      forwardedOffset = off;
      forwardedLength = len;
      forwardedBytes = Arrays.copyOfRange(b, off, off + len);
    }
  }
}
