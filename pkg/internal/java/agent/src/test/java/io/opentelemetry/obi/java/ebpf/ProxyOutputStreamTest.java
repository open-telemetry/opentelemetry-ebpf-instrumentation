/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class ProxyOutputStreamTest {
  @Test
  void writeByteArrayForwardsFullArray() throws Exception {
    ByteArrayOutputStream delegate = new ByteArrayOutputStream();
    CapturingProxyOutputStream stream = new CapturingProxyOutputStream(delegate);
    byte[] buffer = new byte[] {1, 2, 3};

    stream.write(buffer);

    assertEquals(0, stream.forwardedOffset);
    assertEquals(3, stream.forwardedLength);
    assertArrayEquals(buffer, stream.forwardedBytes);
    assertArrayEquals(buffer, delegate.toByteArray());
  }

  @Test
  void writeByteArrayWithOffsetForwardsOffsetAndLength() throws Exception {
    ByteArrayOutputStream delegate = new ByteArrayOutputStream();
    CapturingProxyOutputStream stream = new CapturingProxyOutputStream(delegate);
    byte[] buffer = new byte[] {1, 2, 3, 4};

    stream.write(buffer, 1, 2);

    assertEquals(1, stream.forwardedOffset);
    assertEquals(2, stream.forwardedLength);
    assertArrayEquals(new byte[] {2, 3}, stream.forwardedBytes);
    assertArrayEquals(new byte[] {2, 3}, delegate.toByteArray());
  }

  private static class CapturingProxyOutputStream extends ProxyOutputStream {
    private int forwardedOffset = -1;
    private int forwardedLength = -1;
    private byte[] forwardedBytes;

    CapturingProxyOutputStream(ByteArrayOutputStream delegate) {
      super(delegate, null);
    }

    @Override
    void forwardWrite(byte[] b, int off, int len) {
      forwardedOffset = off;
      forwardedLength = len;
      forwardedBytes = Arrays.copyOfRange(b, off, off + len);
    }
  }
}
