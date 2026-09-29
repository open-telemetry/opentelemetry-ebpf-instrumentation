/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.io.InputStream;
import java.io.OutputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class NestedSSLSocketStreamTest {
  @AfterEach
  void cleanup() {
    SSLStorage.exitSSLSocketRead();
    SSLStorage.exitSSLSocketWrite();
  }

  @Test
  void outputIsCapturedOnlyByOutermostStream() throws Exception {
    DirectInstrumentedOutputStream delegate = new DirectInstrumentedOutputStream();
    CapturingProxyOutputStream stream = new CapturingProxyOutputStream(delegate);

    stream.write(new byte[] {1, 2, 3});

    assertEquals(1, stream.captures);
    assertEquals(0, delegate.captures);
  }

  @Test
  void inputIsCapturedOnlyByOutermostStream() throws Exception {
    DirectInstrumentedInputStream delegate = new DirectInstrumentedInputStream();
    CapturingProxyInputStream stream = new CapturingProxyInputStream(delegate);

    assertEquals(1, stream.read(new byte[1]));

    assertEquals(1, stream.captures);
    assertEquals(0, delegate.captures);
  }

  private static class CapturingProxyOutputStream extends ProxyOutputStream {
    private int captures;

    CapturingProxyOutputStream(OutputStream delegate) {
      super(delegate, null);
    }

    @Override
    void forwardWrite(byte[] b, int off, int len) {
      captures++;
    }
  }

  private static class DirectInstrumentedOutputStream extends OutputStream {
    private int captures;

    @Override
    public void write(int b) {}

    @Override
    public void write(byte[] b) {
      capture();
    }

    @Override
    public void write(byte[] b, int off, int len) {
      capture();
    }

    private void capture() {
      if (!SSLStorage.isSSLSocketWriteActive()) {
        captures++;
      }
    }
  }

  private static class CapturingProxyInputStream extends ProxyInputStream {
    private int captures;

    CapturingProxyInputStream(InputStream delegate) {
      super(delegate, null);
    }

    @Override
    void forwardRead(byte[] b, int off, int len) {
      captures++;
    }
  }

  private static class DirectInstrumentedInputStream extends InputStream {
    private int captures;

    @Override
    public int read() {
      return 1;
    }

    @Override
    public int read(byte[] b) {
      b[0] = 1;
      capture();
      return 1;
    }

    @Override
    public int read(byte[] b, int off, int len) {
      b[off] = 1;
      capture();
      return 1;
    }

    private void capture() {
      if (!SSLStorage.isSSLSocketReadActive()) {
        captures++;
      }
    }
  }
}
