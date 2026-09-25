/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import io.opentelemetry.obi.java.Agent;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

public class ProxyInputStream extends InputStream {
  private static final String JDK_APP_INPUT_STREAM =
      "sun.security.ssl.SSLSocketImpl$AppInputStream";

  private final InputStream delegate;
  private final Socket socket;

  public ProxyInputStream(InputStream delegate, Socket socket) {
    this.delegate = delegate;
    this.socket = socket;
  }

  public static boolean requiresProxy(String streamClassName) {
    return !JDK_APP_INPUT_STREAM.equals(streamClassName);
  }

  @Override
  public int read() throws IOException {
    return delegate.read();
  }

  @Override
  public int read(byte[] b) throws IOException {
    boolean capture = SSLStorage.enterSSLSocketRead();
    try {
      int len = delegate.read(b);
      if (capture && len > 0) {
        forwardRead(b, 0, len);
      }
      return len;
    } finally {
      if (capture) {
        SSLStorage.exitSSLSocketRead();
      }
    }
  }

  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    boolean capture = SSLStorage.enterSSLSocketRead();
    try {
      int bytesRead = delegate.read(b, off, len);
      if (capture && bytesRead > 0) {
        forwardRead(b, off, bytesRead);
      }
      return bytesRead;
    } finally {
      if (capture) {
        SSLStorage.exitSSLSocketRead();
      }
    }
  }

  void forwardRead(byte[] b, int off, int len) {
    NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + len);
    writeReadPacket(p, socket, b, off, len);
    Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, p.getAddress());
  }

  static int writeReadPacket(NativeMemory p, Socket socket, byte[] b, int off, int len) {
    int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.RECEIVE, socket, len);
    return IOCTLPacket.writePacketBuffer(p, wOff, b, off, len);
  }

  @Override
  public void close() throws IOException {
    delegate.close();
  }
}
