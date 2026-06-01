/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import io.opentelemetry.obi.java.Agent;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

public class ProxyInputStream extends InputStream {
  private final InputStream delegate;
  private final Socket socket;

  public ProxyInputStream(InputStream delegate, Socket socket) {
    this.delegate = delegate;
    this.socket = socket;
  }

  @Override
  public int read() throws IOException {
    return delegate.read();
  }

  @Override
  public int read(byte[] b) throws IOException {
    int len = delegate.read(b);
    if (len > 0) {
      NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + len);
      writeReadPacket(p, socket, b, 0, len);
      Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, p.getAddress());
    }
    return len;
  }

  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    int bytesRead = delegate.read(b, off, len);
    if (bytesRead > 0) {
      NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + bytesRead);
      writeReadPacket(p, socket, b, off, bytesRead);
      Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, p.getAddress());
    }
    return bytesRead;
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
