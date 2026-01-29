/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import io.opentelemetry.obi.java.Agent;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;

public class ProxyOutputStream extends OutputStream {
  private final OutputStream delegate;
  private final Socket socket;

  public ProxyOutputStream(OutputStream delegate, Socket socket) {
    this.delegate = delegate;
    this.socket = socket;
  }

  @Override
  public void write(int b) throws IOException {
    delegate.write(b);
  }

  private void writeWrapper(byte[] b) {
    if (b.length > 0) {
      NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + b.length);
      int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.SEND, socket, b.length);
      IOCTLPacket.writePacketBuffer(p, wOff, b);
      Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, p.getAddress());
    }
  }

  @Override
  public void write(byte[] b) throws IOException {
    writeWrapper(b);
    delegate.write(b);
  }

  @Override
  public void write(byte[] b, int off, int len) throws IOException {
    writeWrapper(b);
    delegate.write(b, off, len);
  }

  @Override
  public void flush() throws IOException {
    delegate.flush();
  }

  @Override
  public void close() throws IOException {
    delegate.close();
  }
}
