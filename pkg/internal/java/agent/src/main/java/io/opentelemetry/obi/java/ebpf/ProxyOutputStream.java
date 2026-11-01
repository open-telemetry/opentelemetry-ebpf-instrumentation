/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import io.opentelemetry.obi.java.Agent;
import io.opentelemetry.obi.java.instrumentations.data.ApacheHttpClientPropagation;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;

public class ProxyOutputStream extends OutputStream {
  private static final String JDK_APP_OUTPUT_STREAM =
      "sun.security.ssl.SSLSocketImpl$AppOutputStream";

  private final OutputStream delegate;
  private final Socket socket;

  public ProxyOutputStream(OutputStream delegate, Socket socket) {
    this.delegate = delegate;
    this.socket = socket;
  }

  public static boolean requiresProxy(String streamClassName) {
    return !JDK_APP_OUTPUT_STREAM.equals(streamClassName);
  }

  @Override
  public void write(int b) throws IOException {
    ApacheHttpClientPropagation.skipWrite(socket);
    delegate.write(b);
  }

  void forwardWrite(byte[] b, int off, int len) {
    if (len > 0) {
      NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + len);
      int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.SEND, socket, len);
      IOCTLPacket.writePacketBuffer(p, wOff, b, off, len);
      Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, p.getAddress());
    }
  }

  @Override
  public void write(byte[] b) throws IOException {
    boolean capture = SSLStorage.enterSSLSocketWrite();
    try {
      if (capture) {
        try {
          byte[] injected = ApacheHttpClientPropagation.inject(b, 0, b.length, socket);
          if (injected != null) {
            forwardWrite(injected, 0, injected.length);
            b = injected;
          } else {
            forwardWrite(b, 0, b.length);
          }
        } catch (Throwable ignored) {
        }
      }
      delegate.write(b);
    } finally {
      if (capture) {
        SSLStorage.exitSSLSocketWrite();
      }
    }
  }

  @Override
  public void write(byte[] b, int off, int len) throws IOException {
    boolean capture = SSLStorage.enterSSLSocketWrite();
    try {
      if (capture) {
        try {
          byte[] injected = ApacheHttpClientPropagation.inject(b, off, len, socket);
          if (injected != null) {
            forwardWrite(injected, 0, injected.length);
            b = injected;
            off = 0;
            len = b.length;
          } else {
            forwardWrite(b, off, len);
          }
        } catch (Throwable ignored) {
        }
      }
      delegate.write(b, off, len);
    } finally {
      if (capture) {
        SSLStorage.exitSSLSocketWrite();
      }
    }
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
