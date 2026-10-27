/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.Agent;
import io.opentelemetry.obi.java.ebpf.IOCTLPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import io.opentelemetry.obi.java.instrumentations.data.BytesWithLen;
import io.opentelemetry.obi.java.instrumentations.data.Connection;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import io.opentelemetry.obi.java.instrumentations.util.ByteBufferExtractor;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class SocketChannelInst {
  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.isSubTypeOf(SocketChannel.class)
        .and(ElementMatchers.not(ElementMatchers.isAbstract()))
        .and(ElementMatchers.not(ElementMatchers.isInterface()))
        .and(ElementMatchers.declaresField(ElementMatchers.named("localAddress")))
        .and(ElementMatchers.declaresField(ElementMatchers.named("remoteAddress")));
  }

  public static boolean matches(Class<?> clazz) {
    return SocketChannel.class.isAssignableFrom(clazz);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(WriteAdvice.class)
                    .on(
                        ElementMatchers.named("write")
                            .and(ElementMatchers.takesArgument(0, ByteBuffer.class))))
            .visit(
                Advice.to(WriteAdviceArray.class)
                    .on(
                        ElementMatchers.named("write")
                            .and(ElementMatchers.takesArgument(0, ByteBuffer[].class))))
            .visit(
                Advice.to(ReadAdvice.class)
                    .on(
                        ElementMatchers.named("read")
                            .and(ElementMatchers.takesArguments(1))
                            .and(ElementMatchers.takesArgument(0, ByteBuffer.class))))
            .visit(
                Advice.to(ReadAdviceArray.class)
                    .on(
                        ElementMatchers.named("read")
                            .and(ElementMatchers.takesArguments(3))
                            .and(ElementMatchers.takesArgument(0, ByteBuffer[].class))))
            .visit(
                Advice.to(CleanupAdvice.class)
                    .on(
                        ElementMatchers.named("shutdownInput")
                            .or(ElementMatchers.named("shutdownOutput"))
                            .or(ElementMatchers.named("kill"))
                            .or(ElementMatchers.named("tryClose"))));
  }

  public static final class WriteAdvice {
    // Report before ciphertext reaches the peer: its response may complete send()
    // and release the header reservation before SocketChannel.write() returns.
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void write(
        @Advice.Argument(0) final ByteBuffer src,
        @Advice.FieldValue("localAddress") SocketAddress localSocket,
        @Advice.FieldValue("remoteAddress") SocketAddress remoteSocket) {
      if (!(localSocket instanceof InetSocketAddress)
          || !(remoteSocket instanceof InetSocketAddress)
          || src == null) {
        return;
      }
      String bufKey = ByteBufferExtractor.keyFromFreshBuffer(src);
      if (SSLStorage.debugOn) {
        System.err.println("[SocketChannelInst] write advice, lookup: " + bufKey);
      }
      BytesWithLen unencrypted = SSLStorage.takeUnencryptedBuffer(bufKey);
      if (SSLStorage.debugOn) {
        System.err.println("[SocketChannelInst] write advice, unencrypted: " + unencrypted);
      }
      if (unencrypted == null) {
        return;
      }
      InetSocketAddress local = (InetSocketAddress) localSocket;
      InetSocketAddress remote = (InetSocketAddress) remoteSocket;
      Connection connection =
          new Connection(
              local.getAddress(), local.getPort(), remote.getAddress(), remote.getPort());
      NativeMemory packet = new NativeMemory(IOCTLPacket.packetPrefixSize + unencrypted.len);
      int offset =
          IOCTLPacket.writePacketPrefix(packet, 0, OperationType.SEND, connection, unencrypted.len);
      IOCTLPacket.writePacketBuffer(packet, offset, unencrypted.buf, 0, unencrypted.len);
      Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
    }
  }

  public static final class WriteAdviceArray {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void write(
        @Advice.Argument(0) final ByteBuffer[] srcs,
        @Advice.FieldValue("localAddress") SocketAddress localSocket,
        @Advice.FieldValue("remoteAddress") SocketAddress remoteSocket) {
      if (!(localSocket instanceof InetSocketAddress)
          || !(remoteSocket instanceof InetSocketAddress)
          || srcs == null) {
        return;
      }
      ByteBuffer buffer = ByteBufferExtractor.flattenFreshByteBufferArray(srcs);
      String bufKey = ByteBufferExtractor.keyFromUsedBuffer(buffer);
      if (SSLStorage.debugOn) {
        System.err.println("[SocketChannelInst] write array advice, lookup: " + bufKey);
      }
      BytesWithLen unencrypted = SSLStorage.takeUnencryptedBuffer(bufKey);
      if (SSLStorage.debugOn) {
        System.err.println("[SocketChannelInst] unencrypted: " + unencrypted);
      }
      if (unencrypted == null) {
        return;
      }
      InetSocketAddress local = (InetSocketAddress) localSocket;
      InetSocketAddress remote = (InetSocketAddress) remoteSocket;
      Connection connection =
          new Connection(
              local.getAddress(), local.getPort(), remote.getAddress(), remote.getPort());
      NativeMemory packet = new NativeMemory(IOCTLPacket.packetPrefixSize + unencrypted.len);
      int offset =
          IOCTLPacket.writePacketPrefix(packet, 0, OperationType.SEND, connection, unencrypted.len);
      IOCTLPacket.writePacketBuffer(packet, offset, unencrypted.buf, 0, unencrypted.len);
      Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
    }
  }

  public static final class ReadAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void read(
        @Advice.Argument(0) final ByteBuffer dst,
        @Advice.FieldValue("localAddress") SocketAddress localSocket,
        @Advice.FieldValue("remoteAddress") SocketAddress remoteSocket) {
      if (!(localSocket instanceof InetSocketAddress)
          || !(remoteSocket instanceof InetSocketAddress)
          || (dst == null)) {
        return;
      }
      InetSocketAddress localSocketAddress = (InetSocketAddress) localSocket;
      InetSocketAddress remoteSocketAddress = (InetSocketAddress) remoteSocket;

      Connection c =
          new Connection(
              localSocketAddress.getAddress(),
              localSocketAddress.getPort(),
              remoteSocketAddress.getAddress(),
              remoteSocketAddress.getPort());

      String bufKey = ByteBufferExtractor.keyFromUsedBuffer(dst);
      SSLStorage.setConnectionForBuf(bufKey, c);
      if (SSLStorage.debugOn) {
        System.err.println("[SocketChannelInst] Setting connection for: " + bufKey);
      }
    }
  }

  public static final class ReadAdviceArray {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void read(
        @Advice.Argument(0) final ByteBuffer[] dsts,
        @Advice.FieldValue("localAddress") SocketAddress localSocket,
        @Advice.FieldValue("remoteAddress") SocketAddress remoteSocket) {
      if (!(localSocket instanceof InetSocketAddress)
          || !(remoteSocket instanceof InetSocketAddress)
          || (dsts == null)) {
        return;
      }
      InetSocketAddress localSocketAddress = (InetSocketAddress) localSocket;
      InetSocketAddress remoteSocketAddress = (InetSocketAddress) remoteSocket;

      Connection c =
          new Connection(
              localSocketAddress.getAddress(),
              localSocketAddress.getPort(),
              remoteSocketAddress.getAddress(),
              remoteSocketAddress.getPort());

      ByteBuffer dstBuffer =
          ByteBufferExtractor.flattenUsedByteBufferArray(dsts, ByteBufferExtractor.MAX_KEY_SIZE);
      String bufKey = Arrays.toString(dstBuffer.array());
      SSLStorage.setConnectionForBuf(bufKey, c);

      if (SSLStorage.debugOn) {
        System.err.println("[SocketChannelInst] Setting connection for: " + bufKey);
      }
    }
  }

  public static final class CleanupAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void cleanup(
        @Advice.FieldValue("localAddress") SocketAddress localSocket,
        @Advice.FieldValue("remoteAddress") SocketAddress remoteSocket) {
      if (!(localSocket instanceof InetSocketAddress)
          || !(remoteSocket instanceof InetSocketAddress)) {
        return;
      }
      InetSocketAddress localSocketAddress = (InetSocketAddress) localSocket;
      InetSocketAddress remoteSocketAddress = (InetSocketAddress) remoteSocket;

      Connection c =
          new Connection(
              localSocketAddress.getAddress(),
              localSocketAddress.getPort(),
              remoteSocketAddress.getAddress(),
              remoteSocketAddress.getPort());

      Connection tracked = SSLStorage.getActiveConnection(c);

      if (SSLStorage.debugOn) {
        System.err.println("[SocketChannelInst] Cleanup connection " + tracked);
      }

      if (tracked != null) {
        SSLStorage.cleanupConnectionBufMapping(tracked);
      }
    }
  }
}
