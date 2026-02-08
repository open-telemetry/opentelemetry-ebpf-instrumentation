/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static io.opentelemetry.obi.java.instrumentations.util.ByteBufferExtractor.b;

import io.opentelemetry.obi.java.Agent;
import io.opentelemetry.obi.java.ebpf.IOCTLPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import io.opentelemetry.obi.java.instrumentations.data.BytesWithLen;
import io.opentelemetry.obi.java.instrumentations.data.Connection;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import io.opentelemetry.obi.java.instrumentations.util.ByteBufferExtractor;
import java.nio.ByteBuffer;
import java.util.Arrays;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class SSLEngineInst {

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.isSubTypeOf(SSLEngine.class);
  }

  public static boolean matches(Class<?> clazz) {
    return SSLEngine.class.isAssignableFrom(clazz);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(UnwrapAdvice.class)
                    .on(
                        ElementMatchers.named("unwrap")
                            .and(ElementMatchers.takesArguments(2))
                            .and(ElementMatchers.takesArgument(1, ByteBuffer.class))))
            .visit(
                Advice.to(UnwrapAdviceArray.class)
                    .on(
                        ElementMatchers.named("unwrap")
                            .and(ElementMatchers.takesArguments(2))
                            .and(ElementMatchers.takesArgument(1, ByteBuffer[].class))))
            .visit(
                Advice.to(WrapAdvice.class)
                    .on(
                        ElementMatchers.named("wrap")
                            .and(ElementMatchers.takesArguments(2))
                            .and(ElementMatchers.takesArgument(0, ByteBuffer.class))))
            .visit(
                Advice.to(WrapAdviceArray.class)
                    .on(
                        ElementMatchers.named("wrap")
                            .and(ElementMatchers.takesArguments(2))
                            .and(ElementMatchers.takesArgument(0, ByteBuffer[].class))));
  }

  public static final class UnwrapAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static int unwrap(
        @Advice.This final javax.net.ssl.SSLEngine engine,
        @Advice.Argument(1) final ByteBuffer dst) {
      if (dst == null) {
        return -1;
      }
      if (engine.getSession().getId().length == 0) {
        return -1;
      }

      return b(dst).position();
    }

    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void unwrap(
        @Advice.This final javax.net.ssl.SSLEngine engine,
        @Advice.Enter int savedPos,
        @Advice.Argument(0) final ByteBuffer src,
        @Advice.Argument(1) final ByteBuffer dst,
        @Advice.Return SSLEngineResult result) {
      Connection c = SSLStorage.getConnectionForSession(engine);

      if (src == null || dst == null) {
        return;
      }

      if (c == null) {
        String bufKey = ByteBufferExtractor.keyFromUsedBuffer(src);
        c = SSLStorage.getConnectionForBuf(bufKey);

        if (c == null) {
          c = (Connection) SSLStorage.nettyConnection.get();
        }

        if (c == null) {
          if (SSLStorage.debugOn) {
            System.err.println("[SSLEngineInst] Can't find connection " + engine);
          }
        } else {
          SSLStorage.setConnectionForSession(engine, c);
        }
      }

      if (engine.getSession().getId().length == 0) {
        return;
      }

      if (result.bytesProduced() > 0 && b(dst).limit() >= result.bytesProduced()) {
        if (savedPos == -1) {
          return;
        }

        ByteBuffer dup = dst.duplicate();
        b(dup).position(savedPos);
        ByteBuffer dstBuffer = ByteBufferExtractor.fromFreshBuffer(dup, result.bytesProduced());

        byte[] b = dstBuffer.array();

        if (SSLStorage.debugOn) {
          System.err.println(
              "[SSLEngineInst] unwrap:" + new String(b, java.nio.charset.StandardCharsets.UTF_8));
        }

        NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + b.length);
        int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.RECEIVE, c, b.length);
        IOCTLPacket.writePacketBuffer(p, wOff, b);
        Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, p.getAddress());
      }
    }
  }

  public static final class UnwrapAdviceArray {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static int[] unwrap(
        @Advice.This final javax.net.ssl.SSLEngine engine,
        @Advice.Argument(1) final ByteBuffer[] dsts) {
      if (dsts == null) {
        return null;
      }
      if (dsts.length == 0 || engine.getSession().getId().length == 0) {
        return null;
      }

      int[] positions = new int[dsts.length];
      for (int i = 0; i < dsts.length; i++) {
        if (dsts[i] == null) {
          positions[i] = -1;
          continue;
        }
        positions[i] = b(dsts[i]).position();
      }

      return positions;
    }

    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void unwrap(
        @Advice.This final javax.net.ssl.SSLEngine engine,
        @Advice.Enter int[] savedDstPositions,
        @Advice.Argument(1) final ByteBuffer[] dsts,
        @Advice.Return SSLEngineResult result) {
      if (dsts == null) {
        return;
      }
      Connection c = SSLStorage.getConnectionForSession(engine);

      if (c == null) {
        ByteBuffer dstBuffer =
            ByteBufferExtractor.flattenUsedByteBufferArray(dsts, ByteBufferExtractor.MAX_KEY_SIZE);
        String bufKey = Arrays.toString(dstBuffer.array());
        c = SSLStorage.getConnectionForBuf(bufKey);

        if (c == null) {
          c = (Connection) SSLStorage.nettyConnection.get();
        }

        if (c == null) {
          if (SSLStorage.debugOn) {
            System.err.println("[SSLEngineInst] Can't find connection for dst array");
          }
        } else {
          SSLStorage.setConnectionForSession(engine, c);
        }
      }

      if (dsts.length == 0 || engine.getSession().getId().length == 0) {
        return;
      }

      if (result.bytesProduced() > 0) {
        if (savedDstPositions == null) {
          return;
        }

        ByteBuffer[] dups = new ByteBuffer[dsts.length];
        for (int i = 0; i < dsts.length; i++) {
          if (dsts[i] == null) {
            continue;
          }
          if (savedDstPositions[i] != -1) {
            dups[i] = dsts[i].duplicate();
            b(dups[i]).position(savedDstPositions[i]);
          }
        }

        ByteBuffer dstBuffer = ByteBufferExtractor.flattenFreshByteBufferArray(dups);

        byte[] b = dstBuffer.array();
        int len = b(dstBuffer).position();

        if (SSLStorage.debugOn) {
          System.err.println(
              "[SSLEngineInst] unwrap array:"
                  + new String(b, java.nio.charset.StandardCharsets.UTF_8));
        }

        NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + len);
        int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.RECEIVE, c, len);
        IOCTLPacket.writePacketBuffer(p, wOff, b, 0, len);
        Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, p.getAddress());
      }
    }
  }

  public static final class WrapAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void wrap(
        @Advice.This final javax.net.ssl.SSLEngine engine,
        @Advice.Argument(0) final ByteBuffer src) {
      if (src == null) {
        return;
      }
      if (engine.getSession().getId().length == 0) {
        return;
      }

      if (!b(src).hasRemaining()) {
        return;
      }

      ByteBuffer buf = ByteBufferExtractor.fromFreshBuffer(src, b(src).remaining());
      byte[] b = buf.array();
      int len = b(buf).position();

      SSLStorage.unencrypted.set(new BytesWithLen(b, len));
    }

    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void wrap(
        @Advice.This final javax.net.ssl.SSLEngine engine,
        @Advice.Argument(0) final ByteBuffer src,
        @Advice.Argument(1) final ByteBuffer dst,
        @Advice.Return SSLEngineResult result) {
      if (src == null || dst == null) {
        SSLStorage.unencrypted.remove();
        return;
      }
      if (engine.getSession().getId().length == 0) {
        SSLStorage.unencrypted.remove();
        return;
      }

      if (result.bytesConsumed() > 0) {
        BytesWithLen bLen = SSLStorage.unencrypted.get();
        if (bLen == null) {
          return;
        }

        if (SSLStorage.debugOn) {
          System.err.println(
              "[SSLEngineInst] wrap :"
                  + new String(bLen.buf, java.nio.charset.StandardCharsets.UTF_8));
        }

        Connection c = (Connection) SSLStorage.nettyConnection.get();
        if (SSLStorage.debugOn) {
          System.err.println(
              "[SSLEngineInst] Found netty connection "
                  + c
                  + " thread "
                  + Thread.currentThread().getName());
        }
        if (c != null) {
          NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + bLen.len);
          int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.SEND, c, bLen.len);
          IOCTLPacket.writePacketBuffer(p, wOff, bLen.buf, 0, bLen.len);
          Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, p.getAddress());
        } else {
          String encrypted = ByteBufferExtractor.keyFromUsedBuffer(dst);
          if (SSLStorage.debugOn) {
            System.err.println("[SSLEngineInst] buf mapping on: " + encrypted);
          }
          SSLStorage.setBufferMapping(encrypted, bLen);
        }
      }

      SSLStorage.unencrypted.remove();
    }
  }

  public static final class WrapAdviceArray {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void wrap(
        @Advice.This final javax.net.ssl.SSLEngine engine,
        @Advice.Argument(0) final ByteBuffer[] srcs) {
      if (srcs == null) {
        return;
      }
      if (srcs.length == 0 || engine.getSession().getId().length == 0) {
        return;
      }

      ByteBuffer buf = ByteBufferExtractor.flattenFreshByteBufferArray(srcs);
      byte[] b = buf.array();
      int len = b(buf).position();

      SSLStorage.unencrypted.set(new BytesWithLen(b, len));
    }

    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void wrap(
        @Advice.This final javax.net.ssl.SSLEngine engine,
        @Advice.Argument(0) final ByteBuffer[] srcs,
        @Advice.Argument(1) final ByteBuffer dst,
        @Advice.Return SSLEngineResult result) {
      if (srcs == null || dst == null) {
        SSLStorage.unencrypted.remove();
        return;
      }
      if (srcs.length == 0 || engine.getSession().getId().length == 0) {
        SSLStorage.unencrypted.remove();
        return;
      }

      if (result.bytesConsumed() > 0) {
        BytesWithLen bLen = SSLStorage.unencrypted.get();
        if (bLen == null) {
          return;
        }

        if (SSLStorage.debugOn) {
          System.err.println(
              "[SSLEngineInst] wrap array :["
                  + bLen.len
                  + "]"
                  + new String(bLen.buf, java.nio.charset.StandardCharsets.UTF_8));
        }

        Connection c = (Connection) SSLStorage.nettyConnection.get();
        if (SSLStorage.debugOn) {
          System.err.println(
              "[SSLEngineInst] Found netty connection "
                  + c
                  + " thread "
                  + Thread.currentThread().getName());
        }
        if (c != null) {
          NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + bLen.len);
          int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.SEND, c, bLen.len);
          IOCTLPacket.writePacketBuffer(p, wOff, bLen.buf, 0, bLen.len);
          Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, p.getAddress());
        } else {
          String encrypted = ByteBufferExtractor.keyFromUsedBuffer(dst);
          if (SSLStorage.debugOn) {
            System.err.println("[SSLEngineInst] buf array mapping on: " + encrypted);
          }
          SSLStorage.setBufferMapping(encrypted, bLen);
        }
      }

      SSLStorage.unencrypted.remove();
    }
  }
}
