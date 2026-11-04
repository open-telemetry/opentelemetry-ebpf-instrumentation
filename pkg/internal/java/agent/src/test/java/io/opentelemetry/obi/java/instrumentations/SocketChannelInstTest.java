/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.*;

import io.opentelemetry.obi.java.instrumentations.data.BytesWithLen;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import io.opentelemetry.obi.java.instrumentations.util.ByteBufferExtractor;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.dynamic.loading.ClassLoadingStrategy;
import net.bytebuddy.matcher.ElementMatchers;
import org.junit.jupiter.api.Test;

class SocketChannelInstTest {
  @Test
  void claimsPlaintextBeforeSingleBufferWrite() throws Exception {
    checkWrite(ByteBuffer.class, SocketChannelInst.WriteAdvice.class);
  }

  @Test
  void claimsPlaintextBeforeGatheringWrite() throws Exception {
    checkWrite(ByteBuffer[].class, SocketChannelInst.WriteAdviceArray.class);
  }

  private void checkWrite(Class<?> argument, Class<?> advice) throws Exception {
    ByteBuffer ciphertext = ByteBuffer.wrap(new byte[] {1, 2, 3});
    String key = ByteBufferExtractor.keyFromFreshBuffer(ciphertext);
    SSLStorage.setBufferMapping(key, new BytesWithLen(new byte[] {4, 5, 6}, 3));
    Class<?> instrumented =
        new ByteBuddy()
            .redefine(FastPeerWrite.class)
            .name(FastPeerWrite.class.getName() + advice.getSimpleName())
            .visit(
                Advice.to(advice)
                    .on(
                        ElementMatchers.named("write")
                            .and(ElementMatchers.takesArgument(0, argument))))
            .make()
            .load(getClass().getClassLoader(), ClassLoadingStrategy.Default.WRAPPER)
            .getLoaded();
    Object channel = instrumented.getConstructor().newInstance();
    Object buffers = argument.isArray() ? new ByteBuffer[] {ciphertext} : ciphertext;
    try {
      assertEquals(
          true,
          instrumented.getMethod("write", argument).invoke(channel, buffers),
          "a peer can respond before write returns; plaintext must already be claimed");
      assertNull(
          SSLStorage.getUnencryptedBuffer(key), "a retry must not report the same plaintext");
      assertEquals(3, ciphertext.position(), "the application still consumes its ciphertext");
    } finally {
      SSLStorage.removeBufferMapping(key);
    }
  }

  public static class FastPeerWrite {
    public SocketAddress localAddress = new InetSocketAddress("127.0.0.1", 40000);
    public SocketAddress remoteAddress = new InetSocketAddress("127.0.0.1", 8443);

    public boolean write(ByteBuffer ciphertext) {
      boolean claimed =
          SSLStorage.getUnencryptedBuffer(ByteBufferExtractor.keyFromFreshBuffer(ciphertext))
              == null;
      ((java.nio.Buffer) ciphertext).position(ciphertext.limit());
      return claimed;
    }

    public boolean write(ByteBuffer[] ciphertext) {
      return write(ciphertext[0]);
    }
  }
}
