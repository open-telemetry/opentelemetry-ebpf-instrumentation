/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import static org.junit.jupiter.api.Assertions.*;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class SSLStorageTest {

  static class DummySSLEngine extends SSLEngine {
    @Override
    public String getPeerHost() {
      return null;
    }

    @Override
    public int getPeerPort() {
      return 0;
    }

    @Override
    public void beginHandshake() {}

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
      return null;
    }

    @Override
    public void closeInbound() {}

    @Override
    public boolean isInboundDone() {
      return false;
    }

    @Override
    public void closeOutbound() {}

    @Override
    public boolean isOutboundDone() {
      return false;
    }

    @Override
    public String[] getSupportedCipherSuites() {
      return new String[0];
    }

    @Override
    public String[] getEnabledCipherSuites() {
      return new String[0];
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {}

    @Override
    public String[] getSupportedProtocols() {
      return new String[0];
    }

    @Override
    public String[] getEnabledProtocols() {
      return new String[0];
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {}

    @Override
    public Runnable getDelegatedTask() {
      return null;
    }

    @Override
    public boolean getEnableSessionCreation() {
      return false;
    }

    @Override
    public boolean getNeedClientAuth() {
      return false;
    }

    @Override
    public boolean getUseClientMode() {
      return false;
    }

    @Override
    public boolean getWantClientAuth() {
      return false;
    }

    @Override
    public void setEnableSessionCreation(boolean b) {}

    @Override
    public void setNeedClientAuth(boolean b) {}

    @Override
    public void setUseClientMode(boolean b) {}

    @Override
    public void setWantClientAuth(boolean b) {}

    @Override
    public javax.net.ssl.SSLSession getHandshakeSession() {
      return null;
    }

    @Override
    public javax.net.ssl.SSLSession getSession() {
      return null;
    }

    @Override
    public SSLEngineResult unwrap(java.nio.ByteBuffer src, java.nio.ByteBuffer dst) {
      return null;
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
        throws SSLException {
      return null;
    }

    @Override
    public SSLEngineResult wrap(java.nio.ByteBuffer src, java.nio.ByteBuffer dst) {
      return null;
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst)
        throws SSLException {
      return null;
    }
  }

  @AfterEach
  void cleanup() {
    // Clean up thread locals
    SSLStorage.unencrypted.remove();
    SSLStorage.nettyConnection.remove();
    SSLStorage.exitSSLSocketRead();
    SSLStorage.exitSSLSocketWrite();
    SSLStorage.restoreJdkHttpClientContext(0);
  }

  @Test
  void testNestedSSLSocketOperationsAreCapturedOncePerDirection() {
    assertTrue(SSLStorage.enterSSLSocketRead());
    assertTrue(SSLStorage.isSSLSocketReadActive());
    assertFalse(SSLStorage.enterSSLSocketRead());

    assertTrue(SSLStorage.enterSSLSocketWrite());
    assertTrue(SSLStorage.isSSLSocketWriteActive());
    assertFalse(SSLStorage.enterSSLSocketWrite());

    SSLStorage.exitSSLSocketRead();
    SSLStorage.exitSSLSocketWrite();

    assertFalse(SSLStorage.isSSLSocketReadActive());
    assertFalse(SSLStorage.isSSLSocketWriteActive());
    assertTrue(SSLStorage.enterSSLSocketRead());
    assertTrue(SSLStorage.enterSSLSocketWrite());
  }

  @Test
  void testSessionConnectionMapping() throws Exception {
    SSLEngine engine = new DummySSLEngine();
    Connection conn =
        new Connection(
            InetAddress.getByName("127.0.0.1"), 1234, InetAddress.getByName("1.2.3.4"), 5678);

    assertNull(SSLStorage.getConnectionForSession(engine));
    SSLStorage.setConnectionForSession(engine, conn);
    assertEquals(conn, SSLStorage.getConnectionForSession(engine));
  }

  @Test
  void testBufConnectionMapping() throws Exception {
    String bufKey = "buf123";
    Connection conn =
        new Connection(
            InetAddress.getByName("127.0.0.2"), 4321, InetAddress.getByName("5.6.7.8"), 8765);

    assertNull(SSLStorage.getConnectionForBuf(bufKey));
    SSLStorage.setConnectionForBuf(bufKey, conn);
    assertEquals(conn, SSLStorage.getConnectionForBuf(bufKey));
    assertEquals(bufKey, conn.getBufferKey());
  }

  @Test
  void testActiveConnectionTracking() throws Exception {
    Connection conn =
        new Connection(
            InetAddress.getByName("127.0.0.3"), 1111, InetAddress.getByName("8.8.8.8"), 2222);

    assertTrue(SSLStorage.connectionUntracked(conn));
    SSLStorage.setConnectionForBuf("bufX", conn);
    assertFalse(SSLStorage.connectionUntracked(conn));
    assertEquals(conn, SSLStorage.getActiveConnection(conn));
  }

  @Test
  void testCleanupConnectionBufMapping() throws Exception {
    String bufKey = "bufY";
    Connection conn =
        new Connection(
            InetAddress.getByName("127.0.0.4"), 3333, InetAddress.getByName("9.9.9.9"), 4444);

    SSLStorage.setConnectionForBuf(bufKey, conn);
    assertEquals(conn, SSLStorage.getConnectionForBuf(bufKey));
    SSLStorage.cleanupConnectionBufMapping(conn);
    assertNull(SSLStorage.getConnectionForBuf(bufKey));
    assertNull(SSLStorage.getActiveConnection(conn));
  }

  @Test
  void testBufferMapping() {
    String encrypted = "enc";
    BytesWithLen plain = new BytesWithLen(new byte[] {1, 2, 3}, 3);

    assertNull(SSLStorage.getUnencryptedBuffer(encrypted));
    SSLStorage.setBufferMapping(encrypted, plain);
    assertEquals(plain, SSLStorage.getUnencryptedBuffer(encrypted));
    SSLStorage.removeBufferMapping(encrypted);
    assertNull(SSLStorage.getUnencryptedBuffer(encrypted));
  }

  @Test
  void testJdkHttpClientContextFollowsNestedTasks() {
    Object initialTask = new Object();
    Object nestedTask = new Object();

    long previousContext = SSLStorage.enterJdkHttpClientContext(41);
    SSLStorage.trackTask(90, initialTask);
    SSLStorage.restoreJdkHttpClientContext(previousContext);

    assertEquals(41, SSLStorage.parentThreadId(initialTask));

    long previousTaskContext = SSLStorage.enterJdkHttpClientTask(initialTask);
    SSLStorage.trackTask(91, nestedTask);
    SSLStorage.finishTask(initialTask);
    SSLStorage.restoreJdkHttpClientContext(previousTaskContext);

    assertEquals(41, SSLStorage.parentThreadId(nestedTask));

    SSLStorage.finishTask(nestedTask);
  }

  @Test
  void testUnmarkedTaskDoesNotChangeJdkHttpClientContext() {
    Object task = new Object();

    long previousContext = SSLStorage.enterJdkHttpClientTask(task);

    assertEquals(SSLStorage.NO_JDK_HTTP_CLIENT_CONTEXT, previousContext);
    SSLStorage.restoreJdkHttpClientContext(previousContext);

    SSLStorage.trackTask(72, task);
    assertEquals(72, SSLStorage.parentThreadId(task));
    SSLStorage.finishTask(task);
  }

  @Test
  void testJdkHttpClientContextFollowsSelectorEvents() {
    Object event = new Object();
    Object task = new Object();

    long previousContext = SSLStorage.enterJdkHttpClientContext(84);
    SSLStorage.trackJdkHttpClientEvent(event);
    SSLStorage.restoreJdkHttpClientContext(previousContext);

    long previousEventContext = SSLStorage.enterJdkHttpClientEvent(event);
    SSLStorage.trackTask(92, task);
    SSLStorage.restoreJdkHttpClientContext(previousEventContext);

    assertEquals(84, SSLStorage.parentThreadId(task));

    SSLStorage.finishTask(task);
  }

  @Test
  void testJdkHttpClientRunnableIsWrappedOnlyInRequestContext() {
    Runnable task = () -> {};

    assertSame(task, SSLStorage.wrapJdkHttpClientTask(task));

    long previousContext = SSLStorage.enterJdkHttpClientContext(73);
    Runnable wrapped = SSLStorage.wrapJdkHttpClientTask(task);
    SSLStorage.restoreJdkHttpClientContext(previousContext);

    assertNotSame(task, wrapped);
    assertTrue(SSLStorage.isJdkHttpClientTask(wrapped));
    assertSame(wrapped, SSLStorage.wrapJdkHttpClientTask(wrapped));
  }
}
