/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import io.opentelemetry.obi.java.Agent;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;

public final class JdkHttpClientTask implements Runnable {
  private final Runnable delegate;
  private final long requestThreadId;

  JdkHttpClientTask(Runnable delegate, long requestThreadId) {
    this.delegate = delegate;
    this.requestThreadId = requestThreadId;
  }

  @Override
  public void run() {
    long previousContext = SSLStorage.enterJdkHttpClientContext(requestThreadId);
    try {
      long threadId = Agent.NativeLib.gettid();
      if (requestThreadId != threadId) {
        ThreadInfo.sendTaskParentThreadContext(requestThreadId);
      }
      delegate.run();
    } finally {
      SSLStorage.finishTask(delegate);
      SSLStorage.restoreJdkHttpClientContext(previousContext);
    }
  }
}
