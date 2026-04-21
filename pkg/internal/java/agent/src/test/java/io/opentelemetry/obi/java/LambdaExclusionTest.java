/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.instrument.Instrumentation;
import java.util.Collections;
import java.util.concurrent.*;
import net.bytebuddy.agent.ByteBuddyAgent;
import org.junit.jupiter.api.Test;
import testutil.LambdaFactory;

/**
 * Verifies that dynamic agent attachment does not break lambda classes.
 *
 * <p>On Java 8, lambda classes are VM anonymous classes. Due to JDK-8145964, retransforming them
 * via {@code inst.retransformClasses()} corrupts their constant pool linkage to the host class,
 * causing NoClassDefFoundError. The bug was fixed in Java 9 (anonymous classes became
 * non-modifiable) and is irrelevant on Java 15+ (lambdas are hidden classes).
 *
 * <p>This test calls the actual production code: {@link Agent#builder} to install the ByteBuddy
 * transformer, and {@link Agent#retransformLoadedClasses} to retransform already-loaded classes.
 * Without the $$Lambda exclusion in retransformLoadedClasses, this test fails on Java 8 with
 * NoClassDefFoundError.
 *
 * <p>Lambdas come from {@link testutil.LambdaFactory} (outside io.opentelemetry.obi) because
 * Agent.builder() ignores that package prefix.
 */
class LambdaExclusionTest {

  /**
   * Installs the agent's ByteBuddy transformer and retransforms loaded classes using the actual
   * production code, then exercises lambda classes to verify they weren't corrupted.
   *
   * <p>Without $$Lambda exclusion in {@link Agent#retransformLoadedClasses}, this throws
   * NoClassDefFoundError on Java 8.
   */
  @Test
  void lambdasWorkAfterAgentAttachment() throws Exception {
    // Phase 1: Create and exercise lambdas before agent attachment.
    // Lambdas come from testutil.LambdaFactory, outside io.opentelemetry.obi,
    // so they won't be ignored by the builder's nameStartsWith("io.opentelemetry.obi") rule.
    Callable<String> callable = LambdaFactory.newCallable("before");
    assertEquals("before", callable.call());

    Runnable runnable = LambdaFactory.newRunnable();
    runnable.run();

    ExecutorService executor = Executors.newSingleThreadExecutor();
    try {
      Future<String> f = executor.submit(LambdaFactory.newCallable("baseline"));
      assertEquals("baseline", f.get());
    } finally {
      shutdownAndAwait(executor);
    }

    // Phase 2: Install the agent's ByteBuddy transformer using the actual Agent.builder().
    Instrumentation inst = ByteBuddyAgent.install();

    java.lang.instrument.ClassFileTransformer transformer =
        Agent.builder(Collections.emptyMap(), inst)
            .type(io.opentelemetry.obi.java.instrumentations.RunnableInst.type())
            .transform(io.opentelemetry.obi.java.instrumentations.RunnableInst.transformer())
            .type(io.opentelemetry.obi.java.instrumentations.CallableInst.type())
            .transform(io.opentelemetry.obi.java.instrumentations.CallableInst.transformer())
            .type(io.opentelemetry.obi.java.instrumentations.JavaExecutorInst.type())
            .transform(io.opentelemetry.obi.java.instrumentations.JavaExecutorInst.transformer())
            .installOn(inst);

    try {
      // Phase 3: Retransform loaded classes using the actual production code.
      // Agent.retransformLoadedClasses() is the same method called by agentmain().
      // If it doesn't skip $$Lambda classes, this corrupts them on Java 8.
      Agent.retransformLoadedClasses(inst);

      // Phase 4: Exercise lambdas after retransformation.
      // If lambda classes were corrupted, this throws:
      //   java.lang.NoClassDefFoundError: testutil/LambdaFactory$$Lambda$XX
      executor = Executors.newSingleThreadExecutor();
      try {
        Future<String> f = executor.submit(LambdaFactory.newCallable("after-attach"));
        assertEquals("after-attach", f.get());

        executor.submit(LambdaFactory.newRunnable()).get();
      } finally {
        shutdownAndAwait(executor);
      }
    } finally {
      inst.removeTransformer(transformer);
    }
  }

  private static void shutdownAndAwait(ExecutorService executor) throws InterruptedException {
    executor.shutdown();
    if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
      executor.shutdownNow();
      fail("executor did not terminate within 5 seconds");
    }
  }
}
