/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.Agent;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class RunnableInst {
  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.isSubTypeOf(Runnable.class);
  }

  public static boolean matches(Class<?> clazz) {
    return Runnable.class.isAssignableFrom(clazz);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder.visit(
            Advice.to(RunnableAdvice.class)
                .on(ElementMatchers.named("run").and(ElementMatchers.takesArguments(0))));
  }

  @SuppressWarnings("unused")
  public static final class RunnableAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.This Runnable task) {
      // VT correlation is handled by the VirtualThread.mount hook; the
      // tracked parent here would be the dispatcher's tid (e.g. Tomcat
      // Poller), which poisons java_tasks under virtual threads.
      if (ThreadInfo.loomTaskOrVirtualThread(task)) {
        return;
      }
      Long parentId = SSLStorage.parentThreadId(task);
      if (parentId != null) {
        long threadId = Agent.NativeLib.gettid();
        if (SSLStorage.bootDebugOn().equals(true)) {
          System.err.println(
              "[RunnableAdvice] task = "
                  + task.hashCode()
                  + ", parent = "
                  + parentId
                  + ", thread = "
                  + threadId);
        }
        if (parentId != threadId) {
          ThreadInfo.sendTaskParentThreadContext(parentId);
        }
      }
      SSLStorage.untrackTask(task);
    }
  }
}
