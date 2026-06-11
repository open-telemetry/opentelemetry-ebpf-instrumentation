/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

/**
 * Instruments java.lang.VirtualThread.mount()/unmount(): on every mount the agent reports (carrier
 * kernel thread -> this VT's logical thread id) through the ioctl channel (VT_MOUNT), and on every
 * unmount deletes that entry (VT_UNMOUNT), so eBPF can key correlation by the logical id instead of
 * the carrier tid. mount()/unmount() are unchanged across JDK 21..25; on JDKs without virtual
 * threads the type matcher never matches.
 *
 * <p>Both advices run at method EXIT. At mount() EXIT Thread.currentThread() is already the virtual
 * thread; at unmount() EXIT it is back to the carrier. gettid() returns the CARRIER's kernel tid in
 * both, which is exactly the map key.
 *
 * <p>The advice bodies must remain lock-free and non-blocking: a contended monitor or synchronized
 * I/O on the mount path deadlocks all carriers.
 */
public class VirtualThreadInst {
  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.named("java.lang.VirtualThread");
  }

  public static boolean matches(Class<?> clazz) {
    return "java.lang.VirtualThread".equals(clazz.getName());
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(Advice.to(MountAdvice.class).on(ElementMatchers.named("mount")))
            .visit(Advice.to(UnmountAdvice.class).on(ElementMatchers.named("unmount")));
  }

  @SuppressWarnings("unused")
  public static final class MountAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void exit() {
      ThreadInfo.onVirtualThreadMount();
    }
  }

  @SuppressWarnings("unused")
  public static final class UnmountAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void exit() {
      ThreadInfo.onVirtualThreadUnmount();
    }
  }
}
