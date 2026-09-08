// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

// Programs attached to uprobes run in task context, where kernels with lazy or
// full preemption may preempt them mid-execution: since
// https://github.com/torvalds/linux/commit/8c7dcb84e3b7 (v6.0), uprobe runs
// take only migrate_disable, having dropped both the explicit preempt_disable
// and the bpf_prog_active same-CPU exclusion of the old path. Kernels 6.13+
// also run every kprobe-type program with at least 64 bytes of stack on a
// per-CPU private stack (the verifier's PRIV_STACK_ADAPTIVE mode, with no
// opt-out, https://github.com/torvalds/linux/commit/a76ab5731e32), assuming
// per-CPU exclusivity that only holds while execution cannot interleave. A
// task preempted inside such a program shares its private stack frame with
// whichever task runs the same program next on that CPU, and resumes with its
// spilled registers overwritten: verified-sound pointers reload as garbage and
// the machine panics inside the program or inside map helpers fed the bad
// pointers.
//
// Every program that can execute in uprobe context disables preemption for its
// body, which restores the exclusivity the private stack needs. Programs
// entered from kprobes or tracepoints already run with preemption off, and the
// pair nests, so sharing tail-call chains between the two is fine. The kfuncs
// exist since 6.10; on older kernels, which predate private stacks, the calls
// resolve to nothing and the guard vanishes.
//
// The verifier enforces the discipline: a guarded program cannot return or
// tail-call while preemption is disabled, so a missed exit is a load-time
// error, never a runtime leak. Tail calls therefore re-enable around the jump
// (the outgoing frame is dead past that point) and the target re-disables.

extern void bpf_preempt_disable(void) __ksym __weak;
extern void bpf_preempt_enable(void) __ksym __weak;

static __always_inline void preempt_guard_enter(void) {
    if (bpf_preempt_disable) {
        bpf_preempt_disable();
    }
}

static __always_inline void preempt_guard_exit(void) {
    if (bpf_preempt_enable) {
        bpf_preempt_enable();
    }
}

// clang-format off
#define PREEMPT_GUARDED(expr)                                                                      \
    ({                                                                                             \
        preempt_guard_enter();                                                                     \
        const int __guarded_ret = (expr);                                                          \
        preempt_guard_exit();                                                                      \
        __guarded_ret;                                                                             \
    })
// clang-format on

// A failed tail call falls through, so the guard must come back on either way;
// on success the jump target re-enters it
#define preempt_guarded_tail_call(ctx, table, index)                                               \
    do {                                                                                           \
        preempt_guard_exit();                                                                      \
        bpf_tail_call(ctx, table, index);                                                          \
        preempt_guard_enter();                                                                     \
    } while (0)

#define preempt_guarded_tail_call_static(ctx, table, index)                                        \
    do {                                                                                           \
        preempt_guard_exit();                                                                      \
        bpf_tail_call_static(ctx, table, index);                                                   \
        preempt_guard_enter();                                                                     \
    } while (0)

// Wraps a plain program definition so its body runs under the guard:
//   SEC("uprobe/x")
//   int GUARDED_PROG(name, struct pt_regs *, ctx) { ... }
#define GUARDED_PROG(name, ctx_type, ctx_arg)                                                      \
    name(ctx_type ctx_arg);                                                                        \
    static __always_inline typeof(name(0)) ____##name(ctx_type ctx_arg);                           \
    typeof(name(0)) name(ctx_type ctx_arg) {                                                       \
        return PREEMPT_GUARDED(____##name(ctx_arg));                                               \
    }                                                                                              \
    static __always_inline typeof(name(0)) ____##name(ctx_type ctx_arg)

// Guarded twins of the bpf_tracing.h program macros: same expansion, with the
// thin entry wrapper running the body under the guard
#define BPF_KPROBE_GUARDED(name, args...)                                                          \
    name(struct pt_regs *ctx);                                                                     \
    static __attribute__((always_inline)) typeof(name(0)) ____##name(struct pt_regs *ctx, ##args); \
    typeof(name(0)) name(struct pt_regs *ctx) {                                                    \
        _Pragma("GCC diagnostic push")                                                             \
            _Pragma("GCC diagnostic ignored \"-Wint-conversion\"") return PREEMPT_GUARDED(         \
                ____##name(___bpf_kprobe_args(args)));                                             \
        _Pragma("GCC diagnostic pop")                                                              \
    }                                                                                              \
    static __attribute__((always_inline)) typeof(name(0)) ____##name(struct pt_regs *ctx, ##args)

#define BPF_KRETPROBE_GUARDED(name, args...)                                                       \
    name(struct pt_regs *ctx);                                                                     \
    static __attribute__((always_inline)) typeof(name(0)) ____##name(struct pt_regs *ctx, ##args); \
    typeof(name(0)) name(struct pt_regs *ctx) {                                                    \
        _Pragma("GCC diagnostic push")                                                             \
            _Pragma("GCC diagnostic ignored \"-Wint-conversion\"") return PREEMPT_GUARDED(         \
                ____##name(___bpf_kretprobe_args(args)));                                          \
        _Pragma("GCC diagnostic pop")                                                              \
    }                                                                                              \
    static __attribute__((always_inline)) typeof(name(0)) ____##name(struct pt_regs *ctx, ##args)

#define BPF_UPROBE_GUARDED(name, args...) BPF_KPROBE_GUARDED(name, ##args)
#define BPF_URETPROBE_GUARDED(name, args...) BPF_KRETPROBE_GUARDED(name, ##args)
