// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

// No mapping lives in the first page, so a user pointer at or below this is a
// sentinel, such as the dangling pointer of a Box or Vec that never allocated.
enum { k_rust_low_address_limit = 4096 };

static __always_inline u64 rust_return_word2(const struct pt_regs *ctx) {
#ifdef __TARGET_ARCH_x86
    return ctx->dx;
#else
    return ctx->regs[1];
#endif
}

static __always_inline u64 rust_sret(const struct pt_regs *ctx) {
#ifdef __TARGET_ARCH_x86
    return PT_REGS_PARM1(ctx);
#else
    return ctx->regs[8];
#endif
}

static __always_inline u64 rust_sret_arg1(const struct pt_regs *ctx) {
#ifdef __TARGET_ARCH_x86
    return PT_REGS_PARM2(ctx);
#else
    return PT_REGS_PARM1(ctx);
#endif
}

static __always_inline u64 rust_sret_arg3(const struct pt_regs *ctx) {
#ifdef __TARGET_ARCH_x86
    return PT_REGS_PARM4(ctx);
#else
    return PT_REGS_PARM3(ctx);
#endif
}

static __always_inline u64 rust_sret_arg2(const struct pt_regs *ctx) {
#ifdef __TARGET_ARCH_x86
    return PT_REGS_PARM3(ctx);
#else
    return PT_REGS_PARM2(ctx);
#endif
}
