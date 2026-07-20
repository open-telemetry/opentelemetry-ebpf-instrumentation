// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

enum bpf_debug_flags {
    k_bpf_debug_trace_pipe = 1 << 0,
    k_bpf_debug_userspace = 1 << 1,
};

volatile const u32 g_bpf_debug_flags = 0;
volatile const bool g_bpf_traceparent_enabled = (bool)0;
volatile const bool g_bpf_header_propagation = (bool)0;
volatile const bool g_bpf_loop_enabled = (bool)0;

static inline __attribute__((always_inline)) bool bpf_debug_enabled() {
    return g_bpf_debug_flags != 0;
}
