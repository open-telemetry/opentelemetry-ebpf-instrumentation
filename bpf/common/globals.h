// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

enum bpf_debug_flags {
    BPF_DEBUG_TRACE_PIPE = 1 << 0,
    BPF_DEBUG_RINGBUF = 1 << 1,
};

volatile const u32 g_bpf_debug_flags = 0;
volatile const bool g_bpf_traceparent_enabled = false;
volatile const bool g_bpf_header_propagation = false;
volatile const bool g_bpf_loop_enabled = false;

#define g_bpf_debug (g_bpf_debug_flags != 0)
