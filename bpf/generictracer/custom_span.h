// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <common/usdt_types.h>
#include <shared/obi_ctx.h>

enum {
    k_custom_span_max_args = 12,
    k_custom_span_str_len = 128,
};

enum custom_span_event_kind {
    k_custom_span_kind_invalid = 0,
    k_custom_span_kind_start = 1,
    k_custom_span_kind_end = 2,
    k_custom_span_kind_single = 3,
};

enum custom_span_arg_kind {
    k_custom_span_arg_none = 0,
    k_custom_span_arg_int = 1,
    k_custom_span_arg_str = 2,
};

struct custom_span_event {
    u8 type;
    u8 kind;
    u8 arg_cnt;
    u8 has_trace_ctx;
    u8 pair_kind; // mirrors spec.pair_kind so userspace picks the right pair key
    u8 _pad0a[3];
    u64 cookie;
    u64 timestamp;
    u32 global_pid;
    u32 global_tid;
    u32 ns_pid;
    u32 ns_tid;
    u32 pid_ns_id;
    u32 _pad1;
    u64 g_ptr; // Go runtime g* — pair key on Go function_span (survives goroutine moves)

    obi_ctx_info_t trace_ctx;

    u8 arg_kind[k_custom_span_max_args];
    u16 arg_str_len[k_custom_span_max_args];
    u32 _pad2;
    u64 arg_int[k_custom_span_max_args];
    u8 arg_str[k_custom_span_max_args][k_custom_span_str_len];
};
