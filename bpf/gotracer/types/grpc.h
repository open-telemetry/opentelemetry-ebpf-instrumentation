// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>
#include <common/tp_info.h>

#include <gotracer/types/stream_key.h>

typedef struct grpc_srv_func_invocation {
    u64 start_monotime_ns;
    u64 stream;
    u64 st;
    tp_info_t tp;
} grpc_srv_func_invocation_t;

enum {
    k_grpc_client_func_type_invoke = 0,
    k_grpc_client_func_type_new_stream = 1,
};

typedef struct grpc_client_func_invocation {
    u64 start_monotime_ns;
    u64 cc;
    u64 method;
    u64 method_len;
    tp_info_t tp;
    u64 flags;
    u64 stream_ptr;
    u64 transport_ptr;
    u32 stack_off;
    u32 func_type;
    u32 stream_constructor_active;
    u32 _pad;
} grpc_client_func_invocation_t;

enum { k_grpc_client_max_depth = 4 };

typedef struct grpc_client_invocation_stack {
    grpc_client_func_invocation_t frames[k_grpc_client_max_depth];
    u32 depth;
    u32 overflow;
    u32 unstored_stack_off;
    u32 _pad;
} grpc_client_invocation_stack_t;

typedef struct grpc_client_stream_state {
    grpc_client_func_invocation_t invocation;
    connection_info_t conn;
    u32 _pad;
    u64 claimed;
} grpc_client_stream_state_t;

typedef struct grpc_client_early_finish {
    u32 has_err;
} grpc_client_early_finish_t;

typedef struct transport_new_client_invocation {
    grpc_client_func_invocation_t inv;
    stream_key_t s_key;
} transport_new_client_invocation_t;

typedef struct grpc_framer_func_invocation {
    u64 framer_ptr;
    tp_info_t tp;
    s64 offset;
    u16 s_port;
    u16 d_port;
    u32 stream_id;
} grpc_framer_func_invocation_t;

// Bridge state stashed by executeAndPut on the NewStream goroutine and consumed
// by originateStream on the loopyWriter goroutine. Keyed by *headerFrame ptr
typedef struct pending_h2_invocation {
    grpc_client_func_invocation_t inv;
    u64 conn_ptr;
} pending_h2_invocation_t;
