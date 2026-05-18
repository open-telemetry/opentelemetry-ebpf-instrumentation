// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/tp_info.h>

#include <gotracer/types/stream_key.h>

typedef struct grpc_srv_func_invocation {
    u64 start_monotime_ns;
    u64 stream;
    u64 st;
    tp_info_t tp;
} grpc_srv_func_invocation_t;

typedef struct grpc_client_func_invocation {
    u64 start_monotime_ns;
    u64 cc;
    u64 method;
    u64 method_len;
    tp_info_t tp;
    u64 flags;
} grpc_client_func_invocation_t;

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
