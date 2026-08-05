// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>
#include <common/go_addr_key.h>
#include <common/tp_info.h>

#include <gotracer/types/stream_key.h>

typedef struct grpc_srv_func_invocation {
    u64 start_monotime_ns;
    u64 stream;
    u64 st;
    tp_info_t tp;
} grpc_srv_func_invocation_t;

typedef struct grpc_client_request_id {
    go_addr_key_t creator;
    u64 process_start_time;
    u64 sequence;
    u32 cpu;
    u32 _pad;
} grpc_client_request_id_t;

typedef struct grpc_client_func_invocation {
    u64 start_monotime_ns;
    u64 cc;
    u64 method;
    u64 method_len;
    tp_info_t tp;
    u64 flags;
    go_addr_key_t request_key;
    grpc_client_request_id_t request_id;
    go_addr_key_t stream_key;
    connection_info_t conn;
    u8 has_conn;
    u8 has_stream;
    u8 terminal;
    u8 terminal_error;
    u8 terminal_emitted;
    u8 _pad[7];
} grpc_client_func_invocation_t;

typedef struct transport_new_client_invocation {
    grpc_client_func_invocation_t inv;
    go_exact_process_stream_key_t s_key;
} transport_new_client_invocation_t;

typedef struct grpc_framer_func_invocation {
    u64 framer_ptr;
    tp_info_t tp;
    outgoing_trace_token_t handoff_token;
    egress_key_t egress;
    u32 _egress_pad;
    s64 offset;
} grpc_framer_func_invocation_t;

// Bridge state stashed by executeAndPut on the NewStream goroutine and consumed
// by originateStream on the loopyWriter goroutine. Keyed by *headerFrame ptr
typedef struct pending_h2_invocation {
    grpc_client_func_invocation_t inv;
    u64 conn_ptr;
} pending_h2_invocation_t;
