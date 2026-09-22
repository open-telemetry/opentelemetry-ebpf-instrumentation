// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>
#include <common/go_addr_key.h>
#include <common/grpc_h2_owned_stream.h>
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

typedef struct grpc_stream_key {
    go_addr_key_t conn;
    u32 stream_id;
    u32 _pad;
} grpc_stream_key_t;

typedef struct transport_new_client_invocation {
    grpc_client_func_invocation_t inv;
    grpc_stream_key_t s_key;
} transport_new_client_invocation_t;

typedef struct grpc_framer_func_invocation {
    u64 framer_ptr;
    tp_info_t tp;
    s64 offset;
    u32 stream_id;
    u16 s_port;
    u16 d_port;
    u8 frame_type;
    bool awaiting_continuation;
    u8 _pad[6];
} grpc_framer_func_invocation_t;

typedef struct grpc_connection {
    connection_info_t conn;
    u32 pid;
    u64 socket_cookie;
} grpc_connection_t;

// Bridge state stashed by executeAndPut on the NewStream goroutine and consumed
// by the client header handler on the loopyWriter goroutine.
typedef struct pending_h2_invocation {
    grpc_client_func_invocation_t inv;
    go_addr_key_t request_key;
    u64 conn_ptr;
} pending_h2_invocation_t;

typedef struct grpc_h2_header_observation {
    go_addr_key_t request_key;
    grpc_h2_owned_stream_key_t stream;
} grpc_h2_header_observation_t;
