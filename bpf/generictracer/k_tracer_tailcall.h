// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/http_types.h>
#include <common/scratch_mem.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 16);
} jump_table SEC(".maps");

enum {
    k_tail_protocol_http = 0,
    k_tail_continue_protocol_http = 1,
    k_tail_continue2_protocol_http = 2,
    k_tail_protocol_http2 = 3,
    k_tail_protocol_tcp = 4,
    k_tail_protocol_http2_grpc_frames = 5,
    k_tail_protocol_http2_grpc_handle_start_frame = 6,
    k_tail_protocol_http2_grpc_handle_end_frame = 7,
    k_tail_handle_buf_with_args = 8,
};

// Separate PROG_ARRAY for socket filter tail calls (program types must match).
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 4);
} socket_jump_table SEC(".maps");

enum {
    k_tail_socket_dns = 0,
};

// Per-CPU scratch for passing parsed packet info across socket filter tail calls.
typedef struct socket_filter_ctx {
    connection_info_t conn;
    protocol_info_t tcp;
} socket_filter_ctx_t;

SCRATCH_MEM_TYPED(socket_filter_ctx, socket_filter_ctx_t);
