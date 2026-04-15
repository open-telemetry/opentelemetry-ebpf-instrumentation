// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

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
    k_tail_continue_protocol_http_tp = 9,
};
