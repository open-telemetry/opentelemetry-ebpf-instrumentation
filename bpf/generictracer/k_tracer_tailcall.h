// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 23);
} jump_table SEC(".maps");

enum {
    // HTTP/1
    k_tail_protocol_http = 0,
    k_tail_continue_protocol_http = 1,
    k_tail_continue2_protocol_http = 2,
    k_tail_continue_protocol_http_tp = 3,
    // TCP
    k_tail_protocol_tcp = 4,
    // Generic
    k_tail_handle_buf_with_args = 5,
    k_tail_continue_netfd_read = 6,
    // HTTP/2 + gRPC
    k_tail_protocol_http2 = 7,
    k_tail_protocol_http2_grpc_frames = 8,
    k_tail_protocol_http2_grpc_handle_start_frame = 9,
    k_tail_protocol_http2_grpc_handle_end_frame = 10,
    k_tail_protocol_http2_grpc_handle_start_frame_server = 11,
    k_tail_protocol_http2_unused = 12,
    // Large buffer multi-batch emission
    k_tail_large_buf_emit_continue = 13,
    k_tail_protocol_http2_grpc_handle_start_frame_server_commit = 14,
    // Go SDK span start attributes
    k_tail_go_span_start_attributes = 15,
    k_tail_go_span_start_apply_attributes = 16,
    k_tail_go_span_start_route = 17,
    k_tail_go_span_set_attributes = 18,
    // Each tracer installs this slot in its own jump_table instance.
    k_tail_protocol_http2_grpc_validate_server_traceparent = 19,
    k_tail_handle_http_continuation = 20,
    k_tail_protocol_http2_grpc_finish_client = 21,
    k_tail_protocol_http2_grpc_parse_server_headers = 22,
};
