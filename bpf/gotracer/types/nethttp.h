// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/common.h>
#include <common/go_addr_key.h>
#include <common/go_h2_stream_state.h>
#include <common/tp_info.h>

#define MAX_W_PTR_N 65535

static const char traceparent[] = "traceparent: ";

typedef struct http_client_data {
    s64 content_length;
    pid_info pid;
    unsigned char path[k_path_max_len];
    unsigned char raw_query[k_query_max_len];
    unsigned char host[k_host_max_len];
    unsigned char scheme[k_scheme_max_len];
    unsigned char method[k_method_max_len];
    u8 _pad[7];
} http_client_data_t;

typedef struct server_http_func_invocation {
    u64 start_monotime_ns;
    u64 content_length;
    u64 response_length;
    u64 status;
    u64 rpc_request_addr; // pointer to the jsonrpc Request
    tp_info_t tp;
    u8 method[k_method_max_len];
    u8 path[k_path_max_len];
    u8 raw_query[k_query_max_len];
    u8 pattern[k_pattern_max_len];
    u8 is_tls;
    bool is_jsonrpc;
    u8 _pad[7];
} server_http_func_invocation_t;

typedef struct framer_func_invocation {
    u64 framer_ptr;
    u64 writer_pos;
    s64 initial_n;
    go_h2_stream_key_t stream;
    u8 frame_type;
    bool reserved_padding;
    u8 _pad[2];
} framer_func_invocation_t;

typedef struct http2_writer_stream {
    u64 framer_ptr;
    go_h2_stream_key_t stream;
    u8 _pad[4];
} http2_writer_stream_t;

typedef struct http2_header_context {
    tp_info_t tp;
    go_addr_key_t request_key;
    u64 started_ns;
    bool observed;
    bool app_traceparent;
    bool read_failed;
    u8 _pad[5];
} http2_header_context_t;
