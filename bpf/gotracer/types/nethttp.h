// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/common.h>
#include <common/tp_info.h>

#define MAX_W_PTR_N 1024

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
    tp_info_t tp;
    s64 initial_n;
    u32 stream_id;
    u16 s_port;
    u16 d_port;
} framer_func_invocation_t;
