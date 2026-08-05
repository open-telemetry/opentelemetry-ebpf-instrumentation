// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/common.h>
#include <common/egress_key.h>
#include <common/tp_info.h>

#define MAX_W_PTR_N 1024

static const char traceparent[] = "traceparent: ";

typedef struct http_client_data {
    s64 content_length;
    pid_info pid;
    unsigned char path[k_path_max_len];
    unsigned char host[k_host_max_len];
    unsigned char scheme[k_scheme_max_len];
    unsigned char method[k_method_max_len];
    u8 _pad[3];
} http_client_data_t;

typedef struct http1_header_request_key {
    u64 process_start_time;
    u64 header_addr;
    u64 persist_conn_addr;
    u32 pid;
    u32 _pad;
} http1_header_request_key_t;

typedef struct server_http_func_invocation {
    u64 start_monotime_ns;
    u64 generation;
    u64 content_length;
    u64 response_length;
    u64 status;
    u64 rpc_request_addr; // pointer to the jsonrpc Request
    tp_info_t tp;
    u8 method[k_method_max_len];
    u8 path[k_path_max_len];
    u8 pattern[k_pattern_max_len];
    u8 is_tls;
    bool is_jsonrpc;
    u8 header_traceparent_state;
    u8 header_source;
    u8 _pad[1];
} server_http_func_invocation_t;

typedef struct http1_server_handoff {
    tp_info_t tp;
    u64 generation;
    u8 traceparent_state;
    u8 parsing;
    u8 traceparent_observed;
    u8 headers_observed;
    u8 headers_complete;
    u8 observation_failed;
    u8 is_tls;
    u8 _pad[1];
} http1_server_handoff_t;

typedef struct http2_server_stream_key {
    u64 pid;
    u64 generation;
    u64 server_conn;
    u32 stream_id;
    u32 _pad;
} http2_server_stream_key_t;

typedef struct http2_server_request_state {
    tp_info_t tp;
    u8 traceparent_state;
    u8 _pad[7];
} http2_server_request_state_t;

typedef struct http2_process_headers_invocation {
    http2_server_stream_key_t stream;
    http2_server_request_state_t request;
    u8 candidate_initial;
    u8 _pad[7];
} http2_process_headers_invocation_t;

typedef struct server_http_invocation_scratch {
    server_http_func_invocation_t invocation;
    tp_info_t parent;
} server_http_invocation_scratch_t;

typedef struct framer_func_invocation {
    u64 framer_ptr;
    tp_info_t tp;
    outgoing_trace_token_t handoff_token;
    egress_key_t egress;
    u32 _egress_pad;
    s64 initial_n;
    u8 handoff_expected;
    u8 _pad[7];
} framer_func_invocation_t;
