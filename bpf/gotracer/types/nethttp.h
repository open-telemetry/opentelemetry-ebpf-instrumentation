// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/common.h>
#include <common/tp_info.h>

#include <gotracer/types/stream_key.h>

#define HTTP2_ENCODED_HEADER_LEN                                                                   \
    66 // 1 + 1 + 8 + 1 + 55 = type byte + hpack_len_as_byte("traceparent") + strlen(hpack("traceparent")) + len_as_byte(55) + generated traceparent id

#define MAX_W_PTR_N 1024

static const char traceparent[] = "traceparent: ";

typedef struct http_client_data {
    s64 content_length;
    pid_info pid;
    unsigned char path[PATH_MAX_LEN];
    unsigned char host[HOST_MAX_LEN];
    unsigned char scheme[SCHEME_MAX_LEN];
    unsigned char method[METHOD_MAX_LEN];
    u8 _pad[3];
} http_client_data_t;

typedef struct server_http_func_invocation {
    u64 start_monotime_ns;
    u64 content_length;
    u64 response_length;
    u64 status;
    u64 rpc_request_addr; // pointer to the jsonrpc Request
    tp_info_t tp;
    u8 method[METHOD_MAX_LEN];
    u8 path[PATH_MAX_LEN];
    u8 pattern[PATTERN_MAX_LEN];
    u8 _pad[5];
} server_http_func_invocation_t;

typedef struct framer_func_invocation {
    u64 framer_ptr;
    tp_info_t tp;
    s64 initial_n;
} framer_func_invocation_t;
