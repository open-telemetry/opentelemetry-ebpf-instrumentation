// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/http_buf_size.h>
#include <common/http_info.h>
#include <common/lw_thread.h>
#include <common/tp_info.h>

#define MIN_HTTP_SIZE 12      // HTTP/1.1 CCC is the smallest valid request we can have
#define MIN_HTTP_REQ_SIZE 9   // OPTIONS / is the largest
#define RESPONSE_STATUS_POS 9 // HTTP/1.1 <--
#define MAX_HTTP_STATUS 599

// 100K and above we try to track the response actual time with kretprobes
#define KPROBES_LARGE_RESPONSE_LEN 100000

#define CONN_INFO_FLAG_TRACE 0x1

#define FLAGS_SIZE_BYTES 1
#define TRACE_ID_CHAR_LEN 32
#define SPAN_ID_CHAR_LEN 16
#define FLAGS_CHAR_LEN 2
#define TP_MAX_VAL_LENGTH 55
#define TP_MAX_KEY_LENGTH 11

// Preface PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n https://datatracker.ietf.org/doc/html/rfc7540#section-3.5
#define MIN_HTTP2_SIZE 24

typedef struct protocol_selector {
    u8 http : 1;
    u8 http2 : 1;
    u8 tcp : 1;
    u8 _pad : 5;
} protocol_selector_t;

#define k_protocol_selector_all ((protocol_selector_t){.http = 1, .http2 = 1, .tcp = 1})

typedef struct call_protocol_args {
    pid_connection_info_t pid_conn;
    enum protocol_type protocol_type;
    u8 ssl;
    u8 direction;
    u8 packet_type;
    unsigned char small_buf[MIN_HTTP2_SIZE];
    protocol_selector_t protocols;
    u8 pad[3];
    int bytes_len;
    u16 orig_dport;
    u16 _pad2;
    u64 u_buf;
    u64 self_ref_parent_id;
    lw_thread_t lw_thread;
} call_protocol_args_t;

// Here we keep information on the packets passing through the socket filter
typedef struct protocol_info {
    u32 hdr_len;
    u32 seq;
    u32 ack;
    u16 h_proto;
    u16 tot_len;
    u8 opts_off;
    u8 flags;
    u8 ip_len;
    u8 l4_proto;
} protocol_info_t;

// Here we keep information on the ongoing filtered connections, PID/TID and connection type
typedef struct http_connection_metadata {
    pid_info pid;
    u8 type;
    u8 _pad[3];
} http_connection_metadata_t;

typedef struct http2_conn_stream {
    pid_connection_info_t pid_conn;
    u32 stream_id;
} http2_conn_stream_t;

typedef struct http2_grpc_request {
    u8 flags; // Must be first
    u8 ssl;
    u8 type;
    u8 _pad0[1];
    connection_info_t conn_info;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    unsigned char data[k_kprobes_http2_buf_size];
    unsigned char ret_data[k_kprobes_http2_ret_buf_size];
    int len;
    // we need this to filter traces from unsolicited processes that share the executable
    // with other instrumented processes
    pid_info pid;
    u64 new_conn_id;
    tp_info_t tp;
} http2_grpc_request_t;

// Force emitting struct http_info_t and http2_grpc_request_t into the ELF for automatic creation of Golang struct
const http_info_t *unused __attribute__((unused));
const http2_grpc_request_t *unused_http2 __attribute__((unused));

// Checks whether the request target after the method+space is valid.
// Accepts origin-form (/...), absolute-form (http:// or https://).
// The usage of '|' is intended to minimise the size of jitted code affecting
// older kernel versions - it replaces branching with bitwise operations whose
// result are equivalent in this particular context.
static __always_inline u8 is_http_request_target(unsigned char c) {
    return (c == '/') | (((c | 0x20) == 'h'));
}

static __always_inline u8 is_http_request_buf(const unsigned char *p) {
    unsigned char target;

    if (__builtin_memcmp(p, "GET ", 4) == 0) {
        target = p[4];
    } else if (__builtin_memcmp(p, "POST ", 5) == 0) {
        target = p[5];
    } else if (__builtin_memcmp(p, "PUT ", 4) == 0) {
        target = p[4];
    } else if (__builtin_memcmp(p, "PATCH ", 6) == 0) {
        target = p[6];
    } else if (__builtin_memcmp(p, "DELETE ", 7) == 0) {
        target = p[7];
    } else if (__builtin_memcmp(p, "HEAD ", 5) == 0) {
        target = p[5];
    } else if (__builtin_memcmp(p, "OPTIONS ", 8) == 0) {
        target = p[8];
    } else {
        return 0;
    }

    return is_http_request_target(target);
}
