// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/event_defs.h>
#include <common/http_types.h>

enum http2_client_completion_resolution : u8 {
    k_http2_client_completion_fail_closed,
    k_http2_client_completion_normal,
    k_http2_client_completion_exact,
};

enum {
    k_http2_client_lifecycle_map_type = BPF_MAP_TYPE_LRU_HASH,
};

typedef struct http2_client_lifecycle_key {
    http2_conn_stream_t stream;
    u32 _pad;
    u64 start_monotime_ns;
} http2_client_lifecycle_key_t;

typedef struct http2_client_trace_upgrade {
    tp_info_pid_t publication;
    outgoing_trace_token_t token;
} http2_client_trace_upgrade_t;

typedef struct http2_client_terminal {
    u64 end_monotime_ns;
    unsigned char ret_data[k_kprobes_http2_ret_buf_size];
} http2_client_terminal_t;

typedef struct http2_client_lifecycle_scratch {
    http2_client_trace_upgrade_t upgrade;
    http2_client_terminal_t terminal;
    http2_client_lifecycle_key_t lifecycle_key;
    outgoing_trace_token_t located_token;
    tp_info_pid_t cleanup_publication;
    egress_key_t egress;
    u32 _pad;
} http2_client_lifecycle_scratch_t;

static __always_inline u8 http2_uses_client_publication_lane(u8 request_type) {
    return request_type == EVENT_HTTP_CLIENT;
}

static __always_inline http2_client_lifecycle_key_t
http2_client_lifecycle_key(const http2_conn_stream_t *stream, u64 start_monotime_ns) {
    http2_client_lifecycle_key_t key = {
        .start_monotime_ns = start_monotime_ns,
    };
    if (stream) {
        key.stream = *stream;
    }
    return key;
}

static __always_inline enum http2_client_completion_resolution
http2_client_completion_resolution(u8 has_exact_upgrade, u8 exact_locator_present) {
    if (has_exact_upgrade) {
        return k_http2_client_completion_exact;
    }
    if (exact_locator_present) {
        return k_http2_client_completion_fail_closed;
    }
    return k_http2_client_completion_normal;
}
