// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>
#include <common/tp_info.h>

enum go_h2_protocol : u8 {
    k_go_h2_protocol_http = 1,
    k_go_h2_protocol_grpc = 2,
};

enum go_h2_stream_state : u8 {
    k_go_h2_state_unknown = 0,
    k_go_h2_state_app = 1,
    k_go_h2_state_obi_pending = 2,
    k_go_h2_state_obi_written = 3,
    k_go_h2_state_skip = 4,
    k_go_h2_state_observing = 5,
};

enum go_h2_audit_event : u8 {
    k_go_h2_audit_observed = 1,
    k_go_h2_audit_published = 2,
    k_go_h2_audit_direct_commit = 3,
    k_go_h2_audit_socket_commit = 4,
    k_go_h2_audit_cleanup = 5,
    k_go_h2_audit_rollback = 6,
    k_go_h2_audit_missing = 7,
    k_go_h2_audit_encode_hit = 8,
    k_go_h2_audit_prewrite_commit = 9,
    k_go_h2_audit_socket_continuation_commit = 10,
};

typedef struct go_h2_stream_key {
    pid_connection_info_t p_conn;
    u32 process_start_lo;
    u32 process_start_hi;
    u32 stream_id;
} go_h2_stream_key_t;

typedef struct go_h2_conn_key {
    pid_connection_info_t p_conn;
    u32 process_start_lo;
    u32 process_start_hi;
} go_h2_conn_key_t;

typedef struct go_h2_stream_value {
    tp_info_t tp;
    u64 updated_ns;
    u8 state;
    u8 protocol;
    u8 _pad[6];
} go_h2_stream_value_t;

typedef struct go_h2_conn_value {
    u64 updated_ns;
    u8 protocol;
    u8 _pad[7];
} go_h2_conn_value_t;

typedef struct go_h2_audit_key {
    go_h2_stream_key_t stream;
    u8 protocol;
    u8 event;
    u8 _pad[2];
} go_h2_audit_key_t;

typedef struct go_h2_audit_value {
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    u64 updated_ns;
    u32 count;
    u8 state;
    u8 _pad[3];
} go_h2_audit_value_t;

enum {
    k_go_h2_state_fresh_ns = 30ULL * 1000 * 1000 * 1000,
};

static __always_inline bool go_h2_timestamp_is_fresh(u64 updated_ns, u64 now) {
    return updated_ns && now >= updated_ns && now - updated_ns <= k_go_h2_state_fresh_ns;
}

static __always_inline bool go_h2_state_suppresses_injection(u8 state) {
    return state == k_go_h2_state_app || state == k_go_h2_state_obi_written ||
           state == k_go_h2_state_skip || state == k_go_h2_state_observing;
}

static __always_inline bool go_h2_state_can_inject(u8 state) {
    return state == k_go_h2_state_obi_pending;
}

static __always_inline void go_h2_restore_client_direction(go_h2_stream_key_t *stream,
                                                           u16 original_destination_port) {
    fixup_connection_info(&stream->p_conn.conn, true, original_destination_port);
}
