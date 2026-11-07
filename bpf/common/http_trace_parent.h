// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>

#include <common/http_types.h>
#include <common/trace_helpers.h>

#include <maps/http_server_trace_index.h>
#include <maps/ongoing_http.h>
#include <maps/ongoing_http2_grpc.h>
#include <maps/ongoing_http2_connections.h>
#include <maps/tp_info_mem.h>

static __always_inline http_server_trace_key_t
http_server_trace_key(u32 pid, const unsigned char *trace_id) {
    http_server_trace_key_t key = {.pid = pid};
    __builtin_memcpy(key.trace_id, trace_id, sizeof(key.trace_id));

    return key;
}

// Server spans get a fresh ID per request, so the span alone identifies it.
static __always_inline bool indexes_request(const http_server_trace_ref_t *ref,
                                            const unsigned char *span_id) {
    return bpf_memcmp(ref->span_id, span_id, sizeof(ref->span_id)) == 0;
}

// The server request an index entry points at, while it can still parent children.
static __always_inline const tp_info_t *indexed_server_tp(const http_server_trace_ref_t *ref) {
    const tp_info_t *tp = NULL;

    if (ref->stream.stream_id) {
        const http2_grpc_request_t *server = bpf_map_lookup_elem(&ongoing_http2_grpc, &ref->stream);
        const http2_conn_info_data_t *conn =
            bpf_map_lookup_elem(&ongoing_http2_connections, &ref->stream.pid_conn);

        if (!server || !conn || server->new_conn_id != conn->id ||
            server->type != k_event_type_http_request || server->end_monotime_ns ||
            !server->start_monotime_ns) {
            return NULL;
        }
        tp = &server->tp;
    } else {
        const http_info_t *server = bpf_map_lookup_elem(&ongoing_http, &ref->stream.pid_conn);
        if (!server || server->type != k_event_type_http_request || server->submitted ||
            !still_reading(server)) {
            return NULL;
        }
        tp = &server->tp;
    }

    // The connection or stream may already carry a newer request.
    if (!indexes_request(ref, tp->span_id)) {
        return NULL;
    }

    return tp;
}

static __always_inline void index_http_server_context(const http2_conn_stream_t *stream,
                                                      const tp_info_t *tp) {
    if (!valid_trace(tp->trace_id) || !valid_span(tp->span_id)) {
        return;
    }

    const http_server_trace_key_t key = http_server_trace_key(stream->pid_conn.pid, tp->trace_id);
    http_server_trace_ref_t ref = {.stream = *stream};
    __builtin_memcpy(ref.span_id, tp->span_id, sizeof(ref.span_id));

    if (bpf_map_update_elem(&http_server_trace_index, &key, &ref, BPF_NOEXIST) == 0) {
        return;
    }

    http_server_trace_ref_t *existing = bpf_map_lookup_elem(&http_server_trace_index, &key);
    if (!existing || indexes_request(existing, tp->span_id)) {
        return;
    }

    // An entry left by a finished request, such as an earlier call in the same trace
    if (!existing->ambiguous && !indexed_server_tp(existing)) {
        bpf_map_update_elem(&http_server_trace_index, &key, &ref, BPF_ANY);
        return;
    }

    // Concurrent requests in one trace. Don't choose a stream just because it arrived last.
    // The entry tracks only one of them, so it can't tell when the others end: it stays
    // ambiguous until the LRU evicts it.
    existing->ambiguous = 1;
}

static __always_inline void
unindex_http_server_trace_id(u32 pid, const unsigned char *trace_id, const unsigned char *span_id) {
    const http_server_trace_key_t key = http_server_trace_key(pid, trace_id);

    const http_server_trace_ref_t *ref = bpf_map_lookup_elem(&http_server_trace_index, &key);
    if (ref && !ref->ambiguous && indexes_request(ref, span_id)) {
        bpf_map_delete_elem(&http_server_trace_index, &key);
    }
}

static __always_inline void unindex_http_server_trace(u32 pid, const tp_info_t *tp) {
    unindex_http_server_trace_id(pid, tp->trace_id, tp->span_id);
}

static __always_inline void index_http_server_trace(const pid_connection_info_t *pid_conn,
                                                    const http_info_t *info) {
    if (info->type != k_event_type_http_request) {
        return;
    }

    const http2_conn_stream_t stream = {.pid_conn = *pid_conn};
    index_http_server_context(&stream, &info->tp);
}

// Concurrent requests in one trace are ambiguous here and left to the thread lookups.
static __always_inline tp_info_pid_t *find_http_server_trace(u32 pid, const tp_info_t *wire_tp) {
    const http_server_trace_key_t key = http_server_trace_key(pid, wire_tp->trace_id);

    const http_server_trace_ref_t *ref = bpf_map_lookup_elem(&http_server_trace_index, &key);
    if (!ref || ref->ambiguous) {
        return NULL;
    }

    const tp_info_t *server_tp = indexed_server_tp(ref);
    if (!server_tp ||
        bpf_memcmp(server_tp->trace_id, wire_tp->trace_id, TRACE_ID_SIZE_BYTES) != 0) {
        return NULL;
    }

    tp_info_pid_t *parent = tp_info_backup_mem();
    if (!parent) {
        return NULL;
    }

    parent->tp = *server_tp;
    parent->pid = pid;
    parent->valid = 1;
    parent->written = 0;
    parent->req_type = k_event_type_http_request;
    parent->response_sent = 0;

    return parent;
}
