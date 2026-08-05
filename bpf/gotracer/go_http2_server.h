// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/go_addr_key.h>

#include <gotracer/go_common.h>
#include <gotracer/go_http1_server.h>
#include <gotracer/types/nethttp.h>

#include <pid/pid_helpers.h>

/*
 * These offsets are an internal net/http2 ABI shared by the supported
 * vendored net/http (Go 1.17+) and golang.org/x/net/http2 (v0.12+):
 *
 *   MetaHeadersFrame +0 -> *HeadersFrame
 *   MetaHeadersFrame +32 -> bool Truncated (after pointer + Fields slice)
 *   HeadersFrame +0     -> embedded FrameHeader
 *   FrameHeader +8      -> uint32 StreamID
 *   responseWriter +0   -> *responseWriterState
 *   responseWriterState +0 -> *stream
 *   stream +8           -> uint32 id (after the leading *serverConn)
 *
 * Keeping the reads in one helper makes failures explicit and fail-closed.
 */
enum {
    k_go_http2_embedded_pointer_offset = 0,
    k_go_http2_stream_id_offset = 8,
    k_go_http2_meta_headers_truncated_offset = 32,
};

static __always_inline u8 go_http2_meta_headers_stream_id(const void *frame, u32 *stream_id) {
    if (!frame || !stream_id) {
        return 0;
    }
    void *headers = NULL;
    if (bpf_probe_read(&headers, sizeof(headers), frame + k_go_http2_embedded_pointer_offset) ||
        !headers ||
        bpf_probe_read(stream_id, sizeof(*stream_id), headers + k_go_http2_stream_id_offset)) {
        return 0;
    }
    return *stream_id != 0;
}

static __always_inline u8 go_http2_stream_id_for_server(const void *stream,
                                                        const void *server_conn,
                                                        u32 *stream_id) {
    if (!stream || !server_conn || !stream_id) {
        return 0;
    }
    void *stream_server_conn = NULL;
    if (bpf_probe_read(&stream_server_conn,
                       sizeof(stream_server_conn),
                       stream + k_go_http2_embedded_pointer_offset) ||
        stream_server_conn != server_conn ||
        bpf_probe_read(stream_id, sizeof(*stream_id), stream + k_go_http2_stream_id_offset)) {
        return 0;
    }
    return *stream_id != 0;
}

static __always_inline u8 go_http2_handler_stream_id(const void *rw,
                                                     const void *server_conn,
                                                     u32 *stream_id) {
    if (!rw || !server_conn || !stream_id) {
        return 0;
    }
    void *rws = NULL;
    void *stream = NULL;
    if (bpf_probe_read(&rws, sizeof(rws), rw + k_go_http2_embedded_pointer_offset) || !rws ||
        bpf_probe_read(&stream, sizeof(stream), rws + k_go_http2_embedded_pointer_offset) ||
        !stream) {
        return 0;
    }
    return go_http2_stream_id_for_server(stream, server_conn, stream_id);
}

static __always_inline u8 go_http2_server_stream_key(http2_server_stream_key_t *key,
                                                     const void *server_conn,
                                                     u32 stream_id) {
    if (!key || !server_conn || !stream_id) {
        return 0;
    }
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const u32 pid = pid_from_pid_tgid(pid_tgid);
    const u64 generation = go_process_generation(pid);
    if (!generation) {
        return 0;
    }
    __builtin_memset(key, 0, sizeof(*key));
    key->pid = pid;
    key->generation = generation;
    key->server_conn = (u64)server_conn;
    key->stream_id = stream_id;
    return 1;
}

static __always_inline u8 go_http2_initial_header_candidate(u32 stream_id,
                                                            u32 max_client_stream_id) {
    return stream_id && (stream_id & 1) && stream_id > max_client_stream_id;
}

static __always_inline u8 go_http2_process_headers_key(go_exact_process_addr_key_t *key,
                                                       const void *goroutine_addr) {
    return goroutine_addr && go_exact_process_addr_key_from_id(key, (void *)goroutine_addr);
}

static __always_inline u8
go_http2_process_headers_key_valid(const go_exact_process_addr_key_t *key) {
    return key && key->address.pid && key->address.addr && key->process_start_time;
}

static __always_inline void
go_http2_clear_process_headers_invocation(void *invocation_map,
                                          const go_exact_process_addr_key_t *key) {
    if (go_http2_process_headers_key_valid(key)) {
        bpf_map_delete_elem(invocation_map, key);
    }
}

static __always_inline u8
go_http2_stage_process_headers_invocation(void *invocation_map,
                                          const go_exact_process_addr_key_t *key,
                                          const http2_process_headers_invocation_t *invocation) {
    return go_http2_process_headers_key_valid(key) && invocation &&
           bpf_map_update_elem(invocation_map, key, invocation, BPF_ANY) == 0;
}

static __always_inline http2_process_headers_invocation_t *
go_http2_lookup_process_headers_invocation(void *invocation_map,
                                           const go_exact_process_addr_key_t *key) {
    if (!go_http2_process_headers_key_valid(key)) {
        return NULL;
    }
    return bpf_map_lookup_elem(invocation_map, key);
}

static __always_inline u8
go_http2_normalize_server_traceparent(tp_info_t *tp, enum go_http1_traceparent_scan_result *state) {
    if (!tp || !state || *state != k_go_http1_traceparent_scan_found ||
        !valid_trace(tp->trace_id) || !valid_span(tp->parent_id)) {
        if (tp) {
            __builtin_memset(tp, 0, sizeof(*tp));
        }
        if (state && *state == k_go_http1_traceparent_scan_found) {
            *state = k_go_http1_traceparent_scan_present;
        }
        return 0;
    }

    __builtin_memcpy(tp->span_id, tp->parent_id, SPAN_ID_SIZE_BYTES);
    tp->parent_remote = 1;
    return 1;
}

static __always_inline enum go_http1_traceparent_scan_result
go_http2_process_meta_frame_headers(void *frame, tp_info_t *tp) {
    if (!tp) {
        return k_go_http1_traceparent_scan_unknown;
    }
    __builtin_memset(tp, 0, sizeof(*tp));
    u8 truncated = 0;
    if (!frame ||
        bpf_probe_read(
            &truncated, sizeof(truncated), frame + k_go_http2_meta_headers_truncated_offset) ||
        truncated) {
        return k_go_http1_traceparent_scan_unknown;
    }
    enum go_http1_traceparent_scan_result state =
        (enum go_http1_traceparent_scan_result)process_meta_frame_headers_classified(frame, tp);
    go_http2_normalize_server_traceparent(tp, &state);
    return state;
}

static __always_inline void
go_http2_prepare_h2_sentinel(server_http_func_invocation_t *invocation,
                             const http2_server_request_state_t *request,
                             u8 is_tls,
                             u64 generation) {
    if (!invocation) {
        return;
    }
    __builtin_memset(invocation, 0, sizeof(*invocation));
    invocation->generation = generation;
    invocation->header_source = k_go_http_server_header_source_http2;
    invocation->header_traceparent_state =
        request ? request->traceparent_state : k_go_http1_traceparent_scan_unknown;
    invocation->is_tls = is_tls;
    if (request && request->traceparent_state == k_go_http1_traceparent_scan_found &&
        valid_trace(request->tp.trace_id) && valid_span(request->tp.span_id)) {
        invocation->tp = request->tp;
    } else if (invocation->header_traceparent_state == k_go_http1_traceparent_scan_found) {
        invocation->header_traceparent_state = k_go_http1_traceparent_scan_present;
    }
}

static __always_inline u8
go_http2_begin_request_state(void *request_map,
                             const http2_server_stream_key_t *key,
                             const http2_server_request_state_t *request) {
    if (!key || !key->pid || !key->generation || !key->server_conn || !key->stream_id) {
        return 0;
    }
    if (!request) {
        return 0;
    }
    return bpf_map_update_elem(request_map, key, request, BPF_NOEXIST) == 0;
}

static __always_inline void go_http2_finish_request_state(void *request_map,
                                                          const http2_server_stream_key_t *key,
                                                          u8 accepted) {
    // Entry publishes before processHeaders can schedule runHandler. A real
    // runHandler therefore proves acceptance and may consume that provisional
    // state immediately. Successful returns must never republish: doing so
    // would race a handler that already consumed the entry. Rejected returns
    // cannot have a handler and revoke the provisional state.
    if (!accepted && key) {
        bpf_map_delete_elem(request_map, key);
    }
}

static __always_inline u8 go_http2_consume_request_state(void *request_map,
                                                         const http2_server_stream_key_t *key,
                                                         server_http_func_invocation_t *sentinel,
                                                         u8 is_tls) {
    const u64 generation = key ? go_process_generation(key->pid) : 0;
    go_http2_prepare_h2_sentinel(sentinel, NULL, is_tls, generation);
    if (!key || !key->pid || !key->generation || !key->server_conn || !key->stream_id ||
        !process_incarnation_matches(key->generation, generation)) {
        return 0;
    }

    const http2_server_request_state_t *request = bpf_map_lookup_elem(request_map, key);
    if (!request) {
        return 0;
    }
    go_http2_prepare_h2_sentinel(sentinel, request, is_tls, generation);
    bpf_map_delete_elem(request_map, key);
    return 1;
}

static __always_inline void
go_http2_cleanup_handler_state(void *handoff_map,
                               void *invocation_map,
                               void *reader_map,
                               void *connection_map,
                               const go_addr_key_t *key,
                               server_http_invocation_scratch_t *scratch) {
    if (!key) {
        return;
    }
    if (scratch) {
        __builtin_memset(&scratch->parent, 0, sizeof(scratch->parent));
    }
    const server_http_func_invocation_t *invocation =
        go_http_server_invocation_lookup_current(invocation_map, key);
    if (invocation && scratch) {
        scratch->parent = invocation->tp;
        if (valid_trace(scratch->parent.trace_id) && valid_span(scratch->parent.span_id)) {
            pop_go_trace(key, &scratch->parent);
        }
    }
    go_http_server_close_prehandler_state(handoff_map, invocation_map, key);
    bpf_map_delete_elem(reader_map, key);
    bpf_map_delete_elem(connection_map, key);
    poison_and_revoke_go_trace(key);
}
