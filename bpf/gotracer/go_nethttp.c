// Copyright The OpenTelemetry Authors
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/utils.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_builtins.h>

#include <common/algorithm.h>
#include <common/connection_info.h>
#include <common/globals.h>
#include <common/go_grpc_client_conn.h>
#include <common/http_types.h>
#include <common/outgoing_trace_handoff.h>
#include <common/protocol_defs.h>
#include <common/ringbuf.h>
#include <common/strings.h>
#include <common/tracing.h>
#include <common/trace_helpers.h>

#include <gotracer/go_common.h>
#include <gotracer/go_http1.h>
#include <gotracer/go_http1_client.h>
#include <gotracer/go_large_buffer.h>
#include <gotracer/go_offsets.h>
#include <gotracer/go_str.h>

#include <gotracer/maps/nethttp.h>
#include <gotracer/maps/hpack.h>

#include <gotracer/types/nethttp.h>
#include <gotracer/types/stream_key.h>

#include <logger/bpf_dbg.h>

#include <maps/go_ongoing_http.h>
#include <maps/go_ongoing_http_client_requests.h>
#include <maps/outgoing_trace_map.h>
#include <maps/tp_char_buf_mem.h>

#include <pid/pid_helpers.h>

#include <shared/obi_ctx.h>

#include <gotracer/go_http1_server.h>
#include <gotracer/go_http2_server.h>

static __always_inline unsigned char *temp_header_mem() {
    const u32 zero = 0;
    return bpf_map_lookup_elem(&temp_header_mem_store, &zero);
}

/* HTTP Server */

// This instrumentation attaches uprobe to the following function:
// func (mux *ServeMux) ServeHTTP(w ResponseWriter, r *Request)
// or other functions sharing the same signature (e.g http.Handler.ServeHTTP)
SEC("uprobe/ServeHTTP")
int obi_uprobe_ServeHTTP(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/ServeHTTP ===");
    void *goroutine_addr = GOROUTINE_PTR(ctx);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);
    const u64 generation = go_process_generation(g_key.pid);

    server_http_invocation_scratch_t *scratch = http_server_invocation_scratch_mem();
    if (!scratch) {
        go_http_server_close_prehandler_state(
            &http1_server_handoffs, &ongoing_http_server_requests, &g_key);
        go_http_server_retire_go_trace(&g_key);
        discard_server_parent_candidates(&g_key);
        obi_ctx__del(bpf_get_current_pid_tgid());
        return 0;
    }
    __builtin_memset(scratch, 0, sizeof(*scratch));
    server_http_func_invocation_t *invocation = &scratch->invocation;
    invocation->generation = generation;
    tp_info_t *authority_parent = &scratch->parent;

    http1_server_handoff_t *http1 =
        go_http1_server_handoff_lookup_current(&http1_server_handoffs, &g_key);
    server_http_func_invocation_t *pending_h2 =
        go_http_server_invocation_lookup_current(&ongoing_http_server_requests, &g_key);
    const enum go_http_server_parent_authority authority =
        go_http_server_parent_authority(http1, pending_h2, generation);
    if (http1) {
        invocation->is_tls = http1->is_tls;
        if (authority == k_go_http_server_parent_traceparent) {
            *authority_parent = http1->tp;
        }
    } else if (go_http1_pending_h2_sentinel(pending_h2, generation)) {
        invocation->is_tls = pending_h2->is_tls;
        if (authority == k_go_http_server_parent_traceparent) {
            *authority_parent = pending_h2->tp;
        }
    }

    // Consume pre-handler state before application code can parse trailers or multipart headers.
    go_http_server_close_prehandler_state(
        &http1_server_handoffs, &ongoing_http_server_requests, &g_key);
    go_http_server_retire_go_trace(&g_key);
    obi_ctx__del(bpf_get_current_pid_tgid());

    void *req = GO_PARAM4(ctx);
    off_table_t *ot = get_offsets_table();
    u8 trace_started = 0;
    invocation->start_monotime_ns = bpf_ktime_get_ns();

    invocation->method[0] = 0;
    invocation->path[0] = 0;
    invocation->pattern[0] = 0;

    if (req) {
        tp_info_t *decoded_tp =
            authority == k_go_http_server_parent_traceparent ? authority_parent : NULL;
        server_trace_parent(goroutine_addr,
                            &invocation->tp,
                            decoded_tp,
                            authority == k_go_http_server_parent_force_root);
        trace_started = 1;

        // Get method from Request.Method
        if (!read_go_str("method",
                         req,
                         go_offset_of(ot, (go_offset){.v = _method_ptr_pos}),
                         invocation->method,
                         sizeof(invocation->method))) {
            goto failed;
        }

        // Get path from Request.URL
        void *url_ptr = 0;
        int res = bpf_probe_read(&url_ptr,
                                 sizeof(url_ptr),
                                 (void *)(req + go_offset_of(ot, (go_offset){.v = _url_ptr_pos})));

        if (res || !url_ptr ||
            !read_go_str("path",
                         url_ptr,
                         go_offset_of(ot, (go_offset){.v = _path_ptr_pos}),
                         invocation->path,
                         sizeof(invocation->path))) {
            goto failed;
        }

        res = bpf_probe_read(
            &invocation->content_length,
            sizeof(invocation->content_length),
            (void *)(req + go_offset_of(ot, (go_offset){.v = _content_length_ptr_pos})));
        if (res) {
            goto failed;
        }
    } else {
        goto failed;
    }

    // Write event
    if (bpf_map_update_elem(&ongoing_http_server_requests, &g_key, invocation, BPF_ANY)) {
        go_http_server_retire_go_trace(&g_key);
        discard_server_parent_candidates(&g_key);
        obi_ctx__del(bpf_get_current_pid_tgid());
        return 0;
    }

    obi_ctx__set(bpf_get_current_pid_tgid(), &invocation->tp);
    return 0;

failed:
    bpf_map_delete_elem(&ongoing_http_server_requests, &g_key);
    if (trace_started) {
        go_http_server_retire_go_trace(&g_key);
    }
    discard_server_parent_candidates(&g_key);
    obi_ctx__del(bpf_get_current_pid_tgid());
    return 0;
}

SEC("uprobe/findHandler")
int obi_uprobe_findHandlerRet(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/findHandler ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        go_http_server_invocation_lookup_current(&ongoing_http_server_requests, &g_key);

    bpf_dbg_printk("goroutine_addr=%lx, invocation=%llx", goroutine_addr, invocation);

    if (invocation) {
        const u64 len = (u64)GO_PARAM4(ctx);
        void *ptr = GO_PARAM3(ctx);
        if (ptr) {
            bpf_dbg_printk("reading pattern information with len: %d", len);
            read_go_str_n("pattern", ptr, len, invocation->pattern, k_pattern_max_len);
        }
    }

    return 0;
}

SEC("uprobe/muxSetMatch")
int obi_uprobe_muxSetMatch(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/muxSetMatch ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        go_http_server_invocation_lookup_current(&ongoing_http_server_requests, &g_key);

    bpf_dbg_printk("goroutine_addr=%lx, invocation=%llx", goroutine_addr, invocation);

    if (invocation && !invocation->pattern[0]) {
        off_table_t *ot = get_offsets_table();

        void *path = GO_PARAM2(ctx);
        if (path) {
            bpf_dbg_printk("reading template from path: %llx", path);
            const u64 templ_off = go_offset_of(ot, (go_offset){.v = _mux_template_pos});
            read_go_str("pattern", path, templ_off, invocation->pattern, k_pattern_max_len);
            bpf_dbg_printk("pattern=%s", invocation->pattern);
        }
    }

    return 0;
}

SEC("uprobe/ginGetValue")
int obi_uprobe_ginGetValueRet(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/ginGetValue ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        go_http_server_invocation_lookup_current(&ongoing_http_server_requests, &g_key);

    off_table_t *ot = get_offsets_table();
    const u64 fullpath_off = go_offset_of(ot, (go_offset){.v = _gin_fullpath_pos});

    bpf_dbg_printk("goroutine_addr=%lx, invocation=%llx, fullpath_off=%d",
                   goroutine_addr,
                   invocation,
                   fullpath_off);

    if (fullpath_off == _gin_fullpath_off_pre_17 || fullpath_off == _gin_fullpath_off_post_17) {
        if (invocation && !invocation->pattern[0]) {
            void *handlers = GO_PARAM1(ctx);
            if (handlers) {
                // duplicated because of verifier complaints with choosing one or the other
                // registers
                if (fullpath_off == _gin_fullpath_off_pre_17) {
                    void *ptr = GO_PARAM8(ctx);
                    const u64 len = (u64)GO_PARAM9(ctx);

                    if (ptr) {
                        bpf_dbg_printk("pre gin 1.7.0 fullPath from: %llx", ptr);
                        read_go_str_n("pattern", ptr, len, invocation->pattern, k_pattern_max_len);
                        bpf_dbg_printk("pattern=%s", invocation->pattern);
                    }
                } else {
                    void *ptr = GO_PARAM6(ctx);
                    const u64 len = (u64)GO_PARAM7(ctx);

                    if (ptr) {
                        bpf_dbg_printk("post gin 1.7.0 fullPath from: %llx", ptr);
                        read_go_str_n("pattern", ptr, len, invocation->pattern, k_pattern_max_len);
                        bpf_dbg_printk("pattern=%s", invocation->pattern);
                    }
                }
            }
        }
    }

    return 0;
}

SEC("uprobe/readRequest")
int obi_uprobe_readRequestStart(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/readRequest ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    off_table_t *ot = get_offsets_table();

    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    // net/http's conn.serve handles keepalive requests serially on this goroutine.
    go_http_server_close_prehandler_state(
        &http1_server_handoffs, &ongoing_http_server_requests, &g_key);
    bpf_map_delete_elem(&ongoing_server_bufr, &g_key);
    go_http_server_retire_go_trace(&g_key);
    obi_ctx__del(bpf_get_current_pid_tgid());

    // A runtime.g address and its previous non-zero tuple may be reused. Never retain a tuple
    // across requests: rebuild it from this request's conn and current process incarnation.
    go_server_connection_clear(&g_key);
    void *c_ptr = GO_PARAM1(ctx);
    void *tls_state = 0;
    if (c_ptr && ot &&
        bpf_probe_read(&tls_state,
                       sizeof(tls_state),
                       (void *)(c_ptr + go_offset_of(ot, (go_offset){.v = _c_tls_pos}))) == 0) {
        void *conn_conn_ptr = c_ptr + k_go_iface_data_offset +
                              go_offset_of(ot, (go_offset){.v = _c_rwc_pos}); // embedded struct
        conn_conn_ptr = unwrap_tls_conn_info(conn_conn_ptr, tls_state);

        if (conn_conn_ptr) {
            void *conn_ptr = 0;
            if (bpf_probe_read(&conn_ptr,
                               sizeof(conn_ptr),
                               (void *)(conn_conn_ptr +
                                        go_offset_of(ot, (go_offset){.v = _net_conn_pos}))) == 0 &&
                conn_ptr) { // find conn
                bpf_dbg_printk("conn_ptr=%llx", conn_ptr);
                connection_info_t conn = {};
                if (get_conn_info(conn_ptr, &conn)) {
                    go_server_connection_store_current(&g_key, &conn);
                }
            }
        }
    }

    http1_server_handoff_t *fresh = http1_server_handoff_mem();
    if (!go_http1_begin_server_handoff(&http1_server_handoffs, &g_key, fresh, tls_state != NULL)) {
        bpf_dbg_printk("can't retain HTTP/1 request header authority");
        discard_server_parent_candidates(&g_key);
        obi_ctx__del(bpf_get_current_pid_tgid());
    }

    return 0;
}

SEC("uprobe/readRequest")
int obi_uprobe_readRequestReturns(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/readRequest ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    // readRequest returns (*response, error). A nil response or non-nil error means no
    // handler can consume this request state, and its newly rebuilt tuple is not reusable.
    if (!GO_PARAM1(ctx) || GO_PARAM2(ctx)) {
        go_http_server_close_prehandler_state(
            &http1_server_handoffs, &ongoing_http_server_requests, &g_key);
        bpf_map_delete_elem(&ongoing_server_bufr, &g_key);
        go_server_connection_clear(&g_key);
        go_http_server_retire_go_trace(&g_key);
        obi_ctx__del(bpf_get_current_pid_tgid());
        return 0;
    }
    go_http1_finish_server_header_parsing(&http1_server_handoffs, &g_key);

    // This code is here for keepalive support on HTTP requests. Since the connection is not
    // established everytime, we set the initial goroutine start on the new read initiation.
    const u64 generation = go_process_generation(g_key.pid);
    goroutine_metadata *g_metadata = bpf_map_lookup_elem(&ongoing_goroutines, &g_key);
    if (!g_metadata || !generation || g_metadata->generation != generation) {
        goroutine_metadata metadata = {
            .timestamp = bpf_ktime_get_ns(),
            .parent = g_key,
            .generation = generation,
        };

        if (bpf_map_update_elem(&ongoing_goroutines, &g_key, &metadata, BPF_ANY)) {
            bpf_dbg_printk("can't update active goroutine");
        }
    } else {
        g_metadata->timestamp = bpf_ktime_get_ns();
    }

    return 0;
}

static __always_inline int go_http2_server_process_headers(struct pt_regs *ctx,
                                                           go_offset_const max_stream_id_offset) {
    void *sc_ptr = GO_PARAM1(ctx);
    void *frame = GO_PARAM2(ctx);
    bpf_dbg_printk("=== uprobe/http2Server_processHeaders sc_ptr=%lx ===", sc_ptr);
    go_exact_process_addr_key_t g_key = {};
    if (!go_http2_process_headers_key(&g_key, GOROUTINE_PTR(ctx))) {
        return 0;
    }
    go_http2_clear_process_headers_invocation(&http2_process_headers_invocations, &g_key);

    http2_process_headers_invocation_t *invocation = http2_process_headers_mem();
    if (!invocation) {
        return 0;
    }
    __builtin_memset(invocation, 0, sizeof(*invocation));

    u32 stream_id = 0;
    if (!go_http2_meta_headers_stream_id(frame, &stream_id) ||
        !go_http2_server_stream_key(&invocation->stream, sc_ptr, stream_id)) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();
    u32 max_client_stream_id = 0;
    if (!ot ||
        bpf_probe_read(&max_client_stream_id,
                       sizeof(max_client_stream_id),
                       sc_ptr + go_offset_of(ot, (go_offset){.v = max_stream_id_offset})) ||
        !go_http2_initial_header_candidate(stream_id, max_client_stream_id)) {
        return 0;
    }

    invocation->candidate_initial = 1;
    invocation->request.traceparent_state =
        go_http2_process_meta_frame_headers(frame, &invocation->request.tp);

    // A new stream ID cannot have live authority. Removing any retained value here also
    // prevents a recycled serverConn address from reviving an unconsumed old request.
    bpf_map_delete_elem(&http2_server_requests_tp, &invocation->stream);
    if (!go_http2_stage_process_headers_invocation(
            &http2_process_headers_invocations, &g_key, invocation)) {
        return 0;
    }

    // This uprobe completes before processHeaders can schedule runHandler. Publish once
    // here so both handler-before-return and return-before-handler schedules are lossless.
    // A map update failure is fail-closed: the return probe never retries publication.
    go_http2_begin_request_state(
        &http2_server_requests_tp, &invocation->stream, &invocation->request);
    return 0;
}

SEC("uprobe/http2Server_processHeaders")
int obi_uprobe_http2Server_processHeaders(struct pt_regs *ctx) {
    return go_http2_server_process_headers(ctx, _sc_max_client_stream_id_pos);
}

SEC("uprobe/http2Server_processHeaders_vendored")
int obi_uprobe_http2Server_processHeadersVendored(struct pt_regs *ctx) {
    return go_http2_server_process_headers(ctx, _sc_max_client_stream_id_vendored_pos);
}

static __always_inline int
go_http2_server_process_headers_returns(struct pt_regs *ctx, go_offset_const max_stream_id_offset) {
    go_exact_process_addr_key_t g_key = {};
    if (!go_http2_process_headers_key(&g_key, GOROUTINE_PTR(ctx))) {
        return 0;
    }
    http2_process_headers_invocation_t *invocation =
        go_http2_lookup_process_headers_invocation(&http2_process_headers_invocations, &g_key);
    if (!invocation) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();
    const u64 generation = go_process_generation(g_key.address.pid);
    u32 max_client_stream_id = 0;
    const u8 accepted =
        invocation->candidate_initial && generation &&
        generation == invocation->stream.generation && !GO_PARAM1(ctx) && ot &&
        bpf_probe_read(&max_client_stream_id,
                       sizeof(max_client_stream_id),
                       (void *)invocation->stream.server_conn +
                           go_offset_of(ot, (go_offset){.v = max_stream_id_offset})) == 0 &&
        max_client_stream_id == invocation->stream.stream_id;

    // A successful return leaves the entry-time state for runHandler. Observable errors
    // and nil-error GOAWAY ignores cannot have scheduled a handler and revoke it.
    go_http2_finish_request_state(&http2_server_requests_tp, &invocation->stream, accepted);
    go_http2_clear_process_headers_invocation(&http2_process_headers_invocations, &g_key);
    return 0;
}

SEC("uprobe/http2Server_processHeaders_return")
int obi_uprobe_http2Server_processHeadersReturns(struct pt_regs *ctx) {
    return go_http2_server_process_headers_returns(ctx, _sc_max_client_stream_id_pos);
}

SEC("uprobe/http2Server_processHeaders_return_vendored")
int obi_uprobe_http2Server_processHeadersReturnsVendored(struct pt_regs *ctx) {
    return go_http2_server_process_headers_returns(ctx, _sc_max_client_stream_id_vendored_pos);
}

static __always_inline void apply_http1_server_observation(go_addr_key_t *g_key,
                                                           u8 discard_fallback) {
    if (!discard_fallback) {
        return;
    }

    obi_ctx__del(bpf_get_current_pid_tgid());
    discard_server_parent_candidates(g_key);

    http1_server_handoff_t *handoff =
        go_http1_server_header_observation_eligible(&http1_server_handoffs, g_key);
    if (go_http1_server_handoff_has_parent(handoff)) {
        obi_ctx__set(bpf_get_current_pid_tgid(), &handoff->tp);
    }
}

static __always_inline void store_http1_server_scan(go_addr_key_t *g_key,
                                                    enum go_http1_traceparent_scan_result result,
                                                    const go_http1_traceparent_t *traceparent) {
    http1_server_handoff_t *handoff =
        go_http1_server_header_observation_eligible(&http1_server_handoffs, g_key);
    const u8 discard_fallback = go_http1_store_server_scan(handoff, result, traceparent);
    apply_http1_server_observation(g_key, discard_fallback);
}

static __always_inline void fail_http1_server_observation(go_addr_key_t *g_key) {
    http1_server_handoff_t *handoff =
        go_http1_server_header_observation_eligible(&http1_server_handoffs, g_key);
    const u8 discard_fallback = go_http1_fail_server_header_observation(handoff);
    apply_http1_server_observation(g_key, discard_fallback);
}

static __always_inline void handle_legacy_http1_server_header(go_addr_key_t *g_key,
                                                              const unsigned char *field,
                                                              u32 captured_len,
                                                              u64 field_len) {
    http1_server_handoff_t *handoff =
        go_http1_server_header_observation_eligible(&http1_server_handoffs, g_key);
    const u8 discard_fallback =
        go_http1_observe_legacy_server_header(handoff, field, captured_len, field_len);
    apply_http1_server_observation(g_key, discard_fallback);
}

SEC("uprobe/readMimeHeader")
int obi_uprobe_readMimeHeader(struct pt_regs *ctx) {
    if (!g_bpf_loop_enabled) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/readMimeHeader === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    if (!go_http1_server_header_observation_eligible(&http1_server_handoffs, &g_key)) {
        return 0;
    }

    const void *reader = (const unsigned char *)GO_PARAM1(ctx);
    if (!reader) {
        fail_http1_server_observation(&g_key);
        return 0;
    }
    off_table_t *ot = get_offsets_table();

    const u64 text_reader_r_pos = go_offset_of(ot, (go_offset){.v = _text_reader_r_pos});
    const u64 buf_pos = go_offset_of(ot, (go_offset){.v = _buf_reader_buf_pos});
    const u64 reader_r_pos = go_offset_of(ot, (go_offset){.v = _buf_reader_r_pos});
    const u64 reader_w_pos = go_offset_of(ot, (go_offset){.v = _buf_reader_w_pos});
    if (text_reader_r_pos == (u64)-1 || buf_pos == (u64)-1 || reader_r_pos == (u64)-1 ||
        reader_w_pos == (u64)-1) {
        fail_http1_server_observation(&g_key);
        return 0;
    }

    void *bufio_reader = 0;
    if (bpf_probe_read_user(&bufio_reader, sizeof(bufio_reader), reader + text_reader_r_pos) ||
        !bufio_reader) {
        fail_http1_server_observation(&g_key);
        return 0;
    }

    // Cache the bufio.Reader so serve_http_returns can ship the request bytes.
    bpf_map_update_elem(&ongoing_server_bufr, &g_key, &bufio_reader, BPF_ANY);

    bpf_dbg_printk("R=%llx, off=%d", bufio_reader, buf_pos);

    void *arr = 0;
    u64 buf_len = 0;
    u64 reader_r = 0;
    u64 reader_w = 0;
    if (bpf_probe_read_user(&arr, sizeof(arr), bufio_reader + buf_pos) ||
        bpf_probe_read_user(
            &buf_len, sizeof(buf_len), bufio_reader + buf_pos + k_go_slice_len_offset) ||
        bpf_probe_read_user(&reader_r, sizeof(reader_r), bufio_reader + reader_r_pos) ||
        bpf_probe_read_user(&reader_w, sizeof(reader_w), bufio_reader + reader_w_pos) || !arr) {
        fail_http1_server_observation(&g_key);
        return 0;
    }

    u64 region_start = 0;
    u16 region_len = 0;
    if (!go_http1_reader_capture_region(
            reader_r, reader_w, buf_len, TRACE_BUF_SIZE, &region_start, &region_len)) {
        fail_http1_server_observation(&g_key);
        return 0;
    }

    bpf_dbg_printk("buf r=%d, w=%d, capture=%d", reader_r, reader_w, region_len);

    unsigned char *buf = (unsigned char *)tp_char_buf_mem();
    if (!buf) {
        fail_http1_server_observation(&g_key);
        return 0;
    }

    if (bpf_probe_read_user(buf, region_len, (unsigned char *)arr + region_start) != 0) {
        bpf_dbg_printk("failed to read MIME header buffer");
        fail_http1_server_observation(&g_key);
        return 0;
    }

    go_http1_traceparent_t traceparent = {};
    const enum go_http1_traceparent_scan_result result =
        go_http1_scan_inbound_traceparent(buf, region_len, &traceparent);
    store_http1_server_scan(&g_key, result, &traceparent);
    return 0;
}

SEC("uprobe/readContinuedLineSlice")
int obi_uprobe_readContinuedLineSliceReturns(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/readContinuedLineSlice ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    if (!go_http1_server_header_observation_eligible(&http1_server_handoffs, &g_key)) {
        return 0;
    }

    const u64 len = (u64)GO_PARAM2(ctx);
    const unsigned char *buf = (const unsigned char *)GO_PARAM1(ctx);
    if (GO_PARAM4(ctx)) {
        fail_http1_server_observation(&g_key);
        return 0;
    }
    if (len == 0) {
        handle_legacy_http1_server_header(&g_key, buf, 0, 0);
        return 0;
    }
    if (!buf) {
        fail_http1_server_observation(&g_key);
        return 0;
    }

    unsigned char *temp = temp_header_mem();
    const u32 safe_len = min(k_http_header_max_len, len);
    if (!temp || bpf_probe_read_user(temp, safe_len, buf) != 0) {
        bpf_dbg_printk("failed to read buffer");
        fail_http1_server_observation(&g_key);
        return 0;
    };

    handle_legacy_http1_server_header(&g_key, temp, safe_len, len);

    return 0;
}

static __always_inline int serve_http_returns(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        go_http_server_invocation_lookup_current(&ongoing_http_server_requests, &g_key);

    if (invocation == NULL) {
        void *parent_go = (void *)find_parent_goroutine(&g_key);
        if (parent_go && (u64)parent_go != k_go_parent_error) {
            bpf_dbg_printk("found parent goroutine for header, parent_go=%llx", parent_go);
            go_addr_key_t p_key = {};
            go_addr_key_from_id(&p_key, parent_go);
            invocation =
                go_http_server_invocation_lookup_current(&ongoing_http_server_requests, &p_key);
            if (invocation) {
                goroutine_addr = parent_go;
                g_key.addr = (u64)goroutine_addr;
            }
        }
        if (!invocation) {
            bpf_dbg_printk("can't read http invocation metadata");
            goto done;
        }
    }

    if (!invocation->status) {
        invocation->status = -1;
        return 0;
    }

    unsigned char tp_buf[TP_MAX_VAL_LENGTH];
    make_tp_string(tp_buf, &invocation->tp);
    bpf_dbg_printk("tp=%s", tp_buf);

    connection_info_t conn = {0};
    const go_server_connection_t *state = go_server_connection_lookup_current(&g_key);
    if (state) {
        __builtin_memcpy(&conn, &state->conn, sizeof(connection_info_t));
    } else {
        // We can't find the connection info, this typically means there are too many requests
        // per second and the connection map is too small for the workload.
        bpf_dbg_printk("Can't find connection info for goroutine_addr: %llx", goroutine_addr);
    }
    // Server connections have opposite order, source port is the server port
    swap_connection_info_order(&conn);

    http_request_trace_t *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace_t), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        goto done;
    }

    task_pid(&trace->pid);
    trace->type = EVENT_HTTP_REQUEST;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->end_monotime_ns = bpf_ktime_get_ns();
    trace->host[0] = '\0';
    if (invocation->is_tls) {
        bpf_memcpy(trace->scheme, "https", 6);
    } else {
        bpf_memcpy(trace->scheme, "http", 5);
    }
    trace->pattern[0] = '\0';

    goroutine_metadata *g_metadata = bpf_map_lookup_elem(&ongoing_goroutines, &g_key);
    const u64 generation = go_process_generation(g_key.pid);
    if (g_metadata && generation && g_metadata->generation == generation) {
        trace->go_start_monotime_ns = g_metadata->timestamp;
        bpf_map_delete_elem(&ongoing_goroutines, &g_key);
    } else {
        trace->go_start_monotime_ns = invocation->start_monotime_ns;
    }

    __builtin_memcpy(&trace->conn, &conn, sizeof(connection_info_t));
    trace->tp = invocation->tp;
    trace->content_length = invocation->content_length;
    __builtin_memcpy(trace->method, invocation->method, sizeof(trace->method));
    __builtin_memcpy(trace->path, invocation->path, sizeof(trace->path));
    __builtin_memcpy(trace->pattern, invocation->pattern, sizeof(trace->pattern));
    trace->status = (u16)invocation->status;
    trace->response_length = invocation->response_length;
    trace->is_jsonrpc = invocation->is_jsonrpc;

    make_tp_string(tp_buf, &invocation->tp);
    bpf_dbg_printk("tp=%s", tp_buf);
    bpf_dbg_printk("method=%s", trace->method);
    bpf_dbg_printk("path=%s", trace->path);
    bpf_dbg_printk("pattern=%s", trace->pattern);
    bpf_dbg_printk("is_jsonrpc=%d", trace->is_jsonrpc);

    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

done:
    go_http1_close_server_handoff(&http1_server_handoffs, &g_key);
    bpf_map_delete_elem(&ongoing_server_bufr, &g_key);
    if (invocation) {
        pop_go_trace(&g_key, &invocation->tp);
    } else {
        poison_and_revoke_go_trace(&g_key);
    }
    bpf_map_delete_elem(&ongoing_http_server_requests, &g_key);
    obi_ctx__del(bpf_get_current_pid_tgid());
    return 0;
}

SEC("uprobe/ServeHTTP_ret")
int obi_uprobe_ServeHTTPReturns(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/ServeHTTP_ret ===");
    return serve_http_returns(ctx);
}

/* HTTP Client. We expect to see HTTP client in both HTTP server and gRPC server calls.*/
static __noinline void stage_http1_header_request(void *header_addr,
                                                  void *persist_conn_addr,
                                                  const go_exact_process_addr_key_t *request_key) {
    go_http1_stage_header_request(
        &header_req_map, (u64)header_addr, (u64)persist_conn_addr, request_key);
}

static __noinline u8 take_http1_header_request(void *header_addr,
                                               void *persist_conn_addr,
                                               go_exact_process_addr_key_t *request_key) {
    if (!header_addr || !persist_conn_addr || !request_key) {
        return 0;
    }
    const u64 process_start_time = OBI_CURRENT_PROCESS_START_BOOTTIME_NS();
    const u32 pid = pid_from_pid_tgid(bpf_get_current_pid_tgid());
    if (!process_start_time) {
        return 0;
    }
    return go_http1_take_header_request(&header_req_map,
                                        pid,
                                        process_start_time,
                                        (u64)header_addr,
                                        (u64)persist_conn_addr,
                                        request_key);
}

static __always_inline void roundTripStartHelper(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);

    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);
    go_exact_process_addr_key_t exact_g_key = {};
    if (!go_exact_process_addr_key_from_address(&exact_g_key, &g_key)) {
        return;
    }

    // Clear every same-incarnation staging slot before any request read can
    // fail. A missed earlier return can therefore never be consumed by this
    // invocation or by persistConn.roundTrip.
    bpf_map_delete_elem(&go_ongoing_http_client_requests, &exact_g_key);
    bpf_map_delete_elem(&ongoing_http_client_requests_data, &exact_g_key);
    bpf_map_delete_elem(&ongoing_client_connections, &exact_g_key);

    void *req = GO_PARAM2(ctx);
    off_table_t *ot = get_offsets_table();

    http_func_invocation_t invocation = {.start_monotime_ns = bpf_ktime_get_ns(), .tp = {0}};

    client_trace_parent(goroutine_addr, &invocation.tp);

    http_client_data_t trace = {0};

    // Get method from Request.Method
    if (!read_go_str("method",
                     req,
                     go_offset_of(ot, (go_offset){.v = _method_ptr_pos}),
                     trace.method,
                     sizeof(trace.method))) {
        bpf_dbg_printk("can't read http Request.Method");
        return;
    }

    bpf_probe_read(&trace.content_length,
                   sizeof(trace.content_length),
                   (void *)(req + go_offset_of(ot, (go_offset){.v = _content_length_ptr_pos})));

    // Get path from Request.URL
    void *url_ptr = 0;
    bpf_probe_read(&url_ptr,
                   sizeof(url_ptr),
                   (void *)(req + go_offset_of(ot, (go_offset){.v = _url_ptr_pos})));

    if (url_ptr) {
        if (!read_go_str("path",
                         url_ptr,
                         go_offset_of(ot, (go_offset){.v = _path_ptr_pos}),
                         trace.path,
                         sizeof(trace.path))) {
            bpf_dbg_printk("can't read http Request.URL.Path");
            return;
        }

        if (!read_go_str("host",
                         url_ptr,
                         go_offset_of(ot, (go_offset){.v = _host_ptr_pos}),
                         trace.host,
                         sizeof(trace.host))) {
            bpf_dbg_printk("can't read http Request.URL.Host");
            return;
        }

        if (!read_go_str("scheme",
                         url_ptr,
                         go_offset_of(ot, (go_offset){.v = _scheme_ptr_pos}),
                         trace.scheme,
                         sizeof(trace.scheme))) {
            bpf_dbg_printk("can't read http Request.URL.Scheme");
            return;
        }
    }

    bpf_dbg_printk("path=%s", trace.path);
    bpf_dbg_printk("host=%s", trace.host);
    bpf_dbg_printk("scheme=%s", trace.scheme);

    if (g_bpf_header_propagation) {
        void *headers_ptr = 0;
        bpf_probe_read(&headers_ptr,
                       sizeof(headers_ptr),
                       (void *)(req + go_offset_of(ot, (go_offset){.v = _req_header_ptr_pos})));
        bpf_dbg_printk(
            "goroutine_addr=%lx, req=%llx, headers_ptr=%llx", goroutine_addr, req, headers_ptr);
        invocation.header_addr = (u64)headers_ptr;
    }

    // Write event only after all fallible request reads and exact staging
    // fields have completed.
    if (bpf_map_update_elem(&go_ongoing_http_client_requests, &exact_g_key, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update http client map element");
    }

    bpf_map_update_elem(&ongoing_http_client_requests_data, &exact_g_key, &trace, BPF_ANY);
}

SEC("uprobe/roundTrip")
int obi_uprobe_roundTrip(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/roundTrip ===");
    roundTripStartHelper(ctx);
    return 0;
}

static __always_inline void cleanup_go_http_client_handoff(const go_addr_key_t *g_key) {
    cleanup_go_outgoing_trace_handoff(g_key);
}

SEC("uprobe/roundTrip_return")
int obi_uprobe_roundTripReturn(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/roundTrip_return ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    off_table_t *ot = get_offsets_table();

    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);
    go_exact_process_addr_key_t exact_g_key = {};
    if (!go_exact_process_addr_key_from_address(&exact_g_key, &g_key)) {
        return 0;
    }

    http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&go_ongoing_http_client_requests, &exact_g_key);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read http invocation metadata");
        goto done;
    }

    http_client_data_t *data =
        bpf_map_lookup_elem(&ongoing_http_client_requests_data, &exact_g_key);
    if (data == NULL) {
        bpf_dbg_printk("can't read http client invocation data");
        goto done;
    }

    http_request_trace_t *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace_t), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        goto done;
    }

    task_pid(&trace->pid);
    trace->type = EVENT_HTTP_CLIENT;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->go_start_monotime_ns = invocation->start_monotime_ns;
    trace->end_monotime_ns = bpf_ktime_get_ns();
    trace->pattern[0] = '\0';
    trace->is_jsonrpc = false;

    // Copy the values read on request start
    __builtin_memcpy(trace->method, data->method, sizeof(trace->method));
    __builtin_memcpy(trace->path, data->path, sizeof(trace->path));
    __builtin_memcpy(trace->host, data->host, sizeof(trace->host));
    __builtin_memcpy(trace->scheme, data->scheme, sizeof(trace->scheme));
    trace->content_length = data->content_length;

    // Get request/response struct

    void *resp_ptr = (void *)GO_PARAM1(ctx);

    connection_info_t *info = bpf_map_lookup_elem(&ongoing_client_connections, &exact_g_key);
    if (info) {
        __builtin_memcpy(&trace->conn, info, sizeof(connection_info_t));
    } else {
        __builtin_memset(&trace->conn, 0, sizeof(connection_info_t));
    }

    trace->tp = invocation->tp;

    unsigned char tp_buf[TP_MAX_VAL_LENGTH];
    make_tp_string(tp_buf, &invocation->tp);
    bpf_dbg_printk("tp_buf=[%s]", tp_buf);
    bpf_dbg_printk("method=%s", trace->method);
    bpf_dbg_printk("path=%s", trace->path);

    const u64 status_code_ptr_pos = go_offset_of(ot, (go_offset){.v = _status_code_ptr_pos});
    bpf_probe_read(&trace->status, sizeof(trace->status), (void *)(resp_ptr + status_code_ptr_pos));

    bpf_dbg_printk("status=%d, status_code_ptr_pos=%d, resp_ptr=%lx",
                   trace->status,
                   status_code_ptr_pos,
                   (u64)resp_ptr);

    const u64 response_length_ptr_pos =
        go_offset_of(ot, (go_offset){.v = _response_length_ptr_pos});
    bpf_probe_read(&trace->response_length,
                   sizeof(trace->response_length),
                   (void *)(resp_ptr + response_length_ptr_pos));

    bpf_dbg_printk("response_length=%llx, response_length_ptr_pos=%llu, resp_ptr=%llx",
                   trace->response_length,
                   response_length_ptr_pos,
                   (u64)resp_ptr);

    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

done:
    cleanup_go_http_client_handoff(&g_key);
    bpf_map_delete_elem(&go_ongoing_http_client_requests, &exact_g_key);
    bpf_map_delete_elem(&ongoing_http_client_requests_data, &exact_g_key);
    bpf_map_delete_elem(&ongoing_client_connections, &exact_g_key);
    return 0;
}

// Context propagation through HTTP headers.
//
// The uprobe pair below implements the HTTP/1 client traceparent injection. The
// application's own traceparent (e.g. written by the OTel SDK via
// req.Header.Set) is serialized by writeSubset itself, so it is only present in
// the io.Writer buffer once writeSubset returns. We therefore stash the writer
// on entry and, on return, scan the header block writeSubset just wrote for an
// existing traceparent: if one is present we must not add a second one
// otherwise we inject ours at the current write position.
typedef struct write_subset_invocation {
    u64 io_writer_addr;
    go_exact_process_addr_key_t request_key;
    tp_info_t tp;
    s64 entry_n; // io.Writer write offset at entry (start of this header block)
    outgoing_trace_token_t handoff_token;
    u8 header_map_empty;
    u8 handoff_expected;
    u8 _pad[6];
} write_subset_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_exact_process_addr_key_t);
    __type(value, write_subset_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_write_subsets SEC(".maps");

static __always_inline void
stop_client_traceparent_fallback(const go_exact_process_addr_key_t *request_key) {
    if (!request_key) {
        return;
    }
    cleanup_go_outgoing_trace_handoff(&request_key->address);

    connection_info_t *info = bpf_map_lookup_elem(&ongoing_client_connections, request_key);
    if (!info) {
        return;
    }

    store_go_handled_connection_info(info);
}

static __noinline u8 publish_client_application_traceparent(write_subset_invocation_t *inv) {
    if (!inv) {
        return 0;
    }

    stop_client_traceparent_fallback(&inv->request_key);
    inv->handoff_expected = 0;
    __builtin_memset(&inv->handoff_token, 0, sizeof(inv->handoff_token));

    connection_info_t *info = bpf_map_lookup_elem(&ongoing_client_connections, &inv->request_key);
    if (!info) {
        return 0;
    }

    const egress_key_t egress = make_egress_key(info, (u32)inv->request_key.address.pid, 0);
    const tp_info_pid_t outgoing = {
        .tp = inv->tp,
        .pid = (u32)inv->request_key.address.pid,
        .valid = 1,
        .written = k_outbound_trace_written,
        .req_type = EVENT_HTTP_CLIENT,
    };
    if (!reserve_outgoing_trace_handoff(&egress, &outgoing, &inv->handoff_token)) {
        return 0;
    }
    if (!register_go_outgoing_trace_handoff(
            &inv->request_key.address, &egress, &inv->handoff_token)) {
        request_outgoing_trace_handoff_retirement(&egress, &inv->handoff_token, &outgoing, 0);
        return 0;
    }

    inv->handoff_expected = 1;
    bpf_map_update_elem(&outgoing_trace_map, &egress, &outgoing, BPF_NOEXIST);
    return 1;
}

static __always_inline u8
client_traceparent_fallback(const go_exact_process_addr_key_t *request_key,
                            const outgoing_trace_token_t *token,
                            egress_key_t *egress,
                            tp_info_pid_t *snapshot) {
    connection_info_t *info =
        request_key ? bpf_map_lookup_elem(&ongoing_client_connections, request_key) : NULL;
    if (!info || !egress || !snapshot || !request_key) {
        return 0;
    }
    *egress = make_egress_key(info, (u32)request_key->address.pid, 0);
    return claim_outgoing_trace_handoff(
        egress, token, (u32)request_key->address.pid, EVENT_HTTP_CLIENT, NULL, 0, 1, snapshot);
}

static __always_inline u8 reserve_client_traceparent_fallback(write_subset_invocation_t *inv,
                                                              egress_key_t *egress,
                                                              tp_info_pid_t *snapshot) {
    connection_info_t *info =
        inv ? bpf_map_lookup_elem(&ongoing_client_connections, &inv->request_key) : NULL;
    if (!info || !egress || !snapshot) {
        return 0;
    }
    *egress = make_egress_key(info, (u32)inv->request_key.address.pid, 0);
    tp_info_pid_t outgoing = {
        .tp = inv->tp,
        .pid = (u32)inv->request_key.address.pid,
        .valid = 1,
        .written = k_outbound_trace_pending,
        .req_type = EVENT_HTTP_CLIENT,
    };
    if (!reserve_outgoing_trace_handoff(egress, &outgoing, &inv->handoff_token) ||
        !register_go_outgoing_trace_handoff(
            &inv->request_key.address, egress, &inv->handoff_token)) {
        request_outgoing_trace_handoff_retirement(egress, &inv->handoff_token, &outgoing, 1);
        return 0;
    }
    inv->handoff_expected = 1;
    bpf_map_update_elem(&outgoing_trace_map, egress, &outgoing, BPF_NOEXIST);
    return claim_outgoing_trace_handoff(egress,
                                        &inv->handoff_token,
                                        (u32)inv->request_key.address.pid,
                                        EVENT_HTTP_CLIENT,
                                        &outgoing,
                                        0,
                                        1,
                                        snapshot);
}

SEC("uprobe/header_writeSubset")
int obi_uprobe_writeSubset(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);

    go_addr_key_t gw_key = {};
    go_addr_key_from_id(&gw_key, goroutine_addr);
    go_exact_process_addr_key_t exact_gw_key = {};
    if (!go_exact_process_addr_key_from_address(&exact_gw_key, &gw_key)) {
        return 0;
    }
    // A same-process goroutine address can be reused after a missed return.
    // Clear its slot before propagation flags, offsets, or parameters can
    // cause an early exit.
    go_http1_begin_write_subset(&ongoing_write_subsets, &exact_gw_key);

    if (!g_bpf_header_propagation) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/header_writeSubset ===");

    void *header_addr = GO_PARAM1(ctx);
    void *io_writer_addr = GO_PARAM3(ctx);

    bpf_dbg_printk("goroutine_addr=%lx, header_addr=%llx", goroutine_addr, header_addr);

    if (!header_addr || !io_writer_addr) {
        goto done;
    }

    off_table_t *ot = get_offsets_table();
    const u64 io_writer_wr_pos = go_offset_of(ot, (go_offset){.v = _io_writer_wr_pos});
    if (!io_writer_wr_pos) {
        goto done;
    }
    void *persist_conn_writer = 0;
    if (bpf_probe_read_user(&persist_conn_writer,
                            sizeof(persist_conn_writer),
                            (void *)(io_writer_addr + io_writer_wr_pos + k_go_iface_data_offset)) !=
            0 ||
        !persist_conn_writer) {
        goto done;
    }
    void *persist_conn = 0;
    if (bpf_probe_read_user(&persist_conn, sizeof(persist_conn), persist_conn_writer) != 0 ||
        !persist_conn) {
        goto done;
    }

    // Header is legally shared by concurrent requests. Only the composite
    // Header + owning persistConn association is one-to-one at this write.
    go_exact_process_addr_key_t request_key = {};
    if (!take_http1_header_request(header_addr, persist_conn, &request_key)) {
        goto done;
    }
    const u64 parent_goaddr = request_key.address.addr;

    http_func_invocation_t *func_inv =
        bpf_map_lookup_elem(&go_ongoing_http_client_requests, &request_key);
    if (!func_inv) {
        bpf_dbg_printk("Can't find client request for goroutine, parent_goaddr=%llx",
                       parent_goaddr);
        goto done;
    }

    const u64 io_writer_n_pos = go_offset_of(ot, (go_offset){.v = _io_writer_n_pos});
    if (!io_writer_n_pos) {
        goto done;
    }

    // Record the write offset at entry: the header block writeSubset is about
    // to serialize (where the app's own traceparent would land) starts here.
    // The io.Writer is a *bufio.Writer, whose backing array is allocated once
    // and never grown (it flushes and resets n when full, never append/realloc),
    // so this offset stays valid into a stable buffer at return. The only thing
    // that invalidates it is a Flush() mid-writeSubset (huge header sets), which
    // resets n to 0; the return probe handles that (return_n <= entry_n) and all
    // its reads stay bounded within the buffer regardless.
    s64 entry_n = 0;
    if (bpf_probe_read_user(
            &entry_n, sizeof(entry_n), (void *)(io_writer_addr + io_writer_n_pos)) != 0) {
        goto done;
    }

    s64 header_count = -1;
    bpf_probe_read_user(&header_count, sizeof(header_count), header_addr);

    write_subset_invocation_t inv = {
        .io_writer_addr = (u64)io_writer_addr,
        .request_key = request_key,
        .tp = func_inv->tp,
        .entry_n = entry_n,
        .header_map_empty = header_count == 0,
    };
    connection_info_t *client_conn = bpf_map_lookup_elem(&ongoing_client_connections, &request_key);
    if (client_conn) {
        const egress_key_t egress = make_egress_key(client_conn, (u32)request_key.address.pid, 0);
        tp_info_pid_t snapshot = {};
        if (snapshot_current_outgoing_trace_handoff(&egress,
                                                    (u32)request_key.address.pid,
                                                    EVENT_HTTP_CLIENT,
                                                    1,
                                                    &inv.handoff_token,
                                                    &snapshot,
                                                    NULL)) {
            inv.handoff_expected = 1;
        }
    }
    if (go_http1_should_suppress_fallback(inv.header_map_empty)) {
        // A nonempty header map can flush before the return probe can inspect it.
        // Suppress blind fallback injection so an application traceparent cannot
        // be duplicated in an earlier flushed block, even if write staging fails.
        stop_client_traceparent_fallback(&request_key);
        inv.handoff_expected = 0;
        __builtin_memset(&inv.handoff_token, 0, sizeof(inv.handoff_token));
    }
    bpf_map_update_elem(&ongoing_write_subsets, &exact_gw_key, &inv, BPF_ANY);

done:
    return 0;
}

// client_request_traceparent scans the complete header block that writeSubset
// just serialized ([entry_n, return_n)) for traceparent field presence. Exactly
// one valid field is authoritative, while malformed or duplicate fields only
// suppress injection. An incomplete capture is reported as unknown so callers
// never treat a flushed or oversized block as proof of absence.
static __always_inline enum go_http1_traceparent_scan_result
client_request_traceparent(void *buf_ptr,
                           s64 entry_n,
                           s64 return_n,
                           s64 size,
                           u8 header_map_empty,
                           enum go_http1_traceparent_scan_result (*tp_scan_fn)(
                               unsigned char *, u16, go_http1_traceparent_t *),
                           go_http1_traceparent_t *app_traceparent) {
    // Go's map header starts with its entry count. If the map was empty,
    // writeSubset could not have flushed or serialized a field, so an unchanged
    // writer offset is definitive absence rather than an incomplete capture.
    if (go_http1_header_map_is_definitively_empty(header_map_empty, entry_n, return_n)) {
        return k_go_http1_traceparent_scan_absent;
    }

    u32 region = 0;
    if (!go_http1_capture_region(entry_n, return_n, size, TRACE_BUF_SIZE, &region)) {
        return k_go_http1_traceparent_scan_unknown;
    }

    unsigned char *scan = (unsigned char *)tp_char_buf_mem();
    if (!scan) {
        return k_go_http1_traceparent_scan_unknown;
    }

    if (bpf_probe_read_user(scan, region, (void *)(buf_ptr + (u32)entry_n)) != 0) {
        return k_go_http1_traceparent_scan_unknown;
    }
    scan[region] = '\0';

    // Direct (not indirect) calls so the untaken branch is const-folded away per
    // program instantiation, keeping the bpf_loop subprog out of the legacy one.
    if (tp_scan_fn == go_http1_scan_traceparent) {
        return go_http1_scan_traceparent(scan, (u16)region, app_traceparent);
    }
    return go_http1_scan_traceparent_legacy(scan, (u16)region, app_traceparent);
}

static __noinline void inject_client_traceparent(
    write_subset_invocation_t *inv, void *buf_ptr, s64 len, s64 size, void *writer_n_addr) {
    if (!inv || !buf_ptr || !writer_n_addr || !go_http1_can_append_traceparent(len, size)) {
        return;
    }

    egress_key_t egress = {};
    tp_info_pid_t handoff = {};
    const u8 claimed =
        inv->handoff_expected
            ? client_traceparent_fallback(&inv->request_key, &inv->handoff_token, &egress, &handoff)
            : reserve_client_traceparent_fallback(inv, &egress, &handoff);
    if (!claimed) {
        return;
    }

    unsigned char buf[k_traceparent_len];
    make_tp_string(buf, &inv->tp);
    char key[TP_MAX_KEY_LENGTH + 2] = "Traceparent: ";
    char end[2] = "\r\n";
    s64 next_len = len;
    long write_err = bpf_probe_write_user(buf_ptr + (next_len & 0x0ffff), key, sizeof(key));
    next_len += sizeof(key);
    if (write_err == 0) {
        write_err = bpf_probe_write_user(buf_ptr + (next_len & 0x0ffff), buf, sizeof(buf));
    }
    next_len += sizeof(buf);
    if (write_err == 0) {
        write_err = bpf_probe_write_user(buf_ptr + (next_len & 0x0ffff), end, sizeof(end));
    }
    next_len += sizeof(end);
    if (write_err == 0) {
        write_err = bpf_probe_write_user(writer_n_addr, &next_len, sizeof(next_len));
    }
    if (write_err == 0) {
        commit_claimed_outgoing_trace_handoff(&egress, &inv->handoff_token);
        mirror_outgoing_trace_handoff_commit(&egress, &handoff);
        return;
    }

    release_claimed_outgoing_trace_handoff(&egress, &inv->handoff_token);
    stop_client_traceparent_fallback(&inv->request_key);
    inv->handoff_expected = 0;
}

static __always_inline int
on_writeSubset_returns(struct pt_regs *ctx,
                       enum go_http1_traceparent_scan_result (*tp_scan_fn)(
                           unsigned char *, u16, go_http1_traceparent_t *)) {
    if (!g_bpf_header_propagation) {
        return 0;
    }

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t gw_key = {};
    go_addr_key_from_id(&gw_key, goroutine_addr);
    go_exact_process_addr_key_t exact_gw_key = {};
    if (!go_exact_process_addr_key_from_address(&exact_gw_key, &gw_key)) {
        return 0;
    }

    write_subset_invocation_t *inv = bpf_map_lookup_elem(&ongoing_write_subsets, &exact_gw_key);
    if (!inv) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/header_writeSubset_returns ===");

    off_table_t *ot = get_offsets_table();
    void *io_writer_addr = (void *)inv->io_writer_addr;

    const u64 io_writer_buf_ptr_pos = go_offset_of(ot, (go_offset){.v = _io_writer_buf_ptr_pos});
    const u64 io_writer_n_pos = go_offset_of(ot, (go_offset){.v = _io_writer_n_pos});

    // writing with bad offsets can crash the application, be defensive here
    if (!io_writer_buf_ptr_pos || !io_writer_n_pos) {
        goto unknown;
    }

    void *buf_ptr = 0;
    if (bpf_probe_read_user(
            &buf_ptr, sizeof(buf_ptr), (void *)(io_writer_addr + io_writer_buf_ptr_pos)) != 0 ||
        !buf_ptr) {
        goto unknown;
    }

    s64 size = 0; // len(buf) of the bufio.Writer; for bufio len == cap == capacity
    if (bpf_probe_read_user(
            &size,
            sizeof(size),
            (void *)(io_writer_addr + io_writer_buf_ptr_pos + k_go_slice_len_offset)) != 0) {
        goto unknown;
    }

    s64 len = 0; // current write offset (return position)
    if (bpf_probe_read_user(&len, sizeof(len), (void *)(io_writer_addr + io_writer_n_pos)) != 0) {
        goto unknown;
    }

    // Sanity-check the writer bounds before touching the buffer: a negative or
    // out-of-range write offset (e.g. after a bufio flush reset) means we can't
    // reason about the buffer, so skip rather than risk a bad access.
    if (size <= 0 || len < 0 || len > size) {
        goto unknown;
    }

    bpf_dbg_printk("buf_ptr=%llx, entry_n=%d, len=%d", (void *)buf_ptr, inv->entry_n, len);

    go_http1_traceparent_t app_traceparent = {};
    const enum go_http1_traceparent_scan_result scan_result = client_request_traceparent(
        buf_ptr, inv->entry_n, len, size, inv->header_map_empty, tp_scan_fn, &app_traceparent);
    if (scan_result == k_go_http1_traceparent_scan_found) {
        go_http1_adopt_traceparent(&inv->tp, &app_traceparent);

        http_func_invocation_t *request =
            bpf_map_lookup_elem(&go_ongoing_http_client_requests, &inv->request_key);
        if (request) {
            go_http1_adopt_traceparent(&request->tp, &app_traceparent);
        }

        publish_client_application_traceparent(inv);
        bpf_dbg_printk("adopted application traceparent for client request, skipping injection");
        goto done;
    }
    if (scan_result == k_go_http1_traceparent_scan_present) {
        stop_client_traceparent_fallback(&inv->request_key);
        bpf_dbg_printk("application traceparent is non-authoritative, skipping injection");
        goto done;
    }
    if (scan_result == k_go_http1_traceparent_scan_unknown) {
        goto unknown;
    }

    inject_client_traceparent(inv, buf_ptr, len, size, (void *)(io_writer_addr + io_writer_n_pos));

    goto done;

unknown:
    // The pre-populated fallback carries the independently-created context and
    // injects without inspecting HTTP/1 fields. A nonempty map may have flushed
    // before this incomplete capture, so keep its blind path suppressed. An
    // empty map cannot have flushed a field and retains fallback propagation.
    if (go_http1_should_suppress_fallback(inv->header_map_empty)) {
        stop_client_traceparent_fallback(&inv->request_key);
        inv->handoff_expected = 0;
    }
    bpf_dbg_printk("client header field capture incomplete, skipping direct injection");

done:
    bpf_map_delete_elem(&ongoing_write_subsets, &exact_gw_key);
    return 0;
}

// Two variants of the return probe: the default uses bpf_loop; the _legacy one
// uses a bounded scan for kernels without bpf_loop. FixupSpec swaps the default
// for the legacy on those kernels (and dummies the legacy elsewhere), mirroring
// obi_uprobe_readMimeHeader / obi_protocol_http. This keeps the bpf_loop subprog
// out of the program loaded on pre-5.17 kernels, which would otherwise reject it
// with "number of funcs in func_info doesn't match number of subprogs".
SEC("uprobe/header_writeSubset_returns")
int obi_uprobe_writeSubset_returns(struct pt_regs *ctx) {
    return on_writeSubset_returns(ctx, go_http1_scan_traceparent);
}

SEC("uprobe/header_writeSubset_returns_legacy")
int obi_uprobe_writeSubset_returns_legacy(struct pt_regs *ctx) {
    return on_writeSubset_returns(ctx, go_http1_scan_traceparent_legacy);
}

// HTTP 2.0 server support
SEC("uprobe/http2ResponseWriterStateWriteHeader")
int obi_uprobe_http2ResponseWriterStateWriteHeader(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/http2ResponseWriterStateWriteHeader ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    const u64 status = (u64)GO_PARAM2(ctx);
    bpf_dbg_printk("goroutine_addr=%lx, status=%d", goroutine_addr, status);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        go_http_server_invocation_lookup_current(&ongoing_http_server_requests, &g_key);

    if (invocation == NULL) {
        void *parent_go = (void *)find_parent_goroutine(&g_key);
        if (parent_go && (u64)parent_go != k_go_parent_error) {
            bpf_dbg_printk("found parent goroutine for header, parent_go=%llx", parent_go);
            go_addr_key_t p_key = {};
            go_addr_key_from_id(&p_key, parent_go);
            invocation =
                go_http_server_invocation_lookup_current(&ongoing_http_server_requests, &p_key);
        }
        if (!invocation) {
            bpf_dbg_printk("can't read http invocation metadata");
            return 0;
        }
    }

    // Strange case when the HTTP server response is empty, the writeHeader
    // is called on defer after the ServeHTTP returns.
    if (invocation->status == -1) {
        invocation->status = status;
        serve_http_returns(ctx);
    } else {
        invocation->status = status;
    }

    return 0;
}

// HTTP 2.0 server support
SEC("uprobe/http2serverConn_runHandler")
int obi_uprobe_http2serverConn_runHandler(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/http2serverConn_runHandler ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

    void *sc = GO_PARAM1(ctx);
    void *rw = GO_PARAM2(ctx);
    void *req = GO_PARAM3(ctx);
    off_table_t *ot = get_offsets_table();

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    go_http_server_close_prehandler_state(
        &http1_server_handoffs, &ongoing_http_server_requests, &g_key);
    bpf_map_delete_elem(&ongoing_server_bufr, &g_key);
    go_http_server_retire_go_trace(&g_key);
    obi_ctx__del(bpf_get_current_pid_tgid());
    go_server_connection_clear(&g_key);

    server_http_func_invocation_t *sentinel = http_server_invocation_mem();
    const u64 generation = go_process_generation(g_key.pid);
    u8 is_tls = 0;
    if (req && ot) {
        void *tls = NULL;
        if (bpf_probe_read(
                &tls, sizeof(tls), req + go_offset_of(ot, (go_offset){.v = _req_tls_pos})) == 0) {
            is_tls = tls != NULL;
        }
    }
    go_http2_prepare_h2_sentinel(sentinel, NULL, is_tls, generation);

    if (sc && ot) {
        void *conn_ptr = 0;
        bpf_probe_read(&conn_ptr,
                       sizeof(void *),
                       sc + go_offset_of(ot, (go_offset){.v = _sc_conn_pos}) +
                           k_go_iface_data_offset);
        bpf_dbg_printk("conn_ptr=%llx", conn_ptr);
        if (conn_ptr) {
            void *conn_conn_ptr = 0;
            bpf_probe_read(&conn_conn_ptr, sizeof(void *), conn_ptr + k_go_iface_data_offset);
            bpf_dbg_printk("conn_conn_ptr=%llx", conn_conn_ptr);
            if (conn_conn_ptr) {
                connection_info_t conn = {};
                if (get_conn_info(conn_conn_ptr, &conn)) {
                    go_server_connection_store_current(&g_key, &conn);
                }
            }
        }
    }

    if (sc) {
        u32 stream_id = 0;
        http2_server_stream_key_t stream_key = {};
        if (go_http2_handler_stream_id(rw, sc, &stream_id) &&
            go_http2_server_stream_key(&stream_key, sc, stream_id)) {
            go_http2_consume_request_state(
                &http2_server_requests_tp, &stream_key, sentinel, is_tls);
        }
    }

    if (sentinel && go_http2_header_requires_parent_discard(sentinel->header_traceparent_state)) {
        discard_server_parent_candidates(&g_key);
    }
    if (sentinel &&
        bpf_map_update_elem(&ongoing_http_server_requests, &g_key, sentinel, BPF_ANY) == 0 &&
        sentinel->header_traceparent_state == k_go_http1_traceparent_scan_found) {
        obi_ctx__set(bpf_get_current_pid_tgid(), &sentinel->tp);
    }

    return 0;
}

SEC("uprobe/http2serverConn_runHandler_return")
int obi_uprobe_http2serverConn_runHandlerReturns(struct pt_regs *ctx) {
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, GOROUTINE_PTR(ctx));

    server_http_invocation_scratch_t *scratch = http_server_invocation_scratch_mem();
    go_http2_cleanup_handler_state(&http1_server_handoffs,
                                   &ongoing_http_server_requests,
                                   &ongoing_server_bufr,
                                   &ongoing_server_connections,
                                   &g_key,
                                   scratch);
    obi_ctx__del(bpf_get_current_pid_tgid());
    return 0;
}

static __noinline void stage_http2_client_stream(void *framer,
                                                 u32 stream_id,
                                                 const go_exact_process_addr_key_t *request_key) {
    if (!framer || !stream_id || !request_key) {
        return;
    }
    go_exact_process_stream_key_t stream_key = {};
    if (!go_exact_process_stream_key_from_id(&stream_key, framer, stream_id) ||
        request_key->address.pid != stream_key.pid ||
        request_key->process_start_time != stream_key.process_start_time) {
        return;
    }
    bpf_map_update_elem(&http2_req_map, &stream_key, request_key, BPF_ANY);
}

static __noinline u8 take_http2_client_stream(void *framer,
                                              u32 stream_id,
                                              go_exact_process_addr_key_t *request_key) {
    if (!framer || !stream_id || !request_key) {
        return 0;
    }
    go_exact_process_stream_key_t stream_key = {};
    if (!go_exact_process_stream_key_from_id(&stream_key, framer, stream_id)) {
        return 0;
    }
    const go_exact_process_addr_key_t *located = bpf_map_lookup_elem(&http2_req_map, &stream_key);
    if (!located) {
        return 0;
    }
    const go_exact_process_addr_key_t exact = *located;
    bpf_map_delete_elem(&http2_req_map, &stream_key);
    if (exact.address.pid != stream_key.pid ||
        exact.process_start_time != stream_key.process_start_time) {
        return 0;
    }
    *request_key = exact;
    return 1;
}

static __always_inline void setup_http2_client_conn(void *goroutine_addr,
                                                    void *cc_ptr,
                                                    u32 stream_id,
                                                    go_offset_const off_cc_tconn_pos,
                                                    go_offset_const off_cc_framer_pos) {
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    void *parent_go = (void *)find_parent_goroutine_in_chain(&g_key);

    bpf_dbg_printk("goroutine_addr=%lx, parent_go=%lx", goroutine_addr, parent_go);

    // We should find a parent always
    if (parent_go && (u64)parent_go != k_go_parent_error) {
        goroutine_addr = parent_go;
        go_addr_key_from_id(&g_key, goroutine_addr);
    }
    go_exact_process_addr_key_t exact_g_key = {};
    if (!go_exact_process_addr_key_from_address(&exact_g_key, &g_key)) {
        return;
    }

    off_table_t *ot = get_offsets_table();

    if (cc_ptr) {
        const u64 cc_tconn_pos = go_offset_of(ot, (go_offset){.v = off_cc_tconn_pos});
        bpf_dbg_printk("cc_ptr=%llx, cc_tconn_ptr=%llx", cc_ptr, cc_ptr + cc_tconn_pos);
        void *tconn = cc_ptr + go_offset_of(ot, (go_offset){.v = off_cc_tconn_pos});
        bpf_probe_read(
            &tconn, sizeof(tconn), (void *)(cc_ptr + cc_tconn_pos + k_go_iface_data_offset));
        bpf_dbg_printk("tconn=%llx", tconn);

        if (tconn) {
            void *tconn_conn = 0;
            bpf_probe_read(
                &tconn_conn, sizeof(tconn_conn), (void *)(tconn + k_go_iface_data_offset));
            bpf_dbg_printk("tconn_conn=%llx", tconn_conn);

            connection_info_t conn = {0};
            const u8 ok = get_conn_info(tconn_conn, &conn);

            if (ok) {
                bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

                bpf_map_update_elem(&ongoing_client_connections, &exact_g_key, &conn, BPF_ANY);
                connection_info_t sorted_conn = conn;
                sort_connection_info(&sorted_conn);
                bpf_map_update_elem(
                    &go_http2_client_connections, &sorted_conn, &(bool){true}, BPF_ANY);
                store_go_handled_connection_info_sorted(&sorted_conn);
                cleanup_ongoing_large_buffer_sorted_conn(&sorted_conn, stream_id);
            }
        }

        if (g_bpf_header_propagation) {
            void *framer = 0;
            bpf_probe_read(
                &framer,
                sizeof(framer),
                (void *)(cc_ptr + go_offset_of(ot, (go_offset){.v = off_cc_framer_pos})));

            bpf_dbg_printk("cc_ptr=%llx, stream_id=%d, framer=%llx", cc_ptr, stream_id, framer);
            if (stream_id && framer) {
                stage_http2_client_stream(framer, stream_id, &exact_g_key);
            }
        }
    }
}

SEC("uprobe/http2RoundTrip")
int obi_uprobe_http2RoundTrip(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/http2RoundTrip ===");
    // we use the usual start helper, just like for normal http calls, but we later save
    // more context, like the streamID
    roundTripStartHelper(ctx);

    return 0;
}

// This runs on separate go routine called from the round tripper, but we need it
// to establish the correct connection information and stream_id
SEC("uprobe/http2WriteHeaders")
int obi_uprobe_http2WriteHeaders(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    void *cc_ptr = GO_PARAM1(ctx);
    const u64 stream_id = (u64)GO_PARAM2(ctx);

    bpf_dbg_printk("=== uprobe/http2WriteHeaders ===");

    setup_http2_client_conn(goroutine_addr, cc_ptr, (u32)stream_id, _cc_tconn_pos, _cc_framer_pos);

    return 0;
}

// This runs on separate go routine called from the round tripper, but we need it
// to establish the correct connection information and stream_id. The Go vendored
// version has its own offsets.
SEC("uprobe/http2WriteHeadersVendored")
int obi_uprobe_http2WriteHeaders_vendored(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    void *cc_ptr = GO_PARAM1(ctx);
    const u64 stream_id = (u64)GO_PARAM2(ctx);

    bpf_dbg_printk("=== uprobe/http2WriteHeadersVendored ===");

    setup_http2_client_conn(
        goroutine_addr, cc_ptr, (u32)stream_id, _cc_tconn_vendored_pos, _cc_framer_vendored_pos);

    return 0;
}

static __noinline void
on_http2FramerWriteHeaders(struct pt_regs *ctx, off_table_t *ot, u64 stream_id) {
    if (!g_bpf_header_propagation) {
        return;
    }

    void *framer = GO_PARAM1(ctx);

    if (!framer) {
        bpf_dbg_printk("framer is nil");
        return;
    }

    const u64 framer_w_pos = go_offset_of(ot, (go_offset){.v = _framer_w_pos});

    if (framer_w_pos == -1) {
        bpf_dbg_printk("framer w not found");
        return;
    }

    bpf_dbg_printk("framer=%llx, stream_id=%llu", framer, stream_id);

    go_exact_process_addr_key_t g_key = {};
    if (take_http2_client_stream(framer, (u32)stream_id, &g_key)) {
        bpf_dbg_printk("Found existing stream data, go_addr=%llx", g_key.address.addr);

        http_func_invocation_t *info =
            bpf_map_lookup_elem(&go_ongoing_http_client_requests, &g_key);

        if (info) {
            bpf_dbg_printk("Found func info: %llx", info);
            void *goroutine_addr = GOROUTINE_PTR(ctx);
            go_addr_key_t writer_key = {};
            go_addr_key_from_id(&writer_key, goroutine_addr);

            go_hpack_block_t *app_traceparent = go_hpack_block_scratch_mem();
            if (!app_traceparent) {
                clear_go_hpack_traceparent(&writer_key);
                return;
            }
            __builtin_memset(app_traceparent, 0, sizeof(*app_traceparent));
            const u8 traceparent_class = read_go_hpack_traceparent(&writer_key, app_traceparent);
            const u8 can_inject_traceparent = go_hpack_can_inject_traceparent(traceparent_class);
            clear_go_hpack_traceparent(&writer_key);
            if (traceparent_class == k_go_hpack_traceparent_authoritative) {
                go_hpack_adopt_traceparent(&info->tp, app_traceparent);
            }

            connection_info_t *conn = bpf_map_lookup_elem(&ongoing_client_connections, &g_key);
            if (conn) {
                pid_connection_info_t p_conn = {
                    .conn = *conn,
                    .pid = (u32)g_key.address.pid,
                };
                sort_connection_info(&p_conn.conn);
                mark_go_h2_client_conn(&p_conn);
            }
            const u8 should_publish =
                can_inject_traceparent || traceparent_class == k_go_hpack_traceparent_authoritative;
            framer_func_invocation_t *framer_scratch = http2_client_framer_mem();
            if (!framer_scratch) {
                return;
            }
            __builtin_memset(framer_scratch, 0, sizeof(*framer_scratch));
            u8 handoff_reserved = 0;
            if (should_publish) {
                handoff_reserved = publish_go_hpack_traceparent(conn,
                                                                (u32)stream_id,
                                                                &info->tp,
                                                                (u32)g_key.address.pid,
                                                                &g_key.address,
                                                                &framer_scratch->handoff_token);
            }

            // Retain the pre-TLS mutation path only after WriteField proved
            // that this request block has no traceparent and an exact
            // reservation exists for this stream.
            void *w_ptr = 0;
            bpf_probe_read(
                &w_ptr, sizeof(w_ptr), (void *)(framer + framer_w_pos + k_go_iface_data_offset));
            if (w_ptr && conn && can_inject_traceparent && handoff_reserved) {
                s64 n = 0;
                const u64 io_writer_n_pos = go_offset_of(ot, (go_offset){.v = _io_writer_n_pos});
                if (io_writer_n_pos &&
                    bpf_probe_read(&n, sizeof(n), (void *)(w_ptr + io_writer_n_pos)) == 0 &&
                    n < MAX_W_PTR_N) {
                    framer_func_invocation_t *f_info = framer_scratch;
                    if (f_info) {
                        f_info->framer_ptr = (u64)framer;
                        f_info->tp = info->tp;
                        f_info->egress =
                            make_egress_key(conn, (u32)g_key.address.pid, (u32)stream_id);
                        f_info->initial_n = n;
                        f_info->handoff_expected = 1;
                        go_addr_key_t f_key = {};
                        go_addr_key_from_id(&f_key, goroutine_addr);
                        bpf_map_update_elem(&framer_invocation_map, &f_key, f_info, BPF_ANY);
                    }
                }
            }
        }
    }
}

SEC("uprobe/golang_http2FramerWriteHeaders")
int obi_uprobe_golang_http2FramerWriteHeaders(struct pt_regs *ctx) {
    if (!g_bpf_header_propagation) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();

    const u64 stream_id = golang_stream_id(ctx, ot);

    if (stream_id == 0) {
        return 0;
    }
    bpf_dbg_printk("=== uprobe/golang_http2FramerWriteHeaders ===");
    on_http2FramerWriteHeaders(ctx, ot, stream_id);

    return 0;
}

SEC("uprobe/net_http2FramerWriteHeaders")
int obi_uprobe_net_http2FramerWriteHeaders(struct pt_regs *ctx) {
    if (!g_bpf_header_propagation) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();

    const u64 stream_id = (u64)GO_PARAM2(ctx);

    bpf_dbg_printk("=== uprobe/net_http2FramerWriteHeaders ===");
    on_http2FramerWriteHeaders(ctx, ot, stream_id);

    return 0;
}

SEC("uprobe/http2FramerWriteHeaders_returns")
int obi_uprobe_http2FramerWriteHeaders_returns(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);
    clear_go_hpack_traceparent(&g_key);

    if (!g_bpf_header_propagation) {
        return 0;
    }

    u8 handoff_claimed = 0;
    framer_func_invocation_t *f_info = bpf_map_lookup_elem(&framer_invocation_map, &g_key);
    if (!f_info || !f_info->handoff_expected) {
        goto done;
    }

    tp_info_pid_t snapshot = {};
    handoff_claimed = claim_outgoing_trace_handoff(&f_info->egress,
                                                   &f_info->handoff_token,
                                                   f_info->egress.pid,
                                                   EVENT_HTTP_CLIENT,
                                                   NULL,
                                                   0,
                                                   1,
                                                   &snapshot);
    if (!handoff_claimed || snapshot.written != k_outbound_trace_pending ||
        !outgoing_trace_identity_matches_tp(
            &snapshot, &f_info->tp, f_info->egress.pid, EVENT_HTTP_CLIENT)) {
        goto done;
    }

    off_table_t *ot = get_offsets_table();
    const u64 framer_w_pos = go_offset_of(ot, (go_offset){.v = _framer_w_pos});
    const u64 io_writer_n_pos = go_offset_of(ot, (go_offset){.v = _io_writer_n_pos});
    const u64 io_writer_buf_ptr_pos = go_offset_of(ot, (go_offset){.v = _io_writer_buf_ptr_pos});
    if (!framer_w_pos || !io_writer_n_pos || !io_writer_buf_ptr_pos) {
        goto done;
    }

    void *w_ptr = 0;
    if (bpf_probe_read(&w_ptr,
                       sizeof(w_ptr),
                       (void *)(f_info->framer_ptr + framer_w_pos + k_go_iface_data_offset)) ||
        !w_ptr) {
        goto done;
    }

    void *buf_arr = 0;
    s64 n = 0;
    s64 cap = 0;
    s64 initial_n = f_info->initial_n;
    if (bpf_probe_read(&buf_arr, sizeof(buf_arr), (void *)(w_ptr + io_writer_buf_ptr_pos)) ||
        bpf_probe_read(&n, sizeof(n), (void *)(w_ptr + io_writer_n_pos)) ||
        bpf_probe_read(&cap, sizeof(cap), (void *)(w_ptr + io_writer_buf_ptr_pos + 16))) {
        goto done;
    }

    bpf_clamp_umax(initial_n, MAX_W_PTR_N);
    if (!buf_arr || n < 0 || n >= 65535 || cap < k_h2_tp_hpack_huffman_size ||
        n > cap - k_h2_tp_hpack_huffman_size) {
        goto done;
    }

    u8 size_1 = 0;
    u8 size_2 = 0;
    u8 size_3 = 0;
    if (bpf_probe_read(&size_1, sizeof(size_1), (void *)(buf_arr + initial_n)) ||
        bpf_probe_read(&size_2, sizeof(size_2), (void *)(buf_arr + initial_n + 1)) ||
        bpf_probe_read(&size_3, sizeof(size_3), (void *)(buf_arr + initial_n + 2))) {
        goto done;
    }

    const u32 original_size = ((u32)size_1 << 16) | ((u32)size_2 << 8) | size_3;
    if (!original_size || (u64)n != (u64)initial_n + k_h2_frame_header_len + original_size) {
        goto done;
    }
    if (!h2_frame_can_append(original_size, k_h2_tp_hpack_huffman_size)) {
        goto done;
    }

    uint8_t tp_str[TP_MAX_VAL_LENGTH];
    u8 type_byte = 0;
    const u8 key_len = sizeof(tp_encoded) | 0x80;
    const u8 val_len = TP_MAX_VAL_LENGTH;
    make_tp_string(tp_str, &snapshot.tp);

    long werr = bpf_probe_write_user(buf_arr + (n & 0x0ffff), &type_byte, sizeof(type_byte));
    n++;
    if (!werr) {
        werr = bpf_probe_write_user(buf_arr + (n & 0x0ffff), &key_len, sizeof(key_len));
    }
    n++;
    if (!werr) {
        werr = bpf_probe_write_user(buf_arr + (n & 0x0ffff), tp_encoded, sizeof(tp_encoded));
    }
    n += sizeof(tp_encoded);
    if (!werr) {
        werr = bpf_probe_write_user(buf_arr + (n & 0x0ffff), &val_len, sizeof(val_len));
    }
    n++;
    if (!werr) {
        werr = bpf_probe_write_user(buf_arr + (n & 0x0ffff), tp_str, sizeof(tp_str));
    }
    n += TP_MAX_VAL_LENGTH;

    // Preserve the pre-existing publication order for Go TLS continuity.
    // A helper failure never commits the exact authority.
    if (!werr) {
        werr = bpf_probe_write_user((void *)(w_ptr + io_writer_n_pos), &n, sizeof(n));
    }
    const u32 new_size = original_size + k_h2_tp_hpack_huffman_size;
    size_1 = (u8)(new_size >> 16);
    size_2 = (u8)(new_size >> 8);
    size_3 = (u8)new_size;
    if (!werr) {
        werr = bpf_probe_write_user((void *)(buf_arr + initial_n), &size_1, sizeof(size_1));
    }
    if (!werr) {
        werr = bpf_probe_write_user((void *)(buf_arr + initial_n + 1), &size_2, sizeof(size_2));
    }
    if (!werr) {
        werr = bpf_probe_write_user((void *)(buf_arr + initial_n + 2), &size_3, sizeof(size_3));
    }

    if (!werr) {
        commit_claimed_outgoing_trace_handoff(&f_info->egress, &f_info->handoff_token);
        mirror_outgoing_trace_handoff_commit(&f_info->egress, &snapshot);
        handoff_claimed = 0;
    }

done:
    if (f_info && handoff_claimed) {
        release_claimed_outgoing_trace_handoff(&f_info->egress, &f_info->handoff_token);
    }
    bpf_map_delete_elem(&framer_invocation_map, &g_key);
    return 0;
}

SEC("uprobe/connServe")
int obi_uprobe_connServe(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/connServe goroutine_addr=%lx ===", goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    connection_info_t conn = {0};
    go_server_connection_clear(&g_key);
    go_server_connection_store_current(&g_key, &conn);

    return 0;
}

SEC("uprobe/jsonrpcReadRequestHeader")
int obi_uprobe_jsonrpcReadRequestHeader(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/jsonrpcReadRequestHeader ===");
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        go_http_server_invocation_lookup_current(&ongoing_http_server_requests, &g_key);
    if (!invocation) {
        return 0;
    }
    const u64 rpc_request_addr = (u64)GO_PARAM2(ctx);
    bpf_dbg_printk("rpc_request_addr=%llx", rpc_request_addr);
    invocation->rpc_request_addr = rpc_request_addr;

    return 0;
}

SEC("uprobe/jsonrpcReadRequestHeaderRet")
int obi_uprobe_jsonrpcReadRequestHeaderReturns(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/jsonrpcReadRequestHeaderRet ===");
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        go_http_server_invocation_lookup_current(&ongoing_http_server_requests, &g_key);

    if (!invocation || !invocation->rpc_request_addr) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();

    const u64 rpc_request_addr = invocation->rpc_request_addr;

    bpf_dbg_printk("rpc_request_addr=%llx", rpc_request_addr);

    const u64 method_len = peek_go_str_len(
        "JSON-RPC method",
        (void *)rpc_request_addr,
        go_offset_of(ot, (go_offset){.v = _jsonrpc_request_header_service_method_pos}));

    if (method_len == 0) {
        return 0;
    }

    if (!read_go_str("JSON-RPC method",
                     (void *)rpc_request_addr,
                     go_offset_of(ot, (go_offset){.v = _jsonrpc_request_header_service_method_pos}),
                     invocation->pattern,
                     k_pattern_max_len)) {
        bpf_dbg_printk("Failed to read JSON-RPC method from: %llx", rpc_request_addr);
        return 0;
    }
    bpf_dbg_printk("read jsonrpc method: %s", invocation->pattern);
    invocation->is_jsonrpc = true;

    return 0;
}

SEC("uprobe/connServeRet")
int obi_uprobe_connServeRet(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/connServeRet ===");
    void *goroutine_addr = GOROUTINE_PTR(ctx);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    go_http_server_close_prehandler_state(
        &http1_server_handoffs, &ongoing_http_server_requests, &g_key);
    bpf_map_delete_elem(&ongoing_server_bufr, &g_key);
    bpf_map_delete_elem(&ongoing_server_connections, &g_key);
    go_http_server_retire_go_trace(&g_key);
    obi_ctx__del(bpf_get_current_pid_tgid());

    return 0;
}

SEC("uprobe/persistConnRoundTrip")
int obi_uprobe_persistConnRoundTrip(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/persistConnRoundTrip ===");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    off_table_t *ot = get_offsets_table();

    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);
    go_exact_process_addr_key_t exact_g_key = {};
    if (!go_exact_process_addr_key_from_address(&exact_g_key, &g_key)) {
        return 0;
    }

    http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&go_ongoing_http_client_requests, &exact_g_key);
    if (!invocation) {
        bpf_dbg_printk("can't find invocation info for client call, this might be a bug");
        return 0;
    }

    void *pc_ptr = GO_PARAM1(ctx);
    if (pc_ptr) {
        if (g_bpf_header_propagation && invocation->header_addr) {
            stage_http1_header_request((void *)invocation->header_addr, pc_ptr, &exact_g_key);
        }
        void *conn_conn_ptr = pc_ptr + k_go_iface_data_offset +
                              go_offset_of(ot, (go_offset){.v = _pc_conn_pos}); // embedded struct
        void *tls_state = 0;
        bpf_probe_read(
            &tls_state,
            sizeof(tls_state),
            (void *)(pc_ptr + go_offset_of(ot, (go_offset){.v = _pc_tls_pos}))); // find tlsState
        bpf_dbg_printk("conn_conn_ptr=%llx, tls_state=%llx", conn_conn_ptr, tls_state);

        conn_conn_ptr = unwrap_tls_conn_info(conn_conn_ptr, tls_state);

        if (conn_conn_ptr) {
            void *conn_ptr = 0;
            bpf_probe_read(
                &conn_ptr,
                sizeof(conn_ptr),
                (void *)(conn_conn_ptr +
                         go_offset_of(ot, (go_offset){.v = _net_conn_pos}))); // find conn
            bpf_dbg_printk("conn_ptr=%llx", conn_ptr);
            if (conn_ptr) {
                connection_info_t conn = {0};
                get_conn_info(
                    conn_ptr,
                    &conn); // initialized to 0, no need to check the result if we succeeded
                const u64 pid_tid = bpf_get_current_pid_tgid();
                const u32 pid = pid_from_pid_tgid(pid_tid);
                tp_info_pid_t tp_p = {
                    .pid = pid,
                    .valid = 1,
                    .written = 0,
                    .req_type = EVENT_HTTP_CLIENT,
                };

                tp_clone(&tp_p.tp, &invocation->tp);
                tp_p.tp.ts = bpf_ktime_get_ns();
                bpf_dbg_printk("storing trace_map info for black-box tracing");
                bpf_map_update_elem(&ongoing_client_connections, &exact_g_key, &conn, BPF_ANY);

                connection_info_t sorted_conn = conn;
                sort_connection_info(&sorted_conn);
                store_go_handled_connection_info_sorted(&sorted_conn);
                cleanup_ongoing_large_buffer_sorted_conn(&sorted_conn, 0);

                // Must sort the connection info, this map is shared with kprobes which use sorted connection
                // info always.
                sort_connection_info(&conn);
                set_trace_info_for_connection(&conn, TRACE_TYPE_CLIENT, &tp_p);

                // Setup information for the TC context propagation.
                // We need the PID id to be able to query ongoing_http and update
                // the span id with the SEQ/ACK pair.

                const egress_key_t e_key = make_egress_key(&conn, pid, 0);
                outgoing_trace_token_t handoff_token = {};
                u8 handoff_reserved = reserve_outgoing_trace_handoff(&e_key, &tp_p, &handoff_token);
                if (handoff_reserved &&
                    !register_go_outgoing_trace_handoff(&g_key, &e_key, &handoff_token)) {
                    request_outgoing_trace_handoff_retirement(&e_key, &handoff_token, &tp_p, 1);
                    handoff_reserved = 0;
                }

                if (handoff_reserved && tls_state) {
                    // Clone and mark it invalid for the purpose of storing it in the
                    // outgoing trace map, if it's an SSL connection
                    tp_info_pid_t tp_p_invalid = {0};
                    __builtin_memcpy(&tp_p_invalid, &tp_p, sizeof(tp_p));
                    tp_p_invalid.valid = 0;
                    bpf_map_update_elem(&outgoing_trace_map, &e_key, &tp_p_invalid, BPF_NOEXIST);
                } else if (handoff_reserved) {
                    bpf_map_update_elem(&outgoing_trace_map, &e_key, &tp_p, BPF_NOEXIST);
                }

                bpf_map_update_elem(&go_ongoing_http, &e_key, &g_key, BPF_ANY);
            }
        }
    }

    return 0;
}
