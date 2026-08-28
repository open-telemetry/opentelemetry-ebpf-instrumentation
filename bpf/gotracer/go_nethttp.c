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
#include <common/http_types.h>
#include <common/preempt_guard.h>
#include <common/protocol_defs.h>
#include <common/ringbuf.h>
#include <common/scratch_mem.h>
#include <common/strings.h>
#include <common/tracing.h>
#include <common/trace_helpers.h>

#include <gotracer/go_common.h>
#include <gotracer/go_h2_write.h>
#include <gotracer/go_large_buffer.h>
#include <gotracer/go_offsets.h>
#include <gotracer/go_str.h>

#include <gotracer/maps/go_persist_conn.h>
#include <gotracer/maps/nethttp.h>

#include <gotracer/types/nethttp.h>
#include <gotracer/types/stream_key.h>

#include <logger/bpf_dbg.h>

#include <maps/go_ongoing_http.h>
#include <maps/go_ongoing_http_client_requests.h>
#include <maps/go_h2_owned_streams.h>
#include <maps/outgoing_trace_map.h>
#include <maps/tp_char_buf_mem.h>

#include <pid/pid_helpers.h>

#include <shared/obi_ctx.h>

static __always_inline unsigned char *temp_header_mem() {
    const u32 zero = 0;
    return bpf_map_lookup_elem(&temp_header_mem_store, &zero);
}

SCRATCH_MEM_TYPED(serve_http_inv, server_http_func_invocation_t)
SCRATCH_MEM_TYPED(round_trip_client_data, http_client_data_t)

/* HTTP Server */

// This instrumentation attaches uprobe to the following function:
// func (mux *ServeMux) ServeHTTP(w ResponseWriter, r *Request)
// or other functions sharing the same signature (e.g http.Handler.ServeHTTP)
SEC("uprobe/ServeHTTP")
int GUARDED_PROG(obi_uprobe_ServeHTTP, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/ServeHTTP ===");
    void *goroutine_addr = GOROUTINE_PTR(ctx);

    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    void *req = GO_PARAM4(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    off_table_t *ot = get_offsets_table();

    // Lookup any header information setup for us by readContinuedLineSlice
    server_http_func_invocation_t *header_inv =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);
    tp_info_t *decoded_tp = 0;
    if (header_inv && valid_trace(header_inv->tp.trace_id)) {
        decoded_tp = &header_inv->tp;
    }

    server_http_func_invocation_t *invocation = serve_http_inv_mem();
    if (!invocation) {
        goto done;
    }

    bpf_memset(invocation, 0, sizeof(*invocation));
    invocation->start_monotime_ns = bpf_ktime_get_ns();

    if (req) {
        server_trace_parent(goroutine_addr, &invocation->tp, decoded_tp);
        // TODO: if context propagation is supported, overwrite the header value in the map with the
        // new span context and the same thread id.

        // Get method from Request.Method
        if (!read_go_str("method",
                         req,
                         go_offset_of(ot, (go_offset){.v = _method_ptr_pos}),
                         invocation->method,
                         sizeof(invocation->method))) {
            bpf_dbg_printk("can't read http Request.Method");
            goto done;
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
            bpf_dbg_printk("can't read http Request.URL.Path");
            goto done;
        }

        // best-effort: the query string is optional, so a failed read must not
        // drop the event; the buffer stays zeroed and the span has no query
        read_go_str("raw_query",
                    url_ptr,
                    go_offset_of(ot, (go_offset){.v = _raw_query_ptr_pos}),
                    invocation->raw_query,
                    sizeof(invocation->raw_query));

        bpf_dbg_printk("path=%s", invocation->path);
        bpf_dbg_printk("raw_query=%s", invocation->raw_query);

        res = bpf_probe_read(
            &invocation->content_length,
            sizeof(invocation->content_length),
            (void *)(req + go_offset_of(ot, (go_offset){.v = _content_length_ptr_pos})));
        if (res) {
            bpf_dbg_printk("can't read http Request.ContentLength");
            goto done;
        }
    } else {
        goto done;
    }

    // Write event
    if (bpf_map_update_elem(&ongoing_http_server_requests, &g_key, invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update map element");
    }

    obi_ctx__set(bpf_get_current_pid_tgid(), &invocation->tp);

done:
    return 0;
}

SEC("uprobe/findHandler")
int GUARDED_PROG(obi_uprobe_findHandlerRet, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/findHandler ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);

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
int GUARDED_PROG(obi_uprobe_muxSetMatch, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/muxSetMatch ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);

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
int GUARDED_PROG(obi_uprobe_ginGetValueRet, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/ginGetValue ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);

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
int GUARDED_PROG(obi_uprobe_readRequestStart, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/readRequest ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    off_table_t *ot = get_offsets_table();

    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    connection_info_t *existing = bpf_map_lookup_elem(&ongoing_server_connections, &g_key);

    // Populate connection info if: no entry exists yet, OR the entry was created by connServe
    // with zeroed ports
    if (!existing || (existing->d_port == 0 && existing->s_port == 0)) {
        void *c_ptr = GO_PARAM1(ctx);
        if (c_ptr) {
            void *conn_conn_ptr = c_ptr + k_go_iface_data_offset +
                                  go_offset_of(ot, (go_offset){.v = _c_rwc_pos}); // embedded struct
            void *tls_state = 0;
            bpf_probe_read(&tls_state,
                           sizeof(tls_state),
                           (void *)(c_ptr + go_offset_of(ot, (go_offset){.v = _c_tls_pos})));
            conn_conn_ptr = unwrap_tls_conn_info(conn_conn_ptr, tls_state);

            // Store TLS state in the server invocation so serve_http_returns
            // can populate the scheme field on the trace event.
            server_http_func_invocation_t *inv =
                bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);
            if (inv) {
                inv->is_tls = tls_state ? 1 : 0;
            }

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
                    bpf_map_update_elem(&ongoing_server_connections, &g_key, &conn, BPF_ANY);
                }
            }
        }
    }

    return 0;
}

SEC("uprobe/readRequest")
int GUARDED_PROG(obi_uprobe_readRequestReturns, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/readRequest ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    // This code is here for keepalive support on HTTP requests. Since the connection is not
    // established everytime, we set the initial goroutine start on the new read initiation.
    goroutine_metadata *g_metadata = bpf_map_lookup_elem(&ongoing_goroutines, &g_key);
    if (!g_metadata) {
        goroutine_metadata metadata = {
            .timestamp = bpf_ktime_get_ns(),
            .parent = g_key,
        };

        if (bpf_map_update_elem(&ongoing_goroutines, &g_key, &metadata, BPF_ANY)) {
            bpf_dbg_printk("can't update active goroutine");
        }
    } else {
        g_metadata->timestamp = bpf_ktime_get_ns();
    }

    return 0;
}

// Handles finding the connection information for http2 servers in grpc
SEC("uprobe/http2Server_processHeaders")
int GUARDED_PROG(obi_uprobe_http2Server_processHeaders, struct pt_regs *, ctx) {
    void *sc_ptr = GO_PARAM1(ctx);
    void *frame = GO_PARAM2(ctx);
    bpf_dbg_printk("=== uprobe/http2Server_processHeaders sc_ptr=%lx ===", sc_ptr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, sc_ptr);

    tp_info_t tp = {0};

    process_meta_frame_headers(frame, &tp);

    if (valid_trace(tp.trace_id)) {
        bpf_dbg_printk("found valid traceparent in http2 headers");
        bpf_map_update_elem(&http2_server_requests_tp, &g_key, &tp, BPF_ANY);
    }

    return 0;
}

static __always_inline void update_traceparent(server_http_func_invocation_t *inv,
                                               const unsigned char *header_start) {
    decode_go_traceparent(header_start, inv->tp.trace_id, inv->tp.parent_id, &inv->tp.flags);
    bpf_dbg_printk("Found traceparent in header, header_start=[%s]", header_start);
}

static __always_inline void handle_traceparent_header(server_http_func_invocation_t *inv,
                                                      go_addr_key_t *g_key,
                                                      unsigned char *traceparent_start) {
    if (inv) {
        if (!valid_trace(inv->tp.trace_id)) {
            update_traceparent(inv, traceparent_start);
        }
    } else {
        server_http_func_invocation_t *minimal_inv = serve_http_inv_mem();
        if (!minimal_inv) {
            return;
        }
        bpf_memset(minimal_inv, 0, sizeof(*minimal_inv));
        update_traceparent(minimal_inv, traceparent_start);
        bpf_map_update_elem(&ongoing_http_server_requests, g_key, minimal_inv, BPF_ANY);
        obi_ctx__set(bpf_get_current_pid_tgid(), &minimal_inv->tp);
    }
}

// Matches the header in the buffer and returns a pointer to the value part of the header.
static __always_inline unsigned char *match_header(
    const unsigned char *buf, u32 safe_len, const char *header, u32 header_len, u32 value_len) {
    if (safe_len >= header_len + value_len && stricmp((const char *)buf, header, header_len)) {
        return (unsigned char *)(buf + header_len);
    }
    return NULL;
}

SEC("uprobe/readMimeHeader")
int GUARDED_PROG(obi_uprobe_readMimeHeader, struct pt_regs *, ctx) {
    if (!g_bpf_loop_enabled) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/readMimeHeader === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);
    const connection_info_t *existing = bpf_map_lookup_elem(&ongoing_server_connections, &g_key);
    if (!existing) {
        return 0;
    }

    const void *reader = (const unsigned char *)GO_PARAM1(ctx);
    if (!reader) {
        return 0;
    }
    off_table_t *ot = get_offsets_table();

    void *r = 0;
    bpf_probe_read_user(
        &r, sizeof(void *), reader + go_offset_of(ot, (go_offset){.v = _text_reader_r_pos}));

    if (!r) {
        return 0;
    }

    // Cache the bufio.Reader so serve_http_returns can ship the request bytes.
    bpf_map_update_elem(&ongoing_server_bufr, &g_key, &r, BPF_ANY);

    bpf_dbg_printk("R=%llx, off=%d", r, go_offset_of(ot, (go_offset){.v = _buf_reader_buf_pos}));

    u64 len = 0;
    bpf_probe_read_user(
        &len, sizeof(u64), r + go_offset_of(ot, (go_offset){.v = _buf_reader_w_pos}));

    bpf_dbg_printk(
        "buf len=%d, off=%d", len, go_offset_of(ot, (go_offset){.v = _buf_reader_w_pos}));

    if (len == 0) {
        return 0;
    }

    void *arr = 0;
    bpf_probe_read_user(
        &arr, sizeof(void *), r + go_offset_of(ot, (go_offset){.v = _buf_reader_buf_pos}));

    if (!arr) {
        return 0;
    }

    server_http_func_invocation_t *inv = bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);

    unsigned char *buf = (unsigned char *)tp_char_buf_mem();
    if (!buf) {
        return 0;
    }

    bpf_clamp_umax(len, TRACE_BUF_SIZE);

    if (bpf_probe_read_user(buf, len, arr) != 0) {
        bpf_dbg_printk("failed to read MIME header buffer");
        return 0;
    }

    bpf_dbg_printk("buf=%s", buf);

    unsigned char *tp_ptr = bpf_strstr_tp_loop(buf, len);

    bpf_dbg_printk("tp=%llx", tp_ptr);

    if (!tp_ptr) {
        return 0;
    }

    tp_ptr += TP_MAX_KEY_LENGTH + 2;
    handle_traceparent_header(inv, &g_key, tp_ptr);
    return 0;
}

SEC("uprobe/readContinuedLineSlice")
int GUARDED_PROG(obi_uprobe_readContinuedLineSliceReturns, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/readContinuedLineSlice ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);
    connection_info_t *existing = bpf_map_lookup_elem(&ongoing_server_connections, &g_key);
    if (!existing) {
        return 0;
    }

    const u64 len = (u64)GO_PARAM2(ctx);
    const unsigned char *buf = (const unsigned char *)GO_PARAM1(ctx);

    unsigned char *temp = temp_header_mem();
    const u32 safe_len = min(k_http_header_max_len, len);
    if (!temp || bpf_probe_read_user(temp, safe_len, buf) != 0) {
        bpf_dbg_printk("failed to read buffer");
        return 0;
    };

    const u32 w3c_value_start = sizeof(traceparent) - 1;

    server_http_func_invocation_t *inv = bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);

    unsigned char *traceparent_start =
        match_header(temp, safe_len, traceparent, w3c_value_start, W3C_VAL_LENGTH);
    if (traceparent_start) {
        handle_traceparent_header(inv, &g_key, traceparent_start);
    }

    return 0;
}

static __always_inline int serve_http_returns(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);

    if (invocation == NULL) {
        void *parent_go = (void *)find_parent_goroutine(&g_key);
        if (parent_go) {
            bpf_dbg_printk("found parent goroutine for header, parent_go=%llx", parent_go);
            go_addr_key_t p_key = {};
            go_addr_key_from_id(&p_key, parent_go);
            invocation = bpf_map_lookup_elem(&ongoing_http_server_requests, &p_key);
            goroutine_addr = parent_go;
            g_key.addr = (u64)goroutine_addr;
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
    const connection_info_t *info = bpf_map_lookup_elem(&ongoing_server_connections, &g_key);
    if (info) {
        __builtin_memcpy(&conn, info, sizeof(connection_info_t));
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
    if (g_metadata) {
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
    __builtin_memcpy(trace->raw_query, invocation->raw_query, sizeof(trace->raw_query));
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
    bpf_map_delete_elem(&ongoing_server_bufr, &g_key);
    bpf_map_delete_elem(&ongoing_http_server_requests, &g_key);
    bpf_map_delete_elem(&go_trace_map, &g_key);
    obi_ctx__del(bpf_get_current_pid_tgid());
    return 0;
}

SEC("uprobe/ServeHTTP_ret")
int GUARDED_PROG(obi_uprobe_ServeHTTPReturns, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/ServeHTTP_ret ===");
    return serve_http_returns(ctx);
}

/* HTTP Client. We expect to see HTTP client in both HTTP server and gRPC server calls.*/
static __always_inline void roundTripStartHelper(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);

    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    void *req = GO_PARAM2(ctx);
    off_table_t *ot = get_offsets_table();

    http_func_invocation_t invocation = {.start_monotime_ns = bpf_ktime_get_ns(), .tp = {0}};

    client_trace_parent(goroutine_addr, &invocation.tp);

    http_client_data_t *trace = round_trip_client_data_mem();
    if (!trace) {
        return;
    }

    bpf_memset(trace, 0, sizeof(*trace));

    // Get method from Request.Method
    if (!read_go_str("method",
                     req,
                     go_offset_of(ot, (go_offset){.v = _method_ptr_pos}),
                     trace->method,
                     sizeof(trace->method))) {
        bpf_dbg_printk("can't read http Request.Method");
        return;
    }

    bpf_probe_read(&trace->content_length,
                   sizeof(trace->content_length),
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
                         trace->path,
                         sizeof(trace->path))) {
            bpf_dbg_printk("can't read http Request.URL.Path");
            return;
        }

        // best-effort: the query string is optional, so a failed read must not
        // drop the event; the buffer stays zeroed and the span has no query
        read_go_str("raw_query",
                    url_ptr,
                    go_offset_of(ot, (go_offset){.v = _raw_query_ptr_pos}),
                    trace->raw_query,
                    sizeof(trace->raw_query));

        if (!read_go_str("host",
                         url_ptr,
                         go_offset_of(ot, (go_offset){.v = _host_ptr_pos}),
                         trace->host,
                         sizeof(trace->host))) {
            bpf_dbg_printk("can't read http Request.URL.Host");
            return;
        }

        if (!read_go_str("scheme",
                         url_ptr,
                         go_offset_of(ot, (go_offset){.v = _scheme_ptr_pos}),
                         trace->scheme,
                         sizeof(trace->scheme))) {
            bpf_dbg_printk("can't read http Request.URL.Scheme");
            return;
        }
    }

    bpf_dbg_printk("path=%s", trace->path);
    bpf_dbg_printk("raw_query=%s", trace->raw_query);
    bpf_dbg_printk("host=%s", trace->host);
    bpf_dbg_printk("scheme=%s", trace->scheme);

    // Write event
    if (bpf_map_update_elem(&go_ongoing_http_client_requests, &g_key, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update http client map element");
    }

    bpf_map_update_elem(&ongoing_http_client_requests_data, &g_key, trace, BPF_ANY);

    if (g_bpf_header_propagation) {
        void *headers_ptr = 0;
        bpf_probe_read(&headers_ptr,
                       sizeof(headers_ptr),
                       (void *)(req + go_offset_of(ot, (go_offset){.v = _req_header_ptr_pos})));
        bpf_dbg_printk(
            "goroutine_addr=%lx, req=%llx, headers_ptr=%llx", goroutine_addr, req, headers_ptr);

        if (headers_ptr) {
            bpf_map_update_elem(&header_req_map, &headers_ptr, &goroutine_addr, BPF_ANY);
        }
    }
}

SEC("uprobe/roundTrip")
int GUARDED_PROG(obi_uprobe_roundTrip, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/roundTrip ===");
    roundTripStartHelper(ctx);
    return 0;
}

static __always_inline void cleanup_http2_owned_stream(const go_addr_key_t *g_key) {
    http2_owned_stream_ref_t *ref = bpf_map_lookup_elem(&http2_owned_stream_by_request, g_key);
    if (ref) {
        bpf_map_delete_elem(&go_h2_owned_streams, &ref->stream);
        bpf_map_delete_elem(&http2_owned_stream_by_request, g_key);
    }
}

SEC("uprobe/roundTrip_return")
int GUARDED_PROG(obi_uprobe_roundTripReturn, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/roundTrip_return ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    off_table_t *ot = get_offsets_table();

    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&go_ongoing_http_client_requests, &g_key);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read http invocation metadata");
        goto done;
    }

    http_client_data_t *data = bpf_map_lookup_elem(&ongoing_http_client_requests_data, &g_key);
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
    __builtin_memcpy(trace->raw_query, data->raw_query, sizeof(trace->raw_query));
    __builtin_memcpy(trace->host, data->host, sizeof(trace->host));
    __builtin_memcpy(trace->scheme, data->scheme, sizeof(trace->scheme));
    trace->content_length = data->content_length;

    // Get request/response struct

    void *resp_ptr = (void *)GO_PARAM1(ctx);

    connection_info_t *info = bpf_map_lookup_elem(&ongoing_client_connections, &g_key);
    if (info) {
        __builtin_memcpy(&trace->conn, info, sizeof(connection_info_t));

        egress_key_t e_key = {
            .d_port = info->d_port,
            .s_port = info->s_port,
        };
        bpf_map_delete_elem(&outgoing_trace_map, &e_key);
        bpf_map_delete_elem(&go_ongoing_http, &e_key);
    } else {
        // persistConn.conn was unreadable, so take the connection the write side read
        // from the netFD instead of reporting this call without a peer.
        connection_info_t *published = persist_conn_lookup(&g_key);
        if (published) {
            bpf_memcpy(&trace->conn, published, sizeof(connection_info_t));
        } else {
            bpf_memset(&trace->conn, 0, sizeof(connection_info_t));
        }
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
    cleanup_http2_owned_stream(&g_key);
    bpf_map_delete_elem(&go_ongoing_http_client_requests, &g_key);
    bpf_map_delete_elem(&ongoing_http_client_requests_data, &g_key);
    bpf_map_delete_elem(&ongoing_client_connections, &g_key);
    bpf_map_delete_elem(&go_persist_conn_request, &g_key);
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
    u64 req_goaddr; // request (parent) goroutine, key into ongoing_client_connections
    tp_info_t tp;
    s64 entry_n; // io.Writer write offset at entry (start of this header block)
} write_subset_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // the writeSubset goroutine
    __type(value, write_subset_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_write_subsets SEC(".maps");

SEC("uprobe/header_writeSubset")
int GUARDED_PROG(obi_uprobe_writeSubset, struct pt_regs *, ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);

    go_addr_key_t gw_key = {};
    go_addr_key_from_id(&gw_key, goroutine_addr);

    if (!g_bpf_header_propagation) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/header_writeSubset ===");

    void *header_addr = GO_PARAM1(ctx);
    void *io_writer_addr = GO_PARAM3(ctx);

    bpf_dbg_printk("goroutine_addr=%lx, header_addr=%llx", goroutine_addr, header_addr);

    // we don't want to run this code when the header or the buffer is nil
    if (!header_addr || !io_writer_addr) {
        goto done;
    }

    off_table_t *ot = get_offsets_table();

    u64 *request_goaddr = bpf_map_lookup_elem(&header_req_map, &header_addr);

    if (!request_goaddr) {
        bpf_dbg_printk("Can't find parent go routine for header, header_addr=%llx", header_addr);
        return 0;
    }
    u64 parent_goaddr = *request_goaddr;
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, (void *)parent_goaddr);

    http_func_invocation_t *func_inv =
        bpf_map_lookup_elem(&go_ongoing_http_client_requests, &g_key);
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

    write_subset_invocation_t inv = {
        .io_writer_addr = (u64)io_writer_addr,
        .req_goaddr = parent_goaddr,
        .tp = func_inv->tp,
        .entry_n = entry_n,
    };
    bpf_map_update_elem(&ongoing_write_subsets, &gw_key, &inv, BPF_ANY);

done:
    bpf_map_delete_elem(&header_req_map, &header_addr);
    return 0;
}

// client_request_has_traceparent scans the header block that writeSubset just
// serialized ([entry_n, return_n)) for an existing traceparent header, reusing
// the same primitive as the server-side extraction. All offsets are validated
// and the scan is clamped to both the scratch buffer and the bytes actually
// present in the writer buffer, so the read can never run past the buffer.
// tp_loop_fn selects the scan implementation (bpf_loop vs legacy) at load time.
static __always_inline bool
client_request_has_traceparent(void *buf_ptr,
                               s64 entry_n,
                               s64 return_n,
                               s64 size,
                               unsigned char *(*tp_loop_fn)(unsigned char *, const u16)) {
    if (entry_n < 0 || return_n <= entry_n || return_n > size) {
        return false;
    }

    unsigned char *scan = (unsigned char *)tp_char_buf_mem();
    if (!scan) {
        return false;
    }

    // region = bytes writeSubset wrote; return_n <= size guarantees it stays
    // within the buffer. Clamp to the scratch buffer capacity as well.
    s64 region = return_n - entry_n;

    // this check is redundant but otherwise the verifier complains
    if (region <= 0) {
        return false;
    }
    bpf_clamp_umax(region, TRACE_BUF_SIZE - 1);
    const u32 uregion = (u32)region;
    if (bpf_probe_read_user(scan, uregion, (void *)(buf_ptr + (u32)entry_n)) != 0) {
        return false;
    }
    scan[uregion] = '\0';

    // Direct (not indirect) calls so the untaken branch is const-folded away per
    // program instantiation, keeping the bpf_loop subprog out of the legacy one.
    unsigned char *found = NULL;
    if (tp_loop_fn == bpf_strstr_tp_loop) {
        found = bpf_strstr_tp_loop(scan, (u16)uregion);
    } else {
        found = bpf_strstr_tp_loop__legacy(scan, (u16)uregion);
    }
    return found != NULL;
}

static __always_inline int on_writeSubset_returns(struct pt_regs *ctx,
                                                  unsigned char *(*tp_loop_fn)(unsigned char *,
                                                                               const u16)) {
    if (!g_bpf_header_propagation || !g_bpf_probe_write_user_enabled) {
        return 0;
    }

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t gw_key = {};
    go_addr_key_from_id(&gw_key, goroutine_addr);

    write_subset_invocation_t *inv = bpf_map_lookup_elem(&ongoing_write_subsets, &gw_key);
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
        goto done;
    }

    void *buf_ptr = 0;
    if (bpf_probe_read_user(
            &buf_ptr, sizeof(buf_ptr), (void *)(io_writer_addr + io_writer_buf_ptr_pos)) != 0 ||
        !buf_ptr) {
        goto done;
    }

    s64 size = 0; // len(buf) of the bufio.Writer; for bufio len == cap == capacity
    if (bpf_probe_read_user(
            &size,
            sizeof(size),
            (void *)(io_writer_addr + io_writer_buf_ptr_pos + k_go_slice_len_offset)) != 0) {
        goto done;
    }

    s64 len = 0; // current write offset (return position)
    if (bpf_probe_read_user(&len, sizeof(len), (void *)(io_writer_addr + io_writer_n_pos)) != 0) {
        goto done;
    }

    // Sanity-check the writer bounds before touching the buffer: a negative or
    // out-of-range write offset (e.g. after a bufio flush reset) means we can't
    // reason about the buffer, so skip rather than risk a bad access.
    if (size <= 0 || len < 0 || len > size) {
        goto done;
    }

    bpf_dbg_printk("buf_ptr=%llx, entry_n=%d, len=%d", (void *)buf_ptr, inv->entry_n, len);

    // If the application already wrote its own traceparent, don't add a second.
    if (client_request_has_traceparent(buf_ptr, inv->entry_n, len, size, tp_loop_fn)) {
        bpf_dbg_printk("client request already carries a traceparent, skipping injection");
        goto done;
    }

    unsigned char buf[k_traceparent_len];
    make_tp_string(buf, &inv->tp);

    if (len <
        (size - TP_MAX_VAL_LENGTH - TP_MAX_KEY_LENGTH - 4)) { // 4 = strlen(":_")+strlen("\r\n")
        char key[TP_MAX_KEY_LENGTH + 2] = "Traceparent: ";
        char end[2] = "\r\n";
        bpf_probe_write_user(buf_ptr + (len & 0x0ffff), key, sizeof(key));
        len += TP_MAX_KEY_LENGTH + 2;
        bpf_probe_write_user(buf_ptr + (len & 0x0ffff), buf, sizeof(buf));
        len += TP_MAX_VAL_LENGTH;
        bpf_probe_write_user(buf_ptr + (len & 0x0ffff), end, sizeof(end));
        len += 2;
        bpf_probe_write_user((void *)(io_writer_addr + io_writer_n_pos), &len, sizeof(len));

        // For Go we support two types of HTTP context propagation for now.
        //   1. The one that this code does, which uses the locked down bpf_probe_write_user.
        //   2. By using a sock_msg program that will extend the packet.
        // If this code ran, we should ensure that the second part doesn't run, therefore
        // we remove the metadata setup in uprobe_persistConnRoundTrip(struct pt_regs *ctx), so
        // that approach 2. skips this packet.
        go_addr_key_t g_key = {};
        go_addr_key_from_id(&g_key, (void *)inv->req_goaddr);
        connection_info_t *info = bpf_map_lookup_elem(&ongoing_client_connections, &g_key);
        if (info) {
            egress_key_t e_key = {
                .d_port = info->d_port,
                .s_port = info->s_port,
            };
            //dbg_print_http_connection_info(info);
            bpf_map_delete_elem(&outgoing_trace_map, &e_key);
            bpf_dbg_printk(
                "wrote traceparent using bpf_probe_write_user, removing outgoing trace map,"
                "s_port=%d, d_port=%d",
                e_key.s_port,
                e_key.d_port);
            store_go_handled_connection_info(info);
        }
    }

done:
    bpf_map_delete_elem(&ongoing_write_subsets, &gw_key);
    return 0;
}

// Two variants of the return probe: the default uses bpf_loop; the _legacy one
// uses a bounded scan for kernels without bpf_loop. FixupSpec swaps the default
// for the legacy on those kernels (and dummies the legacy elsewhere), mirroring
// obi_uprobe_readMimeHeader / obi_protocol_http. This keeps the bpf_loop subprog
// out of the program loaded on pre-5.17 kernels, which would otherwise reject it
// with "number of funcs in func_info doesn't match number of subprogs".
SEC("uprobe/header_writeSubset_returns")
int GUARDED_PROG(obi_uprobe_writeSubset_returns, struct pt_regs *, ctx) {
    return on_writeSubset_returns(ctx, bpf_strstr_tp_loop);
}

SEC("uprobe/header_writeSubset_returns_legacy")
int GUARDED_PROG(obi_uprobe_writeSubset_returns_legacy, struct pt_regs *, ctx) {
    return on_writeSubset_returns(ctx, bpf_strstr_tp_loop__legacy);
}

// HTTP 2.0 server support
SEC("uprobe/http2ResponseWriterStateWriteHeader")
int GUARDED_PROG(obi_uprobe_http2ResponseWriterStateWriteHeader, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/http2ResponseWriterStateWriteHeader ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    const u64 status = (u64)GO_PARAM2(ctx);
    bpf_dbg_printk("goroutine_addr=%lx, status=%d", goroutine_addr, status);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);

    if (invocation == NULL) {
        void *parent_go = (void *)find_parent_goroutine(&g_key);
        if (parent_go) {
            bpf_dbg_printk("found parent goroutine for header, parent_go=%llx", parent_go);
            go_addr_key_t p_key = {};
            go_addr_key_from_id(&p_key, parent_go);
            invocation = bpf_map_lookup_elem(&ongoing_http_server_requests, &p_key);
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
int GUARDED_PROG(obi_uprobe_http2serverConn_runHandler, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/http2serverConn_runHandler ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

    void *sc = GO_PARAM1(ctx);
    off_table_t *ot = get_offsets_table();

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    if (sc) {
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
                connection_info_t conn = {0};
                get_conn_info(conn_conn_ptr, &conn);
                bpf_map_update_elem(&ongoing_server_connections, &g_key, &conn, BPF_ANY);
            }
        }

        go_addr_key_t sc_key = {};
        go_addr_key_from_id(&sc_key, sc);

        tp_info_t *tp = bpf_map_lookup_elem(&http2_server_requests_tp, &sc_key);
        bpf_dbg_printk("looked up tp: %llx", tp);

        if (tp) {
            server_http_func_invocation_t *inv = serve_http_inv_mem();
            if (inv) {
                bpf_memset(inv, 0, sizeof(*inv));
                __builtin_memcpy(&inv->tp, tp, sizeof(tp_info_t));
                bpf_dbg_printk("Found traceparent in HTTP2 headers");
                bpf_map_update_elem(&ongoing_http_server_requests, &g_key, inv, BPF_ANY);
                obi_ctx__set(bpf_get_current_pid_tgid(), &inv->tp);
                bpf_map_delete_elem(&http2_server_requests_tp, &sc_key);
            }
        }
    }

    return 0;
}

static __always_inline void setup_http2_client_conn(void *goroutine_addr,
                                                    void *cc_ptr,
                                                    u32 stream_id,
                                                    go_offset_const off_cc_tconn_pos,
                                                    go_offset_const off_cc_tls_pos,
                                                    go_offset_const off_cc_framer_pos) {
    go_addr_key_t writer_key = {};
    go_addr_key_from_id(&writer_key, goroutine_addr);
    const u8 *observation = bpf_map_lookup_elem(&http2_header_observations, &writer_key);
    const bool app_owned = observation && *observation;

    go_addr_key_t g_key = writer_key;
    http2_owned_stream_ref_t owned_ref = {};
    bool owned_ref_published = false;

    void *parent_go = (void *)find_parent_goroutine_in_chain(&g_key);

    bpf_dbg_printk("goroutine_addr=%lx, parent_go=%lx", goroutine_addr, parent_go);

    // We should find a parent always
    if (parent_go) {
        goroutine_addr = parent_go;
        go_addr_key_from_id(&g_key, goroutine_addr);
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
            void *tls_state = 0;
            bpf_probe_read(&tls_state,
                           sizeof(tls_state),
                           (void *)(cc_ptr + go_offset_of(ot, (go_offset){.v = off_cc_tls_pos})));

            void *conn_ptr = tconn;
            if (tls_state) {
                bpf_probe_read(
                    &conn_ptr, sizeof(conn_ptr), (void *)(tconn + k_go_iface_data_offset));
            }
            bpf_dbg_printk("tls_state=%llx, conn_ptr=%llx", tls_state, conn_ptr);

            connection_info_t conn = {0};
            const u8 ok = get_conn_info(conn_ptr, &conn);

            if (ok) {
                bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

                if (app_owned && stream_id) {
                    owned_ref.stream.p_conn.conn = conn;
                    owned_ref.stream.p_conn.pid = pid_from_pid_tgid(bpf_get_current_pid_tgid());
                    owned_ref.stream.stream_id = stream_id;
                    set_go_h2_owned_stream_process_identity(&owned_ref.stream);

                    const u64 now = bpf_ktime_get_ns();
                    if (bpf_map_update_elem(
                            &go_h2_owned_streams, &owned_ref.stream, &now, BPF_ANY) == 0) {
                        owned_ref_published = true;
                        bpf_map_update_elem(
                            &http2_owned_stream_by_request, &g_key, &owned_ref, BPF_ANY);
                    }
                }

                bpf_map_update_elem(&ongoing_client_connections, &g_key, &conn, BPF_ANY);
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
                stream_key_t s_key = {
                    .stream_id = stream_id,
                };
                s_key.conn_ptr = (u64)framer;

                bpf_map_update_elem(&http2_req_map, &s_key, &goroutine_addr, BPF_ANY);
                if (owned_ref_published) {
                    bpf_map_update_elem(&http2_owned_stream_by_framer, &s_key, &owned_ref, BPF_ANY);
                }
            }
        }
    }
}

SEC("uprobe/http2ClientStreamEncodeAndWriteHeaders")
int GUARDED_PROG(obi_uprobe_http2ClientStreamEncodeAndWriteHeaders, struct pt_regs *, ctx) {
    if (!g_bpf_header_propagation) {
        return 0;
    }

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, GOROUTINE_PTR(ctx));
    const u8 not_owned = 0;
    bpf_map_update_elem(&http2_header_observations, &g_key, &not_owned, BPF_ANY);
    return 0;
}

SEC("uprobe/http2ClientStreamEncodeAndWriteHeaders_returns")
int GUARDED_PROG(obi_uprobe_http2ClientStreamEncodeAndWriteHeaders_returns, struct pt_regs *, ctx) {
    if (!g_bpf_header_propagation) {
        return 0;
    }

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, GOROUTINE_PTR(ctx));
    bpf_map_delete_elem(&http2_header_observations, &g_key);
    return 0;
}

SEC("uprobe/http2ClientConnWriteHeader")
int GUARDED_PROG(obi_uprobe_http2ClientConnWriteHeader, struct pt_regs *, ctx) {
    if (!g_bpf_header_propagation || (u64)GO_PARAM3(ctx) != W3C_KEY_LENGTH) {
        return 0;
    }

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, GOROUTINE_PTR(ctx));
    u8 *observation = bpf_map_lookup_elem(&http2_header_observations, &g_key);
    if (!observation) {
        return 0;
    }

    unsigned char name[W3C_KEY_LENGTH];
    if (bpf_probe_read_user(name, sizeof(name), (void *)GO_PARAM2(ctx)) == 0 &&
        stricmp((const char *)name, "traceparent", W3C_KEY_LENGTH)) {
        *observation = 1;
    }
    return 0;
}

SEC("uprobe/http2RoundTrip")
int GUARDED_PROG(obi_uprobe_http2RoundTrip, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/http2RoundTrip ===");
    // we use the usual start helper, just like for normal http calls, but we later save
    // more context, like the streamID
    roundTripStartHelper(ctx);

    return 0;
}

// This runs on separate go routine called from the round tripper, but we need it
// to establish the correct connection information and stream_id
SEC("uprobe/http2WriteHeaders")
int GUARDED_PROG(obi_uprobe_http2WriteHeaders, struct pt_regs *, ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    void *cc_ptr = GO_PARAM1(ctx);
    const u64 stream_id = (u64)GO_PARAM2(ctx);

    bpf_dbg_printk("=== uprobe/http2WriteHeaders ===");

    setup_http2_client_conn(
        goroutine_addr, cc_ptr, (u32)stream_id, _cc_tconn_pos, _cc_tls_pos, _cc_framer_pos);

    return 0;
}

// This runs on separate go routine called from the round tripper, but we need it
// to establish the correct connection information and stream_id. The Go vendored
// version has its own offsets.
SEC("uprobe/http2WriteHeadersVendored")
int GUARDED_PROG(obi_uprobe_http2WriteHeaders_vendored, struct pt_regs *, ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    void *cc_ptr = GO_PARAM1(ctx);
    const u64 stream_id = (u64)GO_PARAM2(ctx);

    bpf_dbg_printk("=== uprobe/http2WriteHeadersVendored ===");

    setup_http2_client_conn(goroutine_addr,
                            cc_ptr,
                            (u32)stream_id,
                            _cc_tconn_vendored_pos,
                            _cc_tls_vendored_pos,
                            _cc_framer_vendored_pos);

    return 0;
}

static __always_inline void
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

    stream_key_t s_key = {
        .stream_id = stream_id,
    };
    s_key.conn_ptr = (u64)framer;

    http2_owned_stream_ref_t *owned_ref =
        bpf_map_lookup_elem(&http2_owned_stream_by_framer, &s_key);
    const bool app_owned =
        owned_ref && fresh_go_h2_owned_stream(&owned_ref->stream, bpf_ktime_get_ns());
    bpf_map_delete_elem(&http2_owned_stream_by_framer, &s_key);
    if (app_owned) {
        bpf_map_delete_elem(&http2_req_map, &s_key);
        return;
    }

    void **go_ptr = bpf_map_lookup_elem(&http2_req_map, &s_key);

    if (go_ptr) {
        void *go_addr = *go_ptr;
        bpf_dbg_printk("Found existing stream data, go_addr=%llx", go_addr);
        go_addr_key_t g_key = {};
        go_addr_key_from_id(&g_key, go_addr);

        http_func_invocation_t *info =
            bpf_map_lookup_elem(&go_ongoing_http_client_requests, &g_key);
        connection_info_t *conn_info = bpf_map_lookup_elem(&ongoing_client_connections, &g_key);

        if (info) {
            bpf_dbg_printk("Found func info: %llx", info);
            void *goroutine_addr = GOROUTINE_PTR(ctx);

            void *w_ptr = 0;
            const long writer_err = bpf_probe_read_user(
                &w_ptr, sizeof(w_ptr), (void *)(framer + framer_w_pos + k_go_iface_data_offset));
            if (!writer_err && w_ptr) {
                s64 n = 0;
                const u64 n_pos = go_offset_of(ot, (go_offset){.v = _io_writer_n_pos});
                if (n_pos == (u64)-1 ||
                    bpf_probe_read_user(&n, sizeof(n), (void *)(w_ptr + n_pos)) != 0) {
                    goto cleanup;
                }

                bpf_dbg_printk("Found initial n=%d, framer=%llx", n, framer);

                // The offset is 0 on all connections we've tested with.
                // If we read some very large offset, we don't do anything since it might be a situation
                // we can't handle.
                if (n >= 0 && n < MAX_W_PTR_N) {
                    framer_func_invocation_t f_info = {
                        .tp = info->tp,
                        .framer_ptr = (u64)framer,
                        .initial_n = n,
                        .stream_id = (u32)stream_id,
                        .s_port = conn_info ? conn_info->s_port : 0,
                        .d_port = conn_info ? conn_info->d_port : 0,
                    };
                    go_addr_key_t f_key = {};
                    go_addr_key_from_id(&f_key, goroutine_addr);

                    bpf_map_update_elem(&framer_invocation_map, &f_key, &f_info, BPF_ANY);

                    if (conn_info && valid_trace(info->tp.trace_id)) {
                        tp_info_pid_t tp_p = {
                            .tp = info->tp,
                            .pid = pid_from_pid_tgid(bpf_get_current_pid_tgid()),
                            .valid = 1,
                            .written = 0,
                            .req_type = EVENT_HTTP_CLIENT,
                        };
                        egress_key_t e_key = {
                            .d_port = conn_info->d_port,
                            .s_port = conn_info->s_port,
                            .stream_id = (u32)stream_id,
                        };
                        sort_egress_key(&e_key);
                        bpf_map_update_elem(&outgoing_trace_map, &e_key, &tp_p, BPF_ANY);
                    }
                } else {
                    bpf_dbg_printk("N too large, ignoring...");
                }
            }
        }
    }

cleanup:
    bpf_map_delete_elem(&http2_req_map, &s_key);
}

SEC("uprobe/golang_http2FramerWriteHeaders")
int GUARDED_PROG(obi_uprobe_golang_http2FramerWriteHeaders, struct pt_regs *, ctx) {
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
int GUARDED_PROG(obi_uprobe_net_http2FramerWriteHeaders, struct pt_regs *, ctx) {
    if (!g_bpf_header_propagation) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();

    const u64 stream_id = (u64)GO_PARAM2(ctx);

    bpf_dbg_printk("=== uprobe/net_http2FramerWriteHeaders ===");
    on_http2FramerWriteHeaders(ctx, ot, stream_id);

    return 0;
}

static __always_inline void
make_http2_traceparent_field(unsigned char field[k_h2_tp_hpack_huffman_size], const tp_info_t *tp) {
    field[0] = 0;
    field[1] = sizeof(tp_encoded) | 0x80;
    __builtin_memcpy(field + 2, tp_encoded, sizeof(tp_encoded));
    field[2 + sizeof(tp_encoded)] = TP_MAX_VAL_LENGTH;
    make_tp_string(field + 3 + sizeof(tp_encoded), tp);
}

static __always_inline u32
http2_frame_stream_id(const unsigned char header[k_h2_frame_header_len]) {
    return ((u32)(header[5] & 0x7f) << 24) | ((u32)header[6] << 16) | ((u32)header[7] << 8) |
           header[8];
}

enum : u32 {
    k_h2_pad_length_to_stream_id_offset = 34,
    k_h2_pad_length_to_fragment_len_offset = 18,
    k_h2_pad_length_stack_offset_limit = 512,
};

static __always_inline int reserve_http2_framer_padding(struct pt_regs *ctx,
                                                        go_offset_const pad_offset) {
    if (!g_bpf_header_propagation || !g_bpf_probe_write_user_enabled) {
        return 0;
    }

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, GOROUTINE_PTR(ctx));
    framer_func_invocation_t *f_info = bpf_map_lookup_elem(&framer_invocation_map, &g_key);
    if (!f_info || f_info->reserved_padding) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();
    const u64 stack_offset = go_offset_of(ot, (go_offset){.v = pad_offset});
    if (stack_offset == (u64)-1 || stack_offset < k_h2_pad_length_to_stream_id_offset ||
        stack_offset >= k_h2_pad_length_stack_offset_limit) {
        return 0;
    }

    unsigned char *pad_ptr = (unsigned char *)PT_REGS_SP(ctx) + stack_offset;
    u32 stream_id = 0;
    u8 original_pad = 0;
    u64 fragment_len = 0;
    long err = bpf_probe_read_user(
        &stream_id, sizeof(stream_id), pad_ptr - k_h2_pad_length_to_stream_id_offset);
    err |= bpf_probe_read_user(&original_pad, sizeof(original_pad), pad_ptr);
    err |= bpf_probe_read_user(
        &fragment_len, sizeof(fragment_len), pad_ptr - k_h2_pad_length_to_fragment_len_offset);
    const u64 max_fragment =
        k_h2_default_max_frame_size - k_h2_tp_hpack_huffman_size - k_h2_priority_prefix_len - 1;
    if (err || !stream_id || stream_id != f_info->stream_id || original_pad ||
        fragment_len > max_fragment) {
        return 0;
    }

    const u64 framer_w_pos = go_offset_of(ot, (go_offset){.v = _framer_w_pos});
    if (framer_w_pos == (u64)-1) {
        return 0;
    }
    const u64 wbuf_pos = framer_w_pos + 2 * k_go_iface_data_offset;
    void *buf = 0;
    s64 n = 0;
    err = bpf_probe_read_user(&buf, sizeof(buf), (void *)(f_info->framer_ptr + wbuf_pos));
    err |= bpf_probe_read_user(
        &n, sizeof(n), (void *)(f_info->framer_ptr + wbuf_pos + k_go_slice_len_offset));
    if (err || !buf || n != k_h2_frame_header_len) {
        return 0;
    }

    unsigned char header[k_h2_frame_header_len] = {};
    if (bpf_probe_read_user(header, sizeof(header), buf) != 0 || header[3] != k_h2_frame_headers ||
        http2_frame_stream_id(header) != stream_id || !(header[4] & k_h2_flag_end_headers) ||
        (header[4] & k_h2_flag_padded)) {
        return 0;
    }

    const u8 padding = k_h2_tp_hpack_huffman_size;
    u8 pad_readback = 0;
    err = bpf_probe_write_user(pad_ptr, &padding, sizeof(padding));
    err |= bpf_probe_read_user(&pad_readback, sizeof(pad_readback), pad_ptr);
    if (err || pad_readback != padding) {
        return 0;
    }

    unsigned char *flags_ptr = (unsigned char *)buf + 4;
    const u8 padded_flags = header[4] | k_h2_flag_padded;
    u8 flags_readback = header[4];
    err = bpf_probe_write_user(flags_ptr, &padded_flags, sizeof(padded_flags));
    err |= bpf_probe_read_user(&flags_readback, sizeof(flags_readback), flags_ptr);
    if (!err && flags_readback == padded_flags) {
        f_info->reserved_padding = true;
        return 0;
    }

    const u8 no_padding = 0;
    bpf_probe_write_user(pad_ptr, &no_padding, sizeof(no_padding));
    bpf_probe_write_user(flags_ptr, &header[4], sizeof(header[4]));
    return 0;
}

SEC("uprobe/http2FramerReservePadding")
int GUARDED_PROG(obi_uprobe_http2FramerReservePadding, struct pt_regs *, ctx) {
    return reserve_http2_framer_padding(ctx, _framer_pad_length_stack_pos);
}

SEC("uprobe/http2FramerReservePaddingVendored")
int GUARDED_PROG(obi_uprobe_http2FramerReservePadding_vendored, struct pt_regs *, ctx) {
    return reserve_http2_framer_padding(ctx, _framer_pad_length_stack_vendored_pos);
}

static __always_inline bool
commit_http2_reserved_padding(void *buf, s64 n, const framer_func_invocation_t *f_info) {
    if (n < k_h2_frame_header_len + 1 + k_h2_tp_hpack_huffman_size ||
        (u64)n > k_h2_default_max_frame_size + k_h2_frame_header_len) {
        return false;
    }
    bpf_clamp_umax(n, k_h2_default_max_frame_size + k_h2_frame_header_len);

    unsigned char header[k_h2_frame_header_len] = {};
    if (bpf_probe_read_user(header, sizeof(header), buf) != 0 || header[3] != k_h2_frame_headers ||
        http2_frame_stream_id(header) != f_info->stream_id ||
        !(header[4] & k_h2_flag_end_headers) || !(header[4] & k_h2_flag_padded)) {
        return false;
    }

    unsigned char *pad_length_ptr = (unsigned char *)buf + k_h2_frame_header_len;
    u8 pad_length = 0;
    if (bpf_probe_read_user(&pad_length, sizeof(pad_length), pad_length_ptr) != 0 ||
        pad_length != k_h2_tp_hpack_huffman_size) {
        return false;
    }

    unsigned char field[k_h2_tp_hpack_huffman_size] = {};
    make_http2_traceparent_field(field, &f_info->tp);
    if (bpf_probe_write_user((unsigned char *)buf + (u64)n - k_h2_tp_hpack_huffman_size,
                             field,
                             sizeof(field)) != 0) {
        return false;
    }

    const u8 consumed_padding = 0;
    return bpf_probe_write_user(pad_length_ptr, &consumed_padding, sizeof(consumed_padding)) == 0;
}

static __always_inline bool append_http2_traceparent_to_framer(
    void *framer, u64 wbuf_pos, void *buf, s64 n, s64 cap, const framer_func_invocation_t *f_info) {
    if (n < k_h2_frame_header_len || cap < n ||
        (u64)n > k_h2_default_max_frame_size + k_h2_frame_header_len ||
        (u64)cap - (u64)n < k_h2_tp_hpack_huffman_size) {
        return false;
    }
    bpf_clamp_umax(n, k_h2_default_max_frame_size + k_h2_frame_header_len);

    unsigned char header[k_h2_frame_header_len] = {};
    if (bpf_probe_read_user(header, sizeof(header), buf) != 0 || header[3] != k_h2_frame_headers ||
        http2_frame_stream_id(header) != f_info->stream_id ||
        !(header[4] & k_h2_flag_end_headers) || (header[4] & k_h2_flag_padded)) {
        return false;
    }

    unsigned char field[k_h2_tp_hpack_huffman_size] = {};
    make_http2_traceparent_field(field, &f_info->tp);
    if (bpf_probe_write_user((unsigned char *)buf + (u64)n, field, sizeof(field)) != 0) {
        return false;
    }

    const s64 new_n = n + k_h2_tp_hpack_huffman_size;
    return bpf_probe_write_user((unsigned char *)framer + wbuf_pos + k_go_slice_len_offset,
                                &new_n,
                                sizeof(new_n)) == 0;
}

SEC("uprobe/http2FramerEndWrite")
int GUARDED_PROG(obi_uprobe_http2FramerEndWrite, struct pt_regs *, ctx) {
    if (!g_bpf_header_propagation || !g_bpf_probe_write_user_enabled) {
        return 0;
    }

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, GOROUTINE_PTR(ctx));
    framer_func_invocation_t *f_info = bpf_map_lookup_elem(&framer_invocation_map, &g_key);
    void *framer = GO_PARAM1(ctx);
    if (!f_info || !framer || f_info->framer_ptr != (u64)framer) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();
    const u64 framer_w_pos = go_offset_of(ot, (go_offset){.v = _framer_w_pos});
    if (framer_w_pos == (u64)-1) {
        return 0;
    }
    const u64 wbuf_pos = framer_w_pos + 2 * k_go_iface_data_offset;
    void *buf = 0;
    s64 n = 0;
    s64 cap = 0;
    long err = bpf_probe_read_user(&buf, sizeof(buf), (unsigned char *)framer + wbuf_pos);
    err |= bpf_probe_read_user(
        &n, sizeof(n), (unsigned char *)framer + wbuf_pos + k_go_slice_len_offset);
    err |= bpf_probe_read_user(
        &cap, sizeof(cap), (unsigned char *)framer + wbuf_pos + 2 * sizeof(void *));
    if (err || !buf) {
        return 0;
    }

    const bool committed =
        f_info->reserved_padding
            ? commit_http2_reserved_padding(buf, n, f_info)
            : append_http2_traceparent_to_framer(framer, wbuf_pos, buf, n, cap, f_info);
    if (committed) {
        bpf_map_delete_elem(&framer_invocation_map, &g_key);
    }
    return 0;
}

SEC("uprobe/http2FramerWriteHeaders_returns")
int GUARDED_PROG(obi_uprobe_http2FramerWriteHeaders_returns, struct pt_regs *, ctx) {
    if (!g_bpf_header_propagation || !g_bpf_probe_write_user_enabled) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/http2FramerWriteHeaders_returns ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    off_table_t *ot = get_offsets_table();
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    framer_func_invocation_t *f_info = bpf_map_lookup_elem(&framer_invocation_map, &g_key);

    if (f_info && !f_info->reserved_padding) {
        void *w_ptr = 0;
        const u64 framer_w_pos = go_offset_of(ot, (go_offset){.v = _framer_w_pos});
        const u64 io_writer_n_pos = go_offset_of(ot, (go_offset){.v = _io_writer_n_pos});

        // being defensive here if we can't find the offsets
        if (!framer_w_pos || !io_writer_n_pos || framer_w_pos == (u64)-1 ||
            io_writer_n_pos == (u64)-1) {
            goto done;
        }

        if (bpf_probe_read_user(
                &w_ptr,
                sizeof(w_ptr),
                (void *)(f_info->framer_ptr + framer_w_pos + k_go_iface_data_offset)) != 0) {
            goto done;
        }

        bpf_dbg_printk("framer_ptr=%llx, w_ptr=%llx, framer_w_pos=%d",
                       f_info->framer_ptr,
                       w_ptr,
                       framer_w_pos + k_go_iface_data_offset);

        if (w_ptr) {
            void *buf_arr = 0;
            s64 n = -1;
            s64 cap = -1;
            const u64 buf_pos = go_offset_of(ot, (go_offset){.v = _io_writer_buf_ptr_pos});
            if (buf_pos == (u64)-1) {
                goto done;
            }

            long read_err =
                bpf_probe_read_user(&buf_arr, sizeof(buf_arr), (void *)(w_ptr + buf_pos));
            read_err |= bpf_probe_read_user(&n, sizeof(n), (void *)(w_ptr + io_writer_n_pos));
            read_err |= bpf_probe_read_user(
                &cap, sizeof(cap), (void *)(w_ptr + buf_pos + 2 * sizeof(void *)));
            if (read_err) {
                goto done;
            }

            bpf_dbg_printk("Found f_info, this is the place to write to w_ptr=%llx, buf_arr=%llx",
                           w_ptr,
                           buf_arr);
            bpf_dbg_printk("Found f_info, this is the place to write to n=%lld, cap=%lld", n, cap);
            const u8 result = append_go_h2_traceparent(w_ptr,
                                                       io_writer_n_pos,
                                                       buf_arr,
                                                       f_info->initial_n,
                                                       n,
                                                       cap,
                                                       f_info->stream_id,
                                                       &f_info->tp);
            if (result == k_go_h2_user_write_uncertain) {
                bpf_dbg_printk("HTTP/2 traceparent write state is uncertain; failing closed");
            }
            if ((result == k_go_h2_user_write_committed ||
                 result == k_go_h2_user_write_uncertain) &&
                (f_info->s_port || f_info->d_port)) {
                egress_key_t e_key = {
                    .d_port = f_info->d_port,
                    .s_port = f_info->s_port,
                    .stream_id = f_info->stream_id,
                };
                sort_egress_key(&e_key);
                tp_info_pid_t *tp_p = bpf_map_lookup_elem(&outgoing_trace_map, &e_key);
                if (tp_p) {
                    tp_p->written = 1;
                }
            }
        }
    }

done:
    bpf_map_delete_elem(&framer_invocation_map, &g_key);
    return 0;
}

SEC("uprobe/connServe")
int GUARDED_PROG(obi_uprobe_connServe, struct pt_regs *, ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/connServe goroutine_addr=%lx ===", goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    connection_info_t conn = {0};
    bpf_map_update_elem(&ongoing_server_connections, &g_key, &conn, BPF_ANY);

    return 0;
}

SEC("uprobe/jsonrpcReadRequestHeader")
int GUARDED_PROG(obi_uprobe_jsonrpcReadRequestHeader, struct pt_regs *, ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/jsonrpcReadRequestHeader ===");
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);
    if (!invocation) {
        return 0;
    }
    const u64 rpc_request_addr = (u64)GO_PARAM2(ctx);
    bpf_dbg_printk("rpc_request_addr=%llx", rpc_request_addr);
    invocation->rpc_request_addr = rpc_request_addr;

    return 0;
}

SEC("uprobe/jsonrpcReadRequestHeaderRet")
int GUARDED_PROG(obi_uprobe_jsonrpcReadRequestHeaderReturns, struct pt_regs *, ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/jsonrpcReadRequestHeaderRet ===");
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);

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
int GUARDED_PROG(obi_uprobe_connServeRet, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/connServeRet ===");
    void *goroutine_addr = GOROUTINE_PTR(ctx);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    bpf_map_delete_elem(&ongoing_server_connections, &g_key);

    return 0;
}

// net/http writes the request through this io.Writer on persistConn.writeLoop.
// Its receiver is the persistConn, which the netFD write that follows on this same
// goroutine cannot see.
SEC("uprobe/persistConnWriterWrite")
int GUARDED_PROG(obi_uprobe_persistConnWriterWrite, struct pt_regs *, ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    const u64 pc = (u64)GO_PARAM1(ctx);

    bpf_dbg_printk(
        "=== uprobe/persistConnWriter.Write goroutine=%lx, pc=%llx ===", goroutine_addr, pc);

    if (!pc) {
        return 0;
    }

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);
    store_persist_conn_writer(&g_key, pc);

    return 0;
}

SEC("uprobe/persistConnRoundTrip")
int GUARDED_PROG(obi_uprobe_persistConnRoundTrip, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/persistConnRoundTrip ===");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    off_table_t *ot = get_offsets_table();

    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&go_ongoing_http_client_requests, &g_key);
    if (!invocation) {
        bpf_dbg_printk("can't find invocation info for client call, this might be a bug");
        return 0;
    }

    void *pc_ptr = GO_PARAM1(ctx);

    // the write side resolves this persistConn's connection from its netFD
    store_persist_conn_request(&g_key, (u64)pc_ptr);

    if (pc_ptr) {
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
                if (!get_conn_info(conn_ptr, &conn)) {
                    // an app wrapping net.Conn leaves this unreadable; storing the zero
                    // connection would claim it as the Go-handled one and set it as this
                    // request's peer, neither of which is true
                    bpf_dbg_printk("can't read client connection, leaving it unassociated");
                    return 0;
                }

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
                bpf_map_update_elem(&ongoing_client_connections, &g_key, &conn, BPF_ANY);

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

                egress_key_t e_key = {
                    .d_port = conn.d_port,
                    .s_port = conn.s_port,
                };

                if (tls_state) {
                    // Clone and mark it invalid for the purpose of storing it in the
                    // outgoing trace map, if it's an SSL connection
                    tp_info_pid_t tp_p_invalid = {0};
                    __builtin_memcpy(&tp_p_invalid, &tp_p, sizeof(tp_p));
                    tp_p_invalid.valid = 0;
                    bpf_map_update_elem(&outgoing_trace_map, &e_key, &tp_p_invalid, BPF_ANY);
                } else {
                    bpf_map_update_elem(&outgoing_trace_map, &e_key, &tp_p, BPF_ANY);
                }

                bpf_map_update_elem(&go_ongoing_http, &e_key, &g_key, BPF_ANY);
            }
        }
    }

    return 0;
}
