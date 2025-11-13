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

#include <bpfcore/utils.h>

#include <common/http_types.h>
#include <common/ringbuf.h>
#include <common/strings.h>
#include <common/tracing.h>

#include <gotracer/go_byte_arr.h>
#include <gotracer/go_common.h>
#include <gotracer/go_str.h>
#include <gotracer/go_stream_key.h>
#include <gotracer/hpack.h>

#include <logger/bpf_dbg.h>

#include <maps/go_ongoing_http.h>
#include <maps/go_ongoing_http_client_requests.h>

#include <pid/pid_helpers.h>

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

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, http_client_data_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http_client_requests_data SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, tp_info_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} http2_server_requests_tp SEC(".maps");

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

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, server_http_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http_server_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, unsigned char[HTTP_HEADER_MAX_LEN]);
    __uint(max_entries, 1);
} temp_header_mem_store SEC(".maps");

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
    bpf_dbg_printk("=== uprobe/ServeHTTP === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);

    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);
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

    server_http_func_invocation_t invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .tp = {0},
        .status = 0,
        .content_length = 0,
        .response_length = 0,
    };

    invocation.method[0] = 0;
    invocation.path[0] = 0;
    invocation.pattern[0] = 0;

    if (req) {
        server_trace_parent(goroutine_addr, &invocation.tp, decoded_tp);
        // TODO: if context propagation is supported, overwrite the header value in the map with the
        // new span context and the same thread id.

        // Get method from Request.Method
        if (!read_go_str("method",
                         req,
                         go_offset_of(ot, (go_offset){.v = _method_ptr_pos}),
                         invocation.method,
                         sizeof(invocation.method))) {
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
                         invocation.path,
                         sizeof(invocation.path))) {
            bpf_dbg_printk("can't read http Request.URL.Path");
            goto done;
        }

        bpf_dbg_printk("path: %s", invocation.path);

        res = bpf_probe_read(
            &invocation.content_length,
            sizeof(invocation.content_length),
            (void *)(req + go_offset_of(ot, (go_offset){.v = _content_length_ptr_pos})));
        if (res) {
            bpf_dbg_printk("can't read http Request.ContentLength");
            goto done;
        }
    } else {
        goto done;
    }

    // Write event
    if (bpf_map_update_elem(&ongoing_http_server_requests, &g_key, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update map element");
    }

done:
    return 0;
}

SEC("uprobe/findHandler")
int obi_uprobe_findHandlerRet(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc findHandler returns === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);

    bpf_dbg_printk("goroutine_addr %lx, inv %llx", goroutine_addr, invocation);

    if (invocation) {
        u64 len = (u64)GO_PARAM4(ctx);
        void *ptr = GO_PARAM3(ctx);
        if (ptr) {
            bpf_dbg_printk("reading pattern information with len %d", len);
            read_go_str_n("pattern", ptr, len, invocation->pattern, PATTERN_MAX_LEN);
        }
    }

    return 0;
}

SEC("uprobe/muxSetMatch")
int obi_uprobe_muxSetMatch(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc gorilla mux setMatch === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);

    bpf_dbg_printk("goroutine_addr %lx, inv %llx", goroutine_addr, invocation);

    if (invocation && !invocation->pattern[0]) {
        off_table_t *ot = get_offsets_table();

        void *path = GO_PARAM2(ctx);
        if (path) {
            bpf_dbg_printk("reading template from %llx", path);
            u64 templ_off = go_offset_of(ot, (go_offset){.v = _mux_template_pos});
            read_go_str("pattern", path, templ_off, invocation->pattern, PATTERN_MAX_LEN);
            bpf_dbg_printk("pattern %s", invocation->pattern);
        }
    }

    return 0;
}

SEC("uprobe/ginGetValue")
int obi_uprobe_ginGetValueRet(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc gin getValue returns === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);

    off_table_t *ot = get_offsets_table();
    u64 fullpath_off = go_offset_of(ot, (go_offset){.v = _gin_fullpath_pos});

    bpf_dbg_printk(
        "goroutine_addr %lx, inv %llx, fullpath_off %d", goroutine_addr, invocation, fullpath_off);

    if (fullpath_off == _gin_fullpath_off_pre_17 || fullpath_off == _gin_fullpath_off_post_17) {
        if (invocation && !invocation->pattern[0]) {
            void *handlers = GO_PARAM1(ctx);
            if (handlers) {
                // duplicated because of verifier complaints with choosing one or the other
                // registers
                if (fullpath_off == _gin_fullpath_off_pre_17) {
                    void *ptr = GO_PARAM8(ctx);
                    u64 len = (u64)GO_PARAM9(ctx);

                    if (ptr) {
                        bpf_dbg_printk("pre gin 1.7.0 fullPath from %llx", ptr);
                        read_go_str_n("pattern", ptr, len, invocation->pattern, PATTERN_MAX_LEN);
                        bpf_dbg_printk("pattern %s", invocation->pattern);
                    }
                } else {
                    void *ptr = GO_PARAM6(ctx);
                    u64 len = (u64)GO_PARAM7(ctx);

                    if (ptr) {
                        bpf_dbg_printk("post gin 1.7.0 fullPath from %llx", ptr);
                        read_go_str_n("pattern", ptr, len, invocation->pattern, PATTERN_MAX_LEN);
                        bpf_dbg_printk("pattern %s", invocation->pattern);
                    }
                }
            }
        }
    }

    return 0;
}

SEC("uprobe/readRequest")
int obi_uprobe_readRequestStart(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc readRequest === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    off_table_t *ot = get_offsets_table();

    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    connection_info_t *existing = bpf_map_lookup_elem(&ongoing_server_connections, &g_key);

    if (!existing) {
        void *c_ptr = GO_PARAM1(ctx);
        if (c_ptr) {
            void *conn_conn_ptr =
                c_ptr + 8 + go_offset_of(ot, (go_offset){.v = _c_rwc_pos}); // embedded struct
            void *tls_state = 0;
            bpf_probe_read(&tls_state,
                           sizeof(tls_state),
                           (void *)(c_ptr + go_offset_of(ot, (go_offset){.v = _c_tls_pos})));
            conn_conn_ptr = unwrap_tls_conn_info(conn_conn_ptr, tls_state);
            //bpf_dbg_printk("conn_conn_ptr %llx, tls_state %llx, c_tls_pos = %d, c_tls_ptr = %llx", conn_conn_ptr, tls_state, c_tls_pos, c_ptr + c_tls_pos);
            if (conn_conn_ptr) {
                void *conn_ptr = 0;
                bpf_probe_read(
                    &conn_ptr,
                    sizeof(conn_ptr),
                    (void *)(conn_conn_ptr +
                             go_offset_of(ot, (go_offset){.v = _net_conn_pos}))); // find conn
                bpf_dbg_printk("conn_ptr %llx", conn_ptr);
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
int obi_uprobe_readRequestReturns(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc readRequest returns === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

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
int obi_uprobe_http2Server_processHeaders(struct pt_regs *ctx) {
    void *sc_ptr = GO_PARAM1(ctx);
    void *frame = GO_PARAM2(ctx);
    bpf_dbg_printk("=== uprobe/http2Server_processHeaders sc %lx === ", sc_ptr);
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
    bpf_dbg_printk("Found traceparent in header %s", header_start);
}

static __always_inline void handle_traceparent_header(server_http_func_invocation_t *inv,
                                                      go_addr_key_t *g_key,
                                                      unsigned char *traceparent_start) {
    if (inv) {
        if (!valid_trace(inv->tp.trace_id)) {
            update_traceparent(inv, traceparent_start);
        }
    } else {
        server_http_func_invocation_t minimal_inv = {.tp = {0}};
        update_traceparent(&minimal_inv, traceparent_start);
        bpf_map_update_elem(&ongoing_http_server_requests, g_key, &minimal_inv, BPF_ANY);
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

SEC("uprobe/readContinuedLineSlice")
int obi_uprobe_readContinuedLineSliceReturns(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc readContinuedLineSlice returns === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);
    connection_info_t *existing = bpf_map_lookup_elem(&ongoing_server_connections, &g_key);
    if (!existing) {
        return 0;
    }

    u64 len = (u64)GO_PARAM2(ctx);
    const unsigned char *buf = (const unsigned char *)GO_PARAM1(ctx);

    unsigned char *temp = temp_header_mem();
    const u32 safe_len = len > HTTP_HEADER_MAX_LEN ? HTTP_HEADER_MAX_LEN : len;
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
    bpf_dbg_printk("=== uprobe/ServeHTTP returns === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);

    if (invocation == NULL) {
        void *parent_go = (void *)find_parent_goroutine(&g_key);
        if (parent_go) {
            bpf_dbg_printk("found parent goroutine for header [%llx]", parent_go);
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
    bpf_dbg_printk("tp: %s", tp_buf);

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
    trace->scheme[0] = '\0';
    trace->pattern[0] = '\0';

    goroutine_metadata *g_metadata = bpf_map_lookup_elem(&ongoing_goroutines, &g_key);
    if (g_metadata) {
        trace->go_start_monotime_ns = g_metadata->timestamp;
        bpf_map_delete_elem(&ongoing_goroutines, &g_key);
    } else {
        trace->go_start_monotime_ns = invocation->start_monotime_ns;
    }

    connection_info_t *info = bpf_map_lookup_elem(&ongoing_server_connections, &g_key);

    if (info) {
        //dbg_print_http_connection_info(info);
        __builtin_memcpy(&trace->conn, info, sizeof(connection_info_t));
    } else {
        // We can't find the connection info, this typically means there are too many requests per second
        // and the connection map is too small for the workload.
        bpf_dbg_printk("Can't find connection info for %llx", goroutine_addr);
        __builtin_memset(&trace->conn, 0, sizeof(connection_info_t));
    }

    // Server connections have opposite order, source port is the server port
    swap_connection_info_order(&trace->conn);
    trace->tp = invocation->tp;
    trace->content_length = invocation->content_length;
    __builtin_memcpy(trace->method, invocation->method, sizeof(trace->method));
    __builtin_memcpy(trace->path, invocation->path, sizeof(trace->path));
    __builtin_memcpy(trace->pattern, invocation->pattern, sizeof(trace->pattern));
    trace->status = (u16)invocation->status;
    trace->response_length = invocation->response_length;

    make_tp_string(tp_buf, &invocation->tp);
    bpf_dbg_printk("tp: %s", tp_buf);
    bpf_dbg_printk("method: %s", trace->method);
    bpf_dbg_printk("path: %s", trace->path);
    bpf_dbg_printk("pattern: %s", trace->pattern);

    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

done:
    bpf_map_delete_elem(&ongoing_http_server_requests, &g_key);
    bpf_map_delete_elem(&go_trace_map, &g_key);
    return 0;
}

SEC("uprobe/ServeHTTP_ret")
int obi_uprobe_ServeHTTPReturns(struct pt_regs *ctx) {
    return serve_http_returns(ctx);
}

#ifndef NO_HEADER_PROPAGATION
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the request header map
    __type(value, u64);  // the goroutine of the transport request
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} header_req_map SEC(".maps");

#endif

/* HTTP Client. We expect to see HTTP client in both HTTP server and gRPC server calls.*/
static __always_inline void roundTripStartHelper(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http roundTrip === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);

    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

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

    bpf_dbg_printk("path: %s", trace.path);
    bpf_dbg_printk("host: %s", trace.host);
    bpf_dbg_printk("scheme: %s", trace.scheme);

    // Write event
    if (bpf_map_update_elem(&go_ongoing_http_client_requests, &g_key, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update http client map element");
    }

    bpf_map_update_elem(&ongoing_http_client_requests_data, &g_key, &trace, BPF_ANY);

#ifndef NO_HEADER_PROPAGATION
    void *headers_ptr = 0;
    bpf_probe_read(&headers_ptr,
                   sizeof(headers_ptr),
                   (void *)(req + go_offset_of(ot, (go_offset){.v = _req_header_ptr_pos})));
    bpf_dbg_printk(
        "goroutine_addr %lx, req ptr %llx, headers_ptr %llx", goroutine_addr, req, headers_ptr);

    if (headers_ptr) {
        bpf_map_update_elem(&header_req_map, &headers_ptr, &goroutine_addr, BPF_ANY);
    }
#endif
}

SEC("uprobe/roundTrip")
int obi_uprobe_roundTrip(struct pt_regs *ctx) {
    roundTripStartHelper(ctx);
    return 0;
}

SEC("uprobe/roundTrip_return")
int obi_uprobe_roundTripReturn(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http roundTrip return === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    off_table_t *ot = get_offsets_table();

    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);
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

    // Copy the values read on request start
    __builtin_memcpy(trace->method, data->method, sizeof(trace->method));
    __builtin_memcpy(trace->path, data->path, sizeof(trace->path));
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
        __builtin_memset(&trace->conn, 0, sizeof(connection_info_t));
    }

    trace->tp = invocation->tp;

    unsigned char tp_buf[TP_MAX_VAL_LENGTH];
    make_tp_string(tp_buf, &invocation->tp);
    bpf_dbg_printk("tp: %s", tp_buf);
    bpf_dbg_printk("method: %s", trace->method);
    bpf_dbg_printk("path: %s", trace->path);

    u64 status_code_ptr_pos = go_offset_of(ot, (go_offset){.v = _status_code_ptr_pos});
    bpf_probe_read(&trace->status, sizeof(trace->status), (void *)(resp_ptr + status_code_ptr_pos));

    bpf_dbg_printk(
        "status %d, offset %d, resp_ptr %lx", trace->status, status_code_ptr_pos, (u64)resp_ptr);

    u64 response_length_ptr_pos = go_offset_of(ot, (go_offset){.v = _response_length_ptr_pos});
    bpf_probe_read(&trace->response_length,
                   sizeof(trace->response_length),
                   (void *)(resp_ptr + response_length_ptr_pos));

    bpf_dbg_printk("response_length %llx, offset %llu, resp_ptr %llx",
                   trace->response_length,
                   response_length_ptr_pos,
                   (u64)resp_ptr);

    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

done:
    bpf_map_delete_elem(&go_ongoing_http_client_requests, &g_key);
    bpf_map_delete_elem(&ongoing_http_client_requests_data, &g_key);
    bpf_map_delete_elem(&ongoing_client_connections, &g_key);
    return 0;
}

#ifndef NO_HEADER_PROPAGATION
// Context propagation through HTTP headers
SEC("uprobe/header_writeSubset")
int obi_uprobe_writeSubset(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc header writeSubset === ");

    void *header_addr = GO_PARAM1(ctx);
    void *io_writer_addr = GO_PARAM3(ctx);

    bpf_dbg_printk("goroutine_addr %lx, header ptr %llx", GOROUTINE_PTR(ctx), header_addr);

    // we don't want to run this code when we header or the buffer is nil
    if (!header_addr || !io_writer_addr) {
        goto done;
    }

    off_table_t *ot = get_offsets_table();

    u64 *request_goaddr = bpf_map_lookup_elem(&header_req_map, &header_addr);

    if (!request_goaddr) {
        bpf_dbg_printk("Can't find parent go routine for header %llx", header_addr);
        return 0;
    }
    u64 parent_goaddr = *request_goaddr;
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, (void *)parent_goaddr);

    http_func_invocation_t *func_inv =
        bpf_map_lookup_elem(&go_ongoing_http_client_requests, &g_key);
    if (!func_inv) {
        bpf_dbg_printk("Can't find client request for goroutine %llx", parent_goaddr);
        goto done;
    }

    unsigned char buf[TRACEPARENT_LEN];

    make_tp_string(buf, &func_inv->tp);

    void *buf_ptr = 0;
    u64 io_writer_buf_ptr_pos = go_offset_of(ot, (go_offset){.v = _io_writer_buf_ptr_pos});
    u64 io_writer_n_pos = go_offset_of(ot, (go_offset){.v = _io_writer_n_pos});

    // writing with bad offsets can crash the application, be defensive here
    if (!io_writer_buf_ptr_pos || !io_writer_n_pos) {
        goto done;
    }

    bpf_probe_read(&buf_ptr, sizeof(buf_ptr), (void *)(io_writer_addr + io_writer_buf_ptr_pos));
    if (!buf_ptr) {
        goto done;
    }

    s64 size = 0;
    bpf_probe_read(
        &size, sizeof(s64), (void *)(io_writer_addr + io_writer_buf_ptr_pos + 8)); // grab size

    s64 len = 0;
    bpf_probe_read(&len, sizeof(s64),
                   (void *)(io_writer_addr + io_writer_n_pos)); // grab len

    bpf_dbg_printk("buf_ptr %llx, len=%d, size=%d", (void *)buf_ptr, len, size);

    if (len <
        (size - TP_MAX_VAL_LENGTH - TP_MAX_KEY_LENGTH - 4)) { // 4 = strlen(":_") + strlen("\r\n")
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
        connection_info_t *info = bpf_map_lookup_elem(&ongoing_client_connections, &g_key);
        if (info) {
            egress_key_t e_key = {
                .d_port = info->d_port,
                .s_port = info->s_port,
            };
            bpf_map_delete_elem(&outgoing_trace_map, &e_key);
            bpf_dbg_printk(
                "wrote traceparent using bpf_probe_write_user, removing outgoing trace map %d:%d",
                e_key.s_port,
                e_key.d_port);
        }
    }

done:
    bpf_map_delete_elem(&header_req_map, &header_addr);
    return 0;
}
#else
SEC("uprobe/header_writeSubset")
int obi_uprobe_writeSubset(struct pt_regs *ctx) {
    return 0;
}
#endif

// HTTP 2.0 server support
SEC("uprobe/http2ResponseWriterStateWriteHeader")
int obi_uprobe_http2ResponseWriterStateWriteHeader(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc (http response)/(http2 responseWriterState) writeHeader === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    u64 status = (u64)GO_PARAM2(ctx);
    bpf_dbg_printk("goroutine_addr %lx, status %d", goroutine_addr, status);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);

    if (invocation == NULL) {
        void *parent_go = (void *)find_parent_goroutine(&g_key);
        if (parent_go) {
            bpf_dbg_printk("found parent goroutine for header [%llx]", parent_go);
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
int obi_uprobe_http2serverConn_runHandler(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http2serverConn_runHandler === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *sc = GO_PARAM1(ctx);
    off_table_t *ot = get_offsets_table();

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    if (sc) {
        void *conn_ptr = 0;
        bpf_probe_read(
            &conn_ptr, sizeof(void *), sc + go_offset_of(ot, (go_offset){.v = _sc_conn_pos}) + 8);
        bpf_dbg_printk("conn_ptr %llx", conn_ptr);
        if (conn_ptr) {
            void *conn_conn_ptr = 0;
            bpf_probe_read(&conn_conn_ptr, sizeof(void *), conn_ptr + 8);
            bpf_dbg_printk("conn_conn_ptr %llx", conn_conn_ptr);
            if (conn_conn_ptr) {
                connection_info_t conn = {0};
                get_conn_info(conn_conn_ptr, &conn);
                bpf_map_update_elem(&ongoing_server_connections, &g_key, &conn, BPF_ANY);
            }
        }

        go_addr_key_t sc_key = {};
        go_addr_key_from_id(&sc_key, sc);

        tp_info_t *tp = bpf_map_lookup_elem(&http2_server_requests_tp, &sc_key);
        bpf_dbg_printk("looked up tp %llx", tp);

        if (tp) {
            server_http_func_invocation_t inv = {};
            __builtin_memcpy(&inv.tp, tp, sizeof(tp_info_t));
            bpf_dbg_printk("Found traceparent in HTTP2 headers");
            bpf_map_update_elem(&ongoing_http_server_requests, &g_key, &inv, BPF_ANY);
            bpf_map_delete_elem(&http2_server_requests_tp, &sc_key);
        }
    }

    return 0;
}

// HTTP 2.0 client support
#ifndef NO_HEADER_PROPAGATION
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, stream_key_t); // key: stream id + connection info
    // the goroutine of the round trip request, which is the key for our traceparent info
    __type(value, u64);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} http2_req_map SEC(".maps");
#endif

static __always_inline void setup_http2_client_conn(void *goroutine_addr,
                                                    void *cc_ptr,
                                                    u32 stream_id,
                                                    go_offset_const off_cc_tconn_pos,
                                                    go_offset_const off_cc_framer_pos) {
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    void *parent_go = (void *)find_parent_goroutine_in_chain(&g_key);

    bpf_dbg_printk("goroutine %lx, parent %lx", goroutine_addr, parent_go);

    // We should find a parent always
    if (parent_go) {
        goroutine_addr = parent_go;
        go_addr_key_from_id(&g_key, goroutine_addr);
    }

    off_table_t *ot = get_offsets_table();

    if (cc_ptr) {
        u64 cc_tconn_pos = go_offset_of(ot, (go_offset){.v = off_cc_tconn_pos});
        bpf_dbg_printk("cc_ptr %llx, cc_tconn_ptr %llx", cc_ptr, cc_ptr + cc_tconn_pos);
        void *tconn = cc_ptr + go_offset_of(ot, (go_offset){.v = off_cc_tconn_pos});
        bpf_probe_read(&tconn, sizeof(tconn), (void *)(cc_ptr + cc_tconn_pos + 8));
        bpf_dbg_printk("tconn %llx", tconn);

        if (tconn) {
            void *tconn_conn = 0;
            bpf_probe_read(&tconn_conn, sizeof(tconn_conn), (void *)(tconn + 8));
            bpf_dbg_printk("tconn_conn %llx", tconn_conn);

            connection_info_t conn = {0};
            u8 ok = get_conn_info(tconn_conn, &conn);

            if (ok) {
                bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

                bpf_map_update_elem(&ongoing_client_connections, &g_key, &conn, BPF_ANY);
            }
        }

#ifndef NO_HEADER_PROPAGATION
        void *framer = 0;
        bpf_probe_read(&framer,
                       sizeof(framer),
                       (void *)(cc_ptr + go_offset_of(ot, (go_offset){.v = off_cc_framer_pos})));

        bpf_dbg_printk(
            "cc_ptr = %llx, nextStreamID = %d, framer = %llx", cc_ptr, stream_id, framer);
        if (stream_id && framer) {
            stream_key_t s_key = {
                .stream_id = stream_id,
            };
            s_key.conn_ptr = (u64)framer;

            bpf_map_update_elem(&http2_req_map, &s_key, &goroutine_addr, BPF_ANY);
        }
#endif
    }
}

SEC("uprobe/http2RoundTrip")
int obi_uprobe_http2RoundTrip(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http2RoundTrip === ");
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
    u64 stream_id = (u64)GO_PARAM2(ctx);

    bpf_dbg_printk("=== uprobe/proc http2WriteHeaders === ");

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
    u64 stream_id = (u64)GO_PARAM2(ctx);

    bpf_dbg_printk("=== uprobe/proc http2WriteHeaders === ");

    setup_http2_client_conn(
        goroutine_addr, cc_ptr, (u32)stream_id, _cc_tconn_vendored_pos, _cc_framer_vendored_pos);

    return 0;
}

#ifndef NO_HEADER_PROPAGATION
#define MAX_W_PTR_N 1024

typedef struct framer_func_invocation {
    u64 framer_ptr;
    tp_info_t tp;
    s64 initial_n;
} framer_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: go routine doing framer write headers
    __type(
        value,
        framer_func_invocation_t); // the goroutine of the round trip request, which is the key for our traceparent info
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} framer_invocation_map SEC(".maps");

SEC("uprobe/http2FramerWriteHeaders")
int obi_uprobe_http2FramerWriteHeaders(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http2 Framer writeHeaders === ");
    void *framer = GO_PARAM1(ctx);

    if (!framer) {
        bpf_dbg_printk("framer is nil");
        return 0;
    }

    u64 stream_id = (u64)GO_PARAM2(ctx);

    off_table_t *ot = get_offsets_table();
    u64 framer_w_pos = go_offset_of(ot, (go_offset){.v = _framer_w_pos});

    if (framer_w_pos == -1) {
        bpf_dbg_printk("framer w not found");
        return 0;
    }

    bpf_dbg_printk("framer=%llx, stream_id=%lld", framer, ((u64)stream_id));

    stream_key_t s_key = {
        .stream_id = stream_id,
    };
    s_key.conn_ptr = (u64)framer;

    void **go_ptr = bpf_map_lookup_elem(&http2_req_map, &s_key);

    if (go_ptr) {
        void *go_addr = *go_ptr;
        bpf_dbg_printk("Found existing stream data goaddr = %llx", go_addr);
        go_addr_key_t g_key = {};
        go_addr_key_from_id(&g_key, go_addr);

        http_func_invocation_t *info =
            bpf_map_lookup_elem(&go_ongoing_http_client_requests, &g_key);

        if (info) {
            bpf_dbg_printk("Found func info %llx", info);
            void *goroutine_addr = GOROUTINE_PTR(ctx);

            void *w_ptr = 0;
            bpf_probe_read(&w_ptr, sizeof(w_ptr), (void *)(framer + framer_w_pos + 8));
            if (w_ptr) {
                s64 n = 0;
                bpf_probe_read(
                    &n,
                    sizeof(n),
                    (void *)(w_ptr + go_offset_of(ot, (go_offset){.v = _io_writer_n_pos})));

                bpf_dbg_printk("Found initial n = %d, framer_ptr %llx", n, framer);

                // The offset is 0 on all connections we've tested with.
                // If we read some very large offset, we don't do anything since it might be a situation
                // we can't handle.
                if (n < MAX_W_PTR_N) {
                    framer_func_invocation_t f_info = {
                        .tp = info->tp,
                        .framer_ptr = (u64)framer,
                        .initial_n = n,
                    };
                    go_addr_key_t f_key = {};
                    go_addr_key_from_id(&f_key, goroutine_addr);

                    bpf_map_update_elem(&framer_invocation_map, &f_key, &f_info, BPF_ANY);
                } else {
                    bpf_dbg_printk("N too large, ignoring...");
                }
            }
        }
    }

    bpf_map_delete_elem(&http2_req_map, &s_key);
    return 0;
}
#else
SEC("uprobe/http2FramerWriteHeaders")
int obi_uprobe_http2FramerWriteHeaders(struct pt_regs *ctx) {
    return 0;
}
#endif

#ifndef NO_HEADER_PROPAGATION
#define HTTP2_ENCODED_HEADER_LEN                                                                   \
    66 // 1 + 1 + 8 + 1 + 55 = type byte + hpack_len_as_byte("traceparent") + strlen(hpack("traceparent")) + len_as_byte(55) + generated traceparent id

SEC("uprobe/http2FramerWriteHeaders_returns")
int obi_uprobe_http2FramerWriteHeaders_returns(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http2 Framer writeHeaders returns === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    off_table_t *ot = get_offsets_table();
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    framer_func_invocation_t *f_info = bpf_map_lookup_elem(&framer_invocation_map, &g_key);

    if (f_info) {
        void *w_ptr = 0;
        u64 framer_w_pos = go_offset_of(ot, (go_offset){.v = _framer_w_pos});
        u64 io_writer_n_pos = go_offset_of(ot, (go_offset){.v = _io_writer_n_pos});

        // being defensive here if we can't find the offsets
        if (!framer_w_pos || !io_writer_n_pos) {
            goto done;
        }

        bpf_probe_read(&w_ptr, sizeof(w_ptr), (void *)(f_info->framer_ptr + framer_w_pos + 8));

        bpf_dbg_printk(
            "framer_ptr %llx, w_ptr %llx, w_pos %d", f_info->framer_ptr, w_ptr, framer_w_pos + 8);

        if (w_ptr) {
            void *buf_arr = 0;
            s64 n = 0;
            s64 cap = 0;
            s64 initial_n = f_info->initial_n;

            bpf_probe_read(
                &buf_arr,
                sizeof(buf_arr),
                (void *)(w_ptr + go_offset_of(ot, (go_offset){.v = _io_writer_buf_ptr_pos})));
            bpf_probe_read(&n, sizeof(n), (void *)(w_ptr + io_writer_n_pos));
            bpf_probe_read(
                &cap,
                sizeof(cap),
                (void *)(w_ptr + go_offset_of(ot, (go_offset){.v = _io_writer_buf_ptr_pos}) + 16));

            bpf_clamp_umax(initial_n, MAX_W_PTR_N);

            bpf_dbg_printk(
                "Found f_info, this is the place to write to w = %llx, buf=%llx", w_ptr, buf_arr);
            bpf_dbg_printk("Found f_info, this is the place to write to n=%lld, size=%lld", n, cap);
            if (buf_arr && n < (cap - HTTP2_ENCODED_HEADER_LEN)) {
                uint8_t tp_str[TP_MAX_VAL_LENGTH];

                // http2 encodes the length of the headers in the first 3 bytes of buf, we need to update those
                u8 size_1 = 0;
                u8 size_2 = 0;
                u8 size_3 = 0;

                bpf_probe_read(&size_1, sizeof(size_1), (void *)(buf_arr + initial_n));
                bpf_probe_read(&size_2, sizeof(size_2), (void *)(buf_arr + initial_n + 1));
                bpf_probe_read(&size_3, sizeof(size_3), (void *)(buf_arr + initial_n + 2));

                bpf_dbg_printk("size 1:%x, 2:%x, 3:%x", size_1, size_2, size_3);

                u32 original_size = ((u32)(size_1) << 16) | ((u32)(size_2) << 8) | size_3;
                if (original_size > 0) {
                    u8 type_byte = 0;
                    u8 key_len =
                        TP_ENCODED_LEN | 0x80; // high tagged to signify hpack encoded value
                    u8 val_len = TP_MAX_VAL_LENGTH;

                    // We don't hpack encode the value of the traceparent field, because that will require that
                    // we use bpf_loop, which in turn increases the kernel requirement to 5.17+.
                    make_tp_string(tp_str, &f_info->tp);
                    //bpf_dbg_printk("Will write %s, type = %d, key_len = %d, val_len = %d", tp_str, type_byte, key_len, val_len);

                    bpf_probe_write_user(buf_arr + (n & 0x0ffff), &type_byte, sizeof(type_byte));
                    n++;
                    // Write the length of the key = 8
                    bpf_probe_write_user(buf_arr + (n & 0x0ffff), &key_len, sizeof(key_len));
                    n++;
                    // Write 'traceparent' encoded as hpack
                    bpf_probe_write_user(buf_arr + (n & 0x0ffff), tp_encoded, sizeof(tp_encoded));
                    ;
                    n += TP_ENCODED_LEN;
                    // Write the length of the hpack encoded traceparent field
                    bpf_probe_write_user(buf_arr + (n & 0x0ffff), &val_len, sizeof(val_len));
                    n++;
                    bpf_probe_write_user(buf_arr + (n & 0x0ffff), tp_str, sizeof(tp_str));
                    n += TP_MAX_VAL_LENGTH;
                    // Update the value of n in w to reflect the new size
                    bpf_probe_write_user((void *)(w_ptr + io_writer_n_pos), &n, sizeof(n));

                    u32 new_size = original_size + HTTP2_ENCODED_HEADER_LEN;

                    bpf_dbg_printk("Changing size from %d to %d", original_size, new_size);
                    size_1 = (u8)(new_size >> 16);
                    size_2 = (u8)(new_size >> 8);
                    size_3 = (u8)(new_size);

                    bpf_probe_write_user((void *)(buf_arr + initial_n), &size_1, sizeof(size_1));
                    bpf_probe_write_user(
                        (void *)(buf_arr + initial_n + 1), &size_2, sizeof(size_2));
                    bpf_probe_write_user(
                        (void *)(buf_arr + initial_n + 2), &size_3, sizeof(size_3));
                }
            }
        }
    }

done:
    bpf_map_delete_elem(&framer_invocation_map, &g_key);
    return 0;
}
#else
SEC("uprobe/http2FramerWriteHeaders_returns")
int obi_uprobe_http2FramerWriteHeaders_returns(struct pt_regs *ctx) {
    return 0;
}
#endif

SEC("uprobe/connServe")
int obi_uprobe_connServe(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/proc http conn serve goroutine %lx === ", goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    connection_info_t conn = {0};
    bpf_map_update_elem(&ongoing_server_connections, &g_key, &conn, BPF_ANY);

    return 0;
}

SEC("uprobe/netFdRead")
int obi_uprobe_netFdRead(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/proc netFD read goroutine %lx === ", goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    // lookup active HTTP connection
    connection_info_t *conn = bpf_map_lookup_elem(&ongoing_server_connections, &g_key);
    if (conn) {
        if (conn->d_port == 0 && conn->s_port == 0) {
            bpf_dbg_printk(
                "Found existing server connection, parsing FD information for socket tuples, %llx",
                goroutine_addr);

            void *fd_ptr = GO_PARAM1(ctx);
            get_conn_info_from_fd(fd_ptr, conn); // ok to not check the result, we leave it as 0
        }
        //dbg_print_http_connection_info(conn);
    }
    // lookup a grpc connection
    // Sets up the connection info to be grabbed and mapped over the transport to operateHeaders
    void *tr = bpf_map_lookup_elem(&ongoing_grpc_operate_headers, &g_key);
    bpf_dbg_printk("tr %llx", tr);
    if (tr) {
        grpc_transports_t *t = bpf_map_lookup_elem(&ongoing_grpc_transports, tr);
        bpf_dbg_printk("t %llx", t);
        if (t) {
            if (t->conn.d_port == 0 && t->conn.s_port == 0) {
                void *fd_ptr = GO_PARAM1(ctx);
                get_conn_info_from_fd(fd_ptr,
                                      &t->conn); // ok to not check the result, we leave it as 0
            }
        }
    }
    // lookup active sql connection
    sql_func_invocation_t *sql_conn = bpf_map_lookup_elem(&ongoing_sql_queries, &g_key);
    bpf_dbg_printk("sql_conn %llx", sql_conn);
    if (sql_conn) {
        void *fd_ptr = GO_PARAM1(ctx);
        get_conn_info_from_fd(fd_ptr,
                              &sql_conn->conn); // ok to not check the result, we leave it as 0
    }

    mongo_go_client_req_t *mongo_conn = bpf_map_lookup_elem(&ongoing_mongo_requests, &g_key);
    bpf_dbg_printk("mongo_conn %llx", mongo_conn);
    if (mongo_conn) {
        void *fd_ptr = GO_PARAM1(ctx);
        get_conn_info_from_fd(fd_ptr,
                              &mongo_conn->conn); // ok to not check the result, we leave it as 0
    }

    return 0;
}

SEC("uprobe/jsonrpcReadRequestHeader")
int obi_uprobe_jsonrpcReadRequestHeader(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/proc jsonrpc read request header goroutine %lx === ",
                   goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);
    if (!invocation) {
        return 0;
    }
    const u64 rpc_request_addr = (u64)GO_PARAM2(ctx);
    bpf_dbg_printk("rpc_request_addr %llx", rpc_request_addr);
    invocation->rpc_request_addr = rpc_request_addr;

    return 0;
}

SEC("uprobe/jsonrpcReadRequestHeaderRet")
int obi_uprobe_jsonrpcReadRequestHeaderReturns(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/proc jsonrpc read request header return goroutine %lx === ",
                   goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    server_http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);

    if (!invocation || !invocation->rpc_request_addr) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();

    const u64 rpc_request_addr = invocation->rpc_request_addr;

    bpf_dbg_printk("rpc_request_addr %llx", rpc_request_addr);

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
                     invocation->method,
                     METHOD_MAX_LEN)) {
        bpf_dbg_printk("Failed to read JSON-RPC method from %llx", rpc_request_addr);
        return 0;
    }
    bpf_dbg_printk("read jsonrpc method %s", invocation->method);

    return 0;
}

SEC("uprobe/connServeRet")
int obi_uprobe_connServeRet(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http conn serve ret === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    bpf_map_delete_elem(&ongoing_server_connections, &g_key);

    return 0;
}

SEC("uprobe/persistConnRoundTrip")
int obi_uprobe_persistConnRoundTrip(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http persistConn roundTrip === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    off_table_t *ot = get_offsets_table();

    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&go_ongoing_http_client_requests, &g_key);
    if (!invocation) {
        bpf_dbg_printk("can't find invocation info for client call, this might be a bug");
        return 0;
    }

    void *pc_ptr = GO_PARAM1(ctx);
    if (pc_ptr) {
        void *conn_conn_ptr =
            pc_ptr + 8 + go_offset_of(ot, (go_offset){.v = _pc_conn_pos}); // embedded struct
        void *tls_state = 0;
        bpf_probe_read(
            &tls_state,
            sizeof(tls_state),
            (void *)(pc_ptr + go_offset_of(ot, (go_offset){.v = _pc_tls_pos}))); // find tlsState
        bpf_dbg_printk("conn_conn_ptr %llx, tls_state %llx", conn_conn_ptr, tls_state);

        conn_conn_ptr = unwrap_tls_conn_info(conn_conn_ptr, tls_state);

        if (conn_conn_ptr) {
            void *conn_ptr = 0;
            bpf_probe_read(
                &conn_ptr,
                sizeof(conn_ptr),
                (void *)(conn_conn_ptr +
                         go_offset_of(ot, (go_offset){.v = _net_conn_pos}))); // find conn
            bpf_dbg_printk("conn_ptr %llx", conn_ptr);
            if (conn_ptr) {
                connection_info_t conn = {0};
                get_conn_info(
                    conn_ptr,
                    &conn); // initialized to 0, no need to check the result if we succeeded
                u64 pid_tid = bpf_get_current_pid_tgid();
                u32 pid = pid_from_pid_tgid(pid_tid);
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
