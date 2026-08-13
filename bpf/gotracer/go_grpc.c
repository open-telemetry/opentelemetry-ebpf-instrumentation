// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

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

#include <common/common.h>
#include <common/globals.h>
#include <common/h2_defs.h>
#include <common/preempt_guard.h>
#include <common/ringbuf.h>
#include <common/trace_helpers.h>

#include <maps/go_h2_stream_states.h>

#include <gotracer/go_common.h>
#include <gotracer/go_h2_write.h>
#include <gotracer/go_offsets.h>
#include <gotracer/go_str.h>

#include <gotracer/maps/grpc.h>
#include <gotracer/maps/nethttp.h>

#include <gotracer/types/grpc.h>
#include <gotracer/types/stream_key.h>

#include <logger/bpf_dbg.h>

#include <pid/pid_helpers.h>

#include <shared/obi_ctx.h>

#define TRANSPORT_HTTP2 1
#define TRANSPORT_HANDLER 2

#define OPTIMISTIC_GRPC_ENCODED_HEADER_LEN                                                         \
    49 // 1 + 1 + 8 + 1 +~ 38 = type byte + hpack_len_as_byte("traceparent") + strlen(hpack("traceparent")) + len_as_byte(38) + hpack(generated tracepanent id)

static __always_inline void grpc_server_conn_info(void *tr, connection_info_t *conn) {
    if (!tr || !conn) {
        return;
    }

    off_table_t *ot = get_offsets_table();
    void *conn_ptr = NULL;
    bpf_probe_read_user(&conn_ptr,
                        sizeof(conn_ptr),
                        (void *)(tr + go_offset_of(ot, (go_offset){.v = _grpc_st_conn_pos}) +
                                 k_go_iface_data_offset));
    if (conn_ptr) {
        get_conn_info(conn_ptr, conn);
    }
}

SEC("uprobe/server_handleStream")
int GUARDED_PROG(obi_uprobe_server_handleStream, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/server_handleStream ===");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    void *stream_ptr = GO_PARAM4(ctx);
    void *stream_stream_ptr = stream_ptr;
    off_table_t *ot = get_offsets_table();

    u64 st_offset = go_offset_of(ot, (go_offset){.v = _grpc_stream_st_ptr_pos});

    const u64 new_handle_stream = go_offset_of(ot, (go_offset){.v = _grpc_one_six_nine});
    const u64 reduce_pointers_stream = go_offset_of(ot, (go_offset){.v = _grpc_one_seven_seven});
    bpf_dbg_printk("stream_ptr=%llx, new_handle_stream=%d, reduce_pointers_stream=%d",
                   stream_ptr,
                   new_handle_stream,
                   reduce_pointers_stream);
    if (new_handle_stream == 1 && reduce_pointers_stream != 1) {
        // Read the embedded object ptr
        bpf_probe_read(
            &stream_stream_ptr,
            sizeof(stream_stream_ptr),
            (void *)(stream_ptr + go_offset_of(ot, (go_offset){.v = _grpc_server_stream_stream})));

        bpf_dbg_printk("new stream pointer, stream_stream_ptr=%llx", stream_stream_ptr);
        if (!stream_stream_ptr) {
            bpf_dbg_printk("Error loading embedded server stream pointer from stream_ptr: %llx",
                           stream_ptr);
            return 0;
        }
        st_offset = go_offset_of(ot, (go_offset){.v = _grpc_server_stream_st_ptr_pos});
    }

    grpc_srv_func_invocation_t invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .stream = (u64)stream_stream_ptr,
        .st = 0,
        .tp = {0},
    };

    if (stream_ptr) {
        void *st_ptr = 0;
        void *tp_ptr = 0;
        // Read the embedded object ptr
        bpf_probe_read(&st_ptr, sizeof(st_ptr), (void *)(stream_ptr + st_offset + sizeof(void *)));

        bpf_dbg_printk("st_ptr=%llx", st_ptr);
        invocation.st = (u64)st_ptr;
        if (st_ptr) {
            u32 stream_id = 0;
            bpf_probe_read(
                &stream_id,
                sizeof(stream_id),
                (void *)(stream_stream_ptr +
                         go_offset_of(ot, (go_offset){.v = _grpc_transport_stream_id_pos})));
            if (stream_id) {
                stream_key_t sk = {.conn_ptr = (u64)st_ptr, .stream_id = stream_id};
                tp_info_t *stream_tp = bpf_map_lookup_elem(&ongoing_grpc_server_stream_tps, &sk);
                if (stream_tp && valid_trace(stream_tp->trace_id)) {
                    tp_ptr = stream_tp;
                }
                bpf_map_delete_elem(&ongoing_grpc_server_stream_tps, &sk);
            }
        }

        server_trace_parent(goroutine_addr, &invocation.tp, tp_ptr);
    }

    if (bpf_map_update_elem(&ongoing_grpc_server_requests, &g_key, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update grpc map element");
    }

    obi_ctx__set(bpf_get_current_pid_tgid(), &invocation.tp);

    return 0;
}

// Handles finding the connection information for http2 servers in grpc
SEC("uprobe/http2Server_operateHeaders")
int GUARDED_PROG(obi_uprobe_http2Server_operateHeaders, struct pt_regs *, ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    void *tr = GO_PARAM1(ctx);
    void *frame = GO_PARAM2(ctx);
    off_table_t *ot = get_offsets_table();

    const u64 new_offset_version = go_offset_of(ot, (go_offset){.v = _grpc_one_six_zero});

    // After grpc version 1.60, they added extra context argument to the
    // function call, which adds two extra arguments.
    if (new_offset_version) {
        frame = GO_PARAM4(ctx);
    }

    bpf_dbg_printk("=== uprobe/http2Server_operateHeaders ===");
    bpf_dbg_printk("tr=%llx, goroutine_addr=%lx, new=%d", tr, goroutine_addr, new_offset_version);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    grpc_transports_t t = {
        .type = TRANSPORT_HTTP2,
        .conn = {0},
        .tp = {0},
    };

    grpc_server_conn_info(tr, &t.conn);
    process_meta_frame_headers(frame, &t.tp);

    bpf_map_update_elem(&ongoing_grpc_operate_headers, &g_key, &tr, BPF_ANY);
    bpf_map_update_elem(&ongoing_grpc_transports, &tr, &t, BPF_ANY);

    // Per-stream tp avoids last-writer-wins on the per-transport entry.
    // MetaHeadersFrame.HeadersFrame is *HeadersFrame at offset 0;
    // FrameHeader.StreamID is at offset 8 inside HeadersFrame.
    if (frame && valid_trace(t.tp.trace_id)) {
        void *headers_frame = NULL;
        bpf_probe_read(&headers_frame, sizeof(headers_frame), frame);
        if (headers_frame) {
            u32 stream_id = 0;
            bpf_probe_read(&stream_id, sizeof(stream_id), (unsigned char *)headers_frame + 8);
            if (stream_id) {
                stream_key_t k = {.conn_ptr = (u64)tr, .stream_id = stream_id};
                bpf_map_update_elem(&ongoing_grpc_server_stream_tps, &k, &t.tp, BPF_ANY);
            }
        }
    }

    return 0;
}

// Handles finding the connection information for grpc ServeHTTP
SEC("uprobe/serverHandlerTransport_HandleStreams")
int GUARDED_PROG(obi_uprobe_server_handler_transport_handle_streams, struct pt_regs *, ctx) {
    void *tr = GO_PARAM1(ctx);
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/serverHandlerTransport_HandleStreams ===");
    bpf_dbg_printk("tr=%llx, goroutine_addr=%lx", tr, goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    void *parent_go = (void *)find_parent_goroutine(&g_key);
    if (parent_go) {
        bpf_dbg_printk("found parent goroutine for transport handler, parent_go=%llx", parent_go);
        go_addr_key_t p_key = {};
        go_addr_key_from_id(&p_key, parent_go);
        connection_info_t *conn = bpf_map_lookup_elem(&ongoing_server_connections, &p_key);
        bpf_dbg_printk("conn=%llx", conn);
        if (conn) {
            grpc_transports_t t = {
                .type = TRANSPORT_HANDLER,
            };
            __builtin_memcpy(&t.conn, conn, sizeof(connection_info_t));

            bpf_map_update_elem(&ongoing_grpc_transports, &tr, &t, BPF_ANY);
        }
    }

    return 0;
}

SEC("uprobe/server_handleStream")
int GUARDED_PROG(obi_uprobe_server_handleStream_return, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/server_handleStream ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    off_table_t *ot = get_offsets_table();

    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    grpc_srv_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_grpc_server_requests, &g_key);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read grpc invocation metadata");
        goto done;
    }

    u16 *status_ptr = bpf_map_lookup_elem(&ongoing_grpc_request_status, &g_key);
    u16 status = 0;
    if (status_ptr != NULL) {
        status = *status_ptr;
    } else {
        bpf_dbg_printk("can't read grpc invocation status");
    }

    void *stream_ptr = (void *)invocation->stream;
    void *st_ptr = (void *)invocation->st;
    const u64 grpc_stream_method_ptr_pos =
        go_offset_of(ot, (go_offset){.v = _grpc_stream_method_ptr_pos});
    bpf_dbg_printk("stream_ptr=%lx, st_ptr=%lx, grpc_stream_method_ptr_pos=%lx",
                   stream_ptr,
                   st_ptr,
                   grpc_stream_method_ptr_pos);

    http_request_trace_t *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace_t), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        goto done;
    }
    task_pid(&trace->pid);
    trace->type = EVENT_GRPC_REQUEST;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->status = status;
    trace->content_length = 0;
    trace->method[0] = '\0';
    trace->host[0] = '\0';
    trace->scheme[0] = '\0';
    trace->path[0] = '\0';
    trace->pattern[0] = '\0';
    trace->is_jsonrpc = false;
    trace->go_start_monotime_ns = invocation->start_monotime_ns;
    bpf_map_delete_elem(&ongoing_goroutines, &g_key);

    // Get method from transport.Stream.Method
    if (!read_go_str("grpc method",
                     stream_ptr,
                     grpc_stream_method_ptr_pos,
                     &trace->path,
                     sizeof(trace->path))) {
        bpf_dbg_printk("can't read grpc transport.Stream.Method");
        bpf_ringbuf_discard(trace, 0);
        goto done;
    }

    u8 found_conn = 0;
    if (st_ptr) {
        grpc_transports_t *t = bpf_map_lookup_elem(&ongoing_grpc_transports, &st_ptr);

        bpf_dbg_printk("found t: %llx", t);
        if (t) {
            bpf_dbg_printk("setting up connection info from grpc handler");
            __builtin_memcpy(&trace->conn, &t->conn, sizeof(connection_info_t));
            found_conn = 1;
        }
    }

    if (!found_conn) {
        bpf_dbg_printk("can't find connection info for st_ptr: %llx", st_ptr);
        __builtin_memset(&trace->conn, 0, sizeof(connection_info_t));
    }

    // Server connections have port order reversed from what we want
    swap_connection_info_order(&trace->conn);
    trace->tp = invocation->tp;
    trace->end_monotime_ns = bpf_ktime_get_ns();
    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

done:
    bpf_map_delete_elem(&ongoing_grpc_server_requests, &g_key);
    bpf_map_delete_elem(&ongoing_grpc_request_status, &g_key);
    bpf_map_delete_elem(&go_trace_map, &g_key);
    obi_ctx__del(bpf_get_current_pid_tgid());

    return 0;
}

SEC("uprobe/transport_writeStatus")
int GUARDED_PROG(obi_uprobe_transport_writeStatus, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/transport_writeStatus ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    off_table_t *ot = get_offsets_table();

    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    void *status_ptr = GO_PARAM3(ctx);
    bpf_dbg_printk("status_ptr=%lx", status_ptr);

    if (status_ptr != NULL) {
        void *s_ptr;
        bpf_probe_read(
            &s_ptr,
            sizeof(s_ptr),
            (void *)(status_ptr + go_offset_of(ot, (go_offset){.v = _grpc_status_s_pos})));

        bpf_dbg_printk("s_ptr=%lx", s_ptr);

        if (s_ptr != NULL) {
            u16 status = -1;
            bpf_probe_read(
                &status,
                sizeof(status),
                (void *)(s_ptr + go_offset_of(ot, (go_offset){.v = _grpc_status_code_ptr_pos})));
            bpf_dbg_printk("status=%d", status);
            bpf_map_update_elem(&ongoing_grpc_request_status, &g_key, &status, BPF_ANY);
        }
    }

    return 0;
}

/* GRPC client */
static __always_inline void clientConnStart(
    void *goroutine_addr, void *cc_ptr, void *ctx_ptr, void *method_ptr, void *method_len) {
    grpc_client_func_invocation_t invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .cc = (u64)cc_ptr,
        .method = (u64)method_ptr,
        .method_len = (u64)method_len,
        .tp = {0},
        .flags = 0,
    };
    off_table_t *ot = get_offsets_table();
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    if (ctx_ptr) {
        void *val_ptr = 0;
        // Read the embedded val object ptr from ctx if there's one
        bpf_probe_read(&val_ptr,
                       sizeof(val_ptr),
                       (void *)(ctx_ptr +
                                go_offset_of(ot, (go_offset){.v = _value_context_val_ptr_pos}) +
                                sizeof(void *)));

        invocation.flags = client_trace_parent(goroutine_addr, &invocation.tp);
    } else {
        // it's OK sending empty tp for a client, the userspace id generator will make random trace_id, span_id
        bpf_dbg_printk("No ctx_ptr: %llx", ctx_ptr);
    }

    // Write event
    if (bpf_map_update_elem(&ongoing_grpc_client_requests, &g_key, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update grpc client map element");
    }

    obi_ctx__set(bpf_get_current_pid_tgid(), &invocation.tp);
}

SEC("uprobe/ClientConn_Invoke")
int GUARDED_PROG(obi_uprobe_ClientConn_Invoke, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/ClientConn_Invoke ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

    void *cc_ptr = GO_PARAM1(ctx);
    void *ctx_ptr = GO_PARAM3(ctx);
    void *method_ptr = GO_PARAM4(ctx);
    void *method_len = GO_PARAM5(ctx);

    clientConnStart(goroutine_addr, cc_ptr, ctx_ptr, method_ptr, method_len);

    return 0;
}

// Same as ClientConn_Invoke, registers for the method are offset by one
SEC("uprobe/ClientConn_NewStream")
int GUARDED_PROG(obi_uprobe_ClientConn_NewStream, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/ClientConn_NewStream ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

    void *cc_ptr = GO_PARAM1(ctx);
    void *ctx_ptr = GO_PARAM3(ctx);
    void *method_ptr = GO_PARAM5(ctx);
    void *method_len = GO_PARAM6(ctx);

    clientConnStart(goroutine_addr, cc_ptr, ctx_ptr, method_ptr, method_len);

    return 0;
}

static __always_inline int grpc_connect_done(struct pt_regs *ctx, void *err) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    grpc_client_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_grpc_client_requests, &g_key);

    if (invocation == NULL) {
        bpf_dbg_printk("can't read grpc client invocation metadata");
        goto done;
    }

    http_request_trace_t *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace_t), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        goto done;
    }

    task_pid(&trace->pid);
    trace->type = EVENT_GRPC_CLIENT;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->go_start_monotime_ns = invocation->start_monotime_ns;
    trace->end_monotime_ns = bpf_ktime_get_ns();
    trace->content_length = 0;
    trace->method[0] = '\0';
    trace->host[0] = '\0';
    trace->scheme[0] = '\0';
    trace->pattern[0] = '\0';
    trace->path[0] = '\0';
    trace->is_jsonrpc = false;

    // Read arguments from the original set of registers

    // Get client request value pointers
    void *method_ptr = (void *)invocation->method;
    void *method_len = (void *)invocation->method_len;

    bpf_dbg_printk("method_ptr=%lx, method_len=%d", method_ptr, method_len);

    // Get method from the incoming call arguments
    if (!read_go_str_n("method", method_ptr, (u64)method_len, trace->path, sizeof(trace->path))) {
        bpf_dbg_printk("can't read grpc client method");
        bpf_ringbuf_discard(trace, 0);
        goto done;
    }

    connection_info_t *info = bpf_map_lookup_elem(&ongoing_client_connections, &g_key);

    if (info) {
        __builtin_memcpy(&trace->conn, info, sizeof(connection_info_t));
    } else {
        __builtin_memset(&trace->conn, 0, sizeof(connection_info_t));
    }

    trace->tp = invocation->tp;

    trace->status =
        (err)
            ? 2
            : 0; // Getting the gRPC client status is complex, if there's an error we set Code.Unknown = 2

    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

done: {
    go_h2_stream_key_t *stream = bpf_map_lookup_elem(&grpc_stream_by_request, &g_key);
    if (stream) {
        const go_h2_stream_key_t stream_key = *stream;
        audit_go_h2_stream(
            &stream_key, k_go_h2_protocol_grpc, k_go_h2_audit_cleanup, k_go_h2_state_unknown, 0);
        bpf_map_delete_elem(&go_h2_stream_states, &stream_key);
        bpf_map_delete_elem(&grpc_stream_by_request, &g_key);
    }
}
    bpf_map_delete_elem(&ongoing_grpc_client_requests, &g_key);
    obi_ctx__del(bpf_get_current_pid_tgid());
    return 0;
}

// Same as ClientConn_Invoke, registers for the method are offset by one
SEC("uprobe/ClientConn_NewStream")
int GUARDED_PROG(obi_uprobe_ClientConn_NewStream_return, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/ClientConn_NewStream ===");

    void *stream = GO_PARAM1(ctx);

    if (!stream) {
        return grpc_connect_done(ctx, (void *)1);
    }

    return 0;
}

SEC("uprobe/ClientConn_Close")
int GUARDED_PROG(obi_uprobe_ClientConn_Close, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/ClientConn_Close ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    bpf_map_delete_elem(&ongoing_grpc_client_requests, &g_key);
    obi_ctx__del(bpf_get_current_pid_tgid());

    return 0;
}

SEC("uprobe/ClientConn_Invoke")
int GUARDED_PROG(obi_uprobe_ClientConn_Invoke_return, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/ClientConn_Invoke ===");

    void *err = GO_PARAM1(ctx);

    if (err) {
        return grpc_connect_done(ctx, err);
    }

    return 0;
}

// google.golang.org/grpc.(*clientStream).RecvMsg
SEC("uprobe/clientStream_RecvMsg")
int GUARDED_PROG(obi_uprobe_clientStream_RecvMsg_return, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/clientStream_RecvMsg ===");
    void *err = (void *)GO_PARAM1(ctx);
    return grpc_connect_done(ctx, err);
}

// The gRPC client stream is written on another goroutine in transport loopyWriter (controlbuf.go).
// We extract the stream ID when it's just created and make a mapping of it to our goroutine that's executing ClientConn.Invoke.
SEC("uprobe/transport_http2Client_NewStream")
int GUARDED_PROG(obi_uprobe_transport_http2Client_NewStream, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/transport_http2Client_NewStream ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    void *t_ptr = GO_PARAM1(ctx);
    off_table_t *ot = get_offsets_table();
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    const u64 grpc_t_conn_pos = go_offset_of(ot, (go_offset){.v = _grpc_t_scheme_pos});
    bpf_dbg_printk(
        "goroutine_addr=%lx, t_ptr=%llx, t.conn_pos=%x", goroutine_addr, t_ptr, grpc_t_conn_pos);

    if (t_ptr) {
        void *conn_ptr = t_ptr + go_offset_of(ot, (go_offset){.v = _grpc_t_conn_pos}) + 8;
        unsigned char buf[16];
        u64 is_secure = 0;
        void *conn_ptr_key = 0;

        if (g_bpf_header_propagation && conn_ptr) {
            bpf_probe_read(&conn_ptr_key, sizeof(conn_ptr_key), conn_ptr);
        }

        // PID-scoped cache key: uses the transport pointer as the address
        // component to avoid stale entries when pointer values are recycled
        // across different processes.
        go_addr_key_t cache_key = {};
        go_addr_key_from_id(&cache_key, t_ptr);

        connection_info_t *cached_conn =
            bpf_map_lookup_elem(&cached_grpc_client_connections, &cache_key);
        // reading the connection can be expensive for high volume of
        // new grpc client connections. We cache it, since most grpc client
        // connections are long lived.
        if (!cached_conn) {
            void *s_ptr = 0;
            buf[0] = 0;
            bpf_probe_read(&s_ptr, sizeof(s_ptr), (void *)(t_ptr + grpc_t_conn_pos));
            bpf_probe_read(buf, sizeof(buf), s_ptr);

            //bpf_dbg_printk("scheme=%s", buf);

            if (buf[0] == 'h' && buf[1] == 't' && buf[2] == 't' && buf[3] == 'p' && buf[4] == 's') {
                is_secure = 1;
            }

            if (is_secure) {
                // double wrapped in grpc
                conn_ptr = unwrap_tls_conn_info(conn_ptr, (void *)is_secure);
                conn_ptr = unwrap_tls_conn_info(conn_ptr, (void *)is_secure);
            }
            bpf_dbg_printk("conn_ptr=%llx, is_secure=%lld", conn_ptr, is_secure);
            if (conn_ptr) {
                void *conn_conn_ptr = 0;
                bpf_probe_read(&conn_conn_ptr, sizeof(conn_conn_ptr), conn_ptr);
                bpf_dbg_printk("conn_conn_ptr=%llx", conn_conn_ptr);
                if (conn_conn_ptr) {
                    connection_info_t conn = {0};
                    const u8 ok = get_conn_info(conn_conn_ptr, &conn);
                    if (ok) {
                        bpf_map_update_elem(&ongoing_client_connections, &g_key, &conn, BPF_ANY);
                        bpf_map_update_elem(
                            &cached_grpc_client_connections, &cache_key, &conn, BPF_ANY);

                        if (conn_ptr_key) {
                            go_addr_key_t conn_key = {};
                            go_addr_key_from_id(&conn_key, conn_ptr_key);
                            bpf_map_update_elem(&grpc_conn_ptr_to_conn, &conn_key, &conn, BPF_ANY);
                        }
                    }
                }
            }
        } else {
            bpf_map_update_elem(&ongoing_client_connections, &g_key, cached_conn, BPF_ANY);

            if (conn_ptr_key) {
                go_addr_key_t conn_key = {};
                go_addr_key_from_id(&conn_key, conn_ptr_key);
                bpf_map_update_elem(&grpc_conn_ptr_to_conn, &conn_key, cached_conn, BPF_ANY);
            }
        }

        if (g_bpf_header_propagation) {
            connection_info_t *known_conn =
                bpf_map_lookup_elem(&ongoing_client_connections, &g_key);
            if (known_conn) {
                go_h2_conn_key_t semantic_conn = {
                    .p_conn =
                        {
                            .conn = *known_conn,
                            .pid = pid_from_pid_tgid(bpf_get_current_pid_tgid()),
                        },
                };
                set_go_h2_process_identity(&semantic_conn.process_start_lo,
                                           &semantic_conn.process_start_hi);
                mark_go_h2_client_conn(&semantic_conn, k_go_h2_protocol_grpc, bpf_ktime_get_ns());
            }

            bpf_dbg_printk("conn_ptr_key=%llx", conn_ptr_key);

            grpc_client_func_invocation_t *invocation =
                bpf_map_lookup_elem(&ongoing_grpc_client_requests, &g_key);

            if (invocation && conn_ptr_key) {
                transport_new_client_invocation_t wrapper = {};
                wrapper.inv = *invocation;
                wrapper.s_key.stream_id = 0;
                wrapper.s_key.conn_ptr = (u64)conn_ptr_key;
                wrapper.request_key = g_key;

                bpf_map_update_elem(&transport_new_client_invocations, &g_key, &wrapper, BPF_ANY);
            } else {
                bpf_dbg_printk(
                    "Couldn't find invocation metadata for goroutine=%lx, conn_ptr_key=%llx",
                    goroutine_addr,
                    conn_ptr_key);
            }
        }
    }

    return 0;
}

SEC("uprobe/transport_http2Client_NewStream_ret")
int GUARDED_PROG(obi_uprobe_transport_http2Client_NewStream_Returns, struct pt_regs *, ctx) {
    if (!g_bpf_header_propagation) {
        return 0;
    }

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, GOROUTINE_PTR(ctx));
    bpf_map_delete_elem(&transport_new_client_invocations, &g_key);
    return 0;
}

#define MAX_W_PTR_OFFSET 65535

SEC("uprobe/grpcFramerWriteHeaders")
int GUARDED_PROG(obi_uprobe_grpcFramerWriteHeaders, struct pt_regs *, ctx) {
    if (!g_bpf_header_propagation) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/grpcFramerWriteHeaders ===");

    void *framer = GO_PARAM1(ctx);
    off_table_t *ot = get_offsets_table();
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, GOROUTINE_PTR(ctx));
    active_h2_invocation_t *active = bpf_map_lookup_elem(&active_h2_invocations, &g_key);
    if (!framer || !active || !active->stream.stream_id) {
        return 0;
    }
    const u64 stream_id = active->stream.stream_id;

    const u64 framer_w_pos = go_offset_of(ot, (go_offset){.v = _framer_w_pos});

    if (framer_w_pos == -1) {
        bpf_dbg_printk("framer w not found");
        return 0;
    }

    bpf_dbg_printk(
        "framer=%llx, stream_id=%llu, framer_w_pos=%llx", framer, stream_id, framer_w_pos);

    void *w_ptr = (void *)(framer + framer_w_pos + 16);
    bpf_probe_read(&w_ptr, sizeof(w_ptr), (void *)(framer + framer_w_pos + 8));

    if (!w_ptr) {
        bpf_dbg_printk("w ptr is 0");
        return 0;
    }

    go_h2_stream_value_t *state = fresh_go_h2_stream_state(&active->stream, bpf_ktime_get_ns());
    if (!state || state->state != k_go_h2_state_observing) {
        return 0;
    }
    if (!active->observed || active->read_failed) {
        state->state = k_go_h2_state_skip;
        state->updated_ns = bpf_ktime_get_ns();
        audit_go_h2_stream(&active->stream,
                           k_go_h2_protocol_grpc,
                           k_go_h2_audit_missing,
                           state->state,
                           &state->tp);
        return 0;
    }

    state->state = k_go_h2_state_obi_pending;
    state->updated_ns = bpf_ktime_get_ns();
    grpc_framer_func_invocation_t f_info = {
        .framer_ptr = (u64)framer,
        .offset = -1,
        .stream = active->stream,
        .frame_type = k_h2_frame_headers,
    };
    s64 offset = -1;
    if (bpf_probe_read_user(
            &offset,
            sizeof(offset),
            (void *)(w_ptr +
                     go_offset_of(ot, (go_offset){.v = _grpc_transport_buf_writer_offset_pos}))) ==
            0 &&
        offset >= 0 && offset < MAX_W_PTR_OFFSET) {
        f_info.offset = offset;
    }
    bpf_map_update_elem(&grpc_framer_invocation_map, &g_key, &f_info, BPF_ANY);
    return 0;
}

SEC("uprobe/grpcFramerWriteContinuation")
int GUARDED_PROG(obi_uprobe_grpcFramerWriteContinuation, struct pt_regs *, ctx) {
    if (!g_bpf_header_propagation) {
        return 0;
    }

    void *framer = GO_PARAM1(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, GOROUTINE_PTR(ctx));
    active_h2_invocation_t *active = bpf_map_lookup_elem(&active_h2_invocations, &g_key);
    if (!framer || !active || !active->stream.stream_id) {
        return 0;
    }
    go_h2_stream_value_t *state = fresh_go_h2_stream_state(&active->stream, bpf_ktime_get_ns());
    if (!state || state->state != k_go_h2_state_obi_pending) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();
    const u64 framer_w_pos = go_offset_of(ot, (go_offset){.v = _framer_w_pos});
    void *w_ptr = 0;
    bpf_probe_read(&w_ptr, sizeof(w_ptr), (void *)(framer + framer_w_pos + 8));
    grpc_framer_func_invocation_t f_info = {
        .framer_ptr = (u64)framer,
        .offset = -1,
        .stream = active->stream,
        .frame_type = k_h2_frame_continuation,
    };
    s64 offset = -1;
    if (w_ptr &&
        bpf_probe_read_user(
            &offset,
            sizeof(offset),
            (void *)(w_ptr +
                     go_offset_of(ot, (go_offset){.v = _grpc_transport_buf_writer_offset_pos}))) ==
            0 &&
        offset >= 0 && offset < MAX_W_PTR_OFFSET) {
        f_info.offset = offset;
    }
    bpf_map_update_elem(&grpc_framer_invocation_map, &g_key, &f_info, BPF_ANY);
    return 0;
}

static __always_inline void reserve_go_h2_padding(struct pt_regs *ctx,
                                                  go_offset_const pad_offset,
                                                  go_offset_const wbuf_offset) {
    if (!g_bpf_header_propagation || g_go_h2_force_socket_fallback) {
        return;
    }

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, GOROUTINE_PTR(ctx));
    const u64 stack_offset = go_offset_of(get_offsets_table(), (go_offset){.v = pad_offset});
    if (stack_offset == (u64)-1 || stack_offset < 34 || stack_offset >= 512) {
        return;
    }
    unsigned char *pad_ptr = (unsigned char *)PT_REGS_SP(ctx) + stack_offset;
    u32 param_stream_id = 0;
    if (bpf_probe_read_user(&param_stream_id, sizeof(param_stream_id), pad_ptr - 34) != 0 ||
        !param_stream_id) {
        return;
    }
    go_h2_stream_key_t *stream = 0;
    bool *reserved = 0;
    void *framer = 0;
    framer_func_invocation_t *http_info = 0;
    grpc_framer_func_invocation_t *grpc_info =
        bpf_map_lookup_elem(&grpc_framer_invocation_map, &g_key);
    if (grpc_info && grpc_info->frame_type == k_h2_frame_headers) {
        if (grpc_info->stream.stream_id != param_stream_id) {
            return;
        }
        framer = (void *)grpc_info->framer_ptr;
        stream = &grpc_info->stream;
        reserved = &grpc_info->reserved_padding;
    } else {
        http_info = bpf_map_lookup_elem(&framer_invocation_map, &g_key);
        if (http_info && http_info->frame_type == k_h2_frame_headers) {
            stream_key_t s_key = {
                .conn_ptr = http_info->framer_ptr,
                .stream_id = param_stream_id,
            };
            go_h2_stream_key_t *exact_stream = bpf_map_lookup_elem(&http2_req_map, &s_key);
            if (!exact_stream) {
                return;
            }
            http_info->stream = *exact_stream;
            framer = (void *)http_info->framer_ptr;
            stream = &http_info->stream;
            reserved = &http_info->reserved_padding;
        }
    }
    if (!stream || !reserved || *reserved) {
        return;
    }
    go_h2_stream_value_t *state = fresh_go_h2_stream_state(stream, bpf_ktime_get_ns());
    if (!state || state->state != k_go_h2_state_obi_pending) {
        return;
    }

    off_table_t *ot = get_offsets_table();
    const u64 wbuf_pos = go_offset_of(ot, (go_offset){.v = wbuf_offset});
    if (wbuf_pos == (u64)-1) {
        return;
    }
    void *buf = 0;
    s64 n = 0;
    long err = bpf_probe_read_user(&buf, sizeof(buf), (unsigned char *)framer + wbuf_pos);
    err |= bpf_probe_read_user(
        &n, sizeof(n), (unsigned char *)framer + wbuf_pos + k_go_slice_len_offset);
    if (err || !buf || n != k_h2_frame_header_len) {
        return;
    }

    unsigned char header[k_h2_frame_header_len] = {};
    if (bpf_probe_read_user(header, sizeof(header), buf) != 0) {
        return;
    }
    u32 wire_stream_id = 0;
    __builtin_memcpy(&wire_stream_id, &header[5], sizeof(wire_stream_id));
    wire_stream_id = bpf_ntohl(wire_stream_id) & 0x7fffffff;
    if (header[3] != k_h2_frame_headers || wire_stream_id != param_stream_id ||
        !(header[4] & k_h2_flag_end_headers) || (header[4] & k_h2_flag_padded)) {
        return;
    }

    u8 original_pad = 0;
    u64 fragment_len = 0;
    err = bpf_probe_read_user(&original_pad, sizeof(original_pad), pad_ptr);
    err |= bpf_probe_read_user(&fragment_len, sizeof(fragment_len), pad_ptr - 2 * sizeof(u64) - 2);
    const u64 max_fragment = k_h2_default_max_frame_size - k_h2_tp_hpack_size - 6;
    if (err || original_pad || fragment_len > max_fragment) {
        return;
    }

    const u8 padding = k_h2_tp_hpack_size;
    u8 readback = 0;
    err = bpf_probe_write_user(pad_ptr, &padding, sizeof(padding));
    err |= bpf_probe_read_user(&readback, sizeof(readback), pad_ptr);
    if (err || readback != padding) {
        return;
    }

    unsigned char *flags_ptr = (unsigned char *)buf + 4;
    const u8 padded_flags = header[4] | k_h2_flag_padded;
    u8 flags_readback = header[4];
    err = bpf_probe_write_user(flags_ptr, &padded_flags, sizeof(padded_flags));
    err |= bpf_probe_read_user(&flags_readback, sizeof(flags_readback), flags_ptr);
    if (!err && flags_readback == padded_flags) {
        *reserved = true;
        return;
    }

    const u8 no_padding = 0;
    readback = padding;
    flags_readback = padded_flags;
    long rollback = bpf_probe_write_user(pad_ptr, &no_padding, sizeof(no_padding));
    rollback |= bpf_probe_write_user(flags_ptr, &header[4], sizeof(header[4]));
    rollback |= bpf_probe_read_user(&readback, sizeof(readback), pad_ptr);
    rollback |= bpf_probe_read_user(&flags_readback, sizeof(flags_readback), flags_ptr);
    if (rollback || readback != no_padding || flags_readback != header[4]) {
        state = fresh_go_h2_stream_state(stream, bpf_ktime_get_ns());
        if (state && state->state == k_go_h2_state_obi_pending) {
            state->state = k_go_h2_state_skip;
            state->updated_ns = bpf_ktime_get_ns();
        }
    }
}

SEC("uprobe/goH2ReservePadding")
int GUARDED_PROG(obi_uprobe_goH2ReservePadding, struct pt_regs *, ctx) {
    reserve_go_h2_padding(ctx, _framer_pad_length_stack_pos, _framer_wbuf_pos);
    return 0;
}

SEC("uprobe/goH2ReservePaddingVendored")
int GUARDED_PROG(obi_uprobe_goH2ReservePaddingVendored, struct pt_regs *, ctx) {
    reserve_go_h2_padding(ctx, _framer_pad_length_stack_vendored_pos, _framer_wbuf_vendored_pos);
    return 0;
}

SEC("uprobe/grpcFramerWriteHeaders_returns")
int GUARDED_PROG(obi_uprobe_grpcFramerWriteHeaders_returns, struct pt_regs *, ctx) {
    if (!g_bpf_header_propagation || !g_bpf_probe_write_user_enabled) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/grpcFramerWriteHeaders_returns ===");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    off_table_t *ot = get_offsets_table();
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    grpc_framer_func_invocation_t *f_info =
        bpf_map_lookup_elem(&grpc_framer_invocation_map, &g_key);

    if (f_info) {
        go_h2_stream_value_t *state = fresh_go_h2_stream_state(&f_info->stream, bpf_ktime_get_ns());
        if (!state || state->state != k_go_h2_state_obi_pending) {
            goto done_framer;
        }

        void *w_ptr =
            (void *)(f_info->framer_ptr + go_offset_of(ot, (go_offset){.v = _framer_w_pos}) + 16);
        bpf_probe_read(
            &w_ptr,
            sizeof(w_ptr),
            (void *)(f_info->framer_ptr + go_offset_of(ot, (go_offset){.v = _framer_w_pos}) + 8));

        if (w_ptr) {
            void *buf_arr = 0;
            s64 n = -1;
            s64 cap = -1;
            const u64 buf_pos =
                go_offset_of(ot, (go_offset){.v = _grpc_transport_buf_writer_buf_pos});
            const u64 n_pos =
                go_offset_of(ot, (go_offset){.v = _grpc_transport_buf_writer_offset_pos});
            long read_err =
                bpf_probe_read_user(&buf_arr, sizeof(buf_arr), (void *)(w_ptr + buf_pos));
            read_err |= bpf_probe_read_user(&n, sizeof(n), (void *)(w_ptr + n_pos));
            read_err |= bpf_probe_read_user(
                &cap, sizeof(cap), (void *)(w_ptr + buf_pos + 2 * sizeof(void *)));
            if (!read_err) {
                const u8 result = g_go_h2_force_socket_fallback || f_info->reserved_padding
                                      ? k_go_h2_user_write_pristine
                                      : append_go_h2_traceparent(w_ptr,
                                                                 n_pos,
                                                                 buf_arr,
                                                                 f_info->offset,
                                                                 n,
                                                                 cap,
                                                                 f_info->stream.stream_id,
                                                                 f_info->frame_type,
                                                                 &state->tp,
                                                                 true);
                state = fresh_go_h2_stream_state(&f_info->stream, bpf_ktime_get_ns());
                if (state && state->state == k_go_h2_state_obi_pending) {
                    const u8 next_state = go_h2_state_after_user_write(state->state, result);
                    if (next_state != state->state) {
                        state->state = next_state;
                        state->updated_ns = bpf_ktime_get_ns();
                        audit_go_h2_stream(&f_info->stream,
                                           k_go_h2_protocol_grpc,
                                           next_state == k_go_h2_state_obi_written
                                               ? k_go_h2_audit_direct_commit
                                               : k_go_h2_audit_rollback,
                                           state->state,
                                           &state->tp);
                    }
                }
            }
        }
    }

done_framer:
    bpf_map_delete_elem(&grpc_framer_invocation_map, &g_key);
    return 0;
}

static __always_inline void commit_go_h2_preflush(const go_h2_stream_key_t *stream,
                                                  u8 protocol,
                                                  u8 frame_type,
                                                  void *framer,
                                                  go_offset_const wbuf_offset,
                                                  bool frame_length_ready,
                                                  bool reserved_padding) {
    go_h2_stream_value_t *state = fresh_go_h2_stream_state(stream, bpf_ktime_get_ns());
    if (!state || state->state != k_go_h2_state_obi_pending || !framer) {
        return;
    }

    off_table_t *ot = get_offsets_table();
    const u64 wbuf_pos = go_offset_of(ot, (go_offset){.v = wbuf_offset});
    if (wbuf_pos == (u64)-1) {
        return;
    }

    void *buf = 0;
    s64 n = -1;
    s64 cap = -1;
    long read_err = bpf_probe_read_user(&buf, sizeof(buf), (unsigned char *)framer + wbuf_pos);
    read_err |= bpf_probe_read_user(
        &n, sizeof(n), (unsigned char *)framer + wbuf_pos + k_go_slice_len_offset);
    read_err |= bpf_probe_read_user(
        &cap, sizeof(cap), (unsigned char *)framer + wbuf_pos + 2 * sizeof(void *));
    if (read_err) {
        return;
    }

    u8 result = k_go_h2_user_write_pristine;
    if (!g_go_h2_force_socket_fallback) {
        if (reserved_padding) {
            if (!frame_length_ready) {
                result = commit_go_h2_reserved_padding(buf, n, stream->stream_id, &state->tp);
            }
        } else if (frame_length_ready) {
            result = append_go_h2_traceparent((unsigned char *)framer + wbuf_pos,
                                              k_go_slice_len_offset,
                                              buf,
                                              0,
                                              n,
                                              cap,
                                              stream->stream_id,
                                              frame_type,
                                              &state->tp,
                                              true);
        } else {
            result = append_go_h2_traceparent_preflush((unsigned char *)framer + wbuf_pos,
                                                       k_go_slice_len_offset,
                                                       buf,
                                                       n,
                                                       cap,
                                                       stream->stream_id,
                                                       frame_type,
                                                       &state->tp);
        }
    }
    state = fresh_go_h2_stream_state(stream, bpf_ktime_get_ns());
    if (!state || state->state != k_go_h2_state_obi_pending) {
        return;
    }
    const u8 next_state = go_h2_state_after_user_write(state->state, result);
    if (next_state != state->state) {
        state->state = next_state;
        state->updated_ns = bpf_ktime_get_ns();
        u8 event = k_go_h2_audit_rollback;
        if (next_state == k_go_h2_state_obi_written) {
            event =
                frame_length_ready ? k_go_h2_audit_prewrite_commit : k_go_h2_audit_direct_commit;
        }
        audit_go_h2_stream(stream, protocol, event, state->state, &state->tp);
    }
}

static __always_inline int on_go_h2_framer_end_write(struct pt_regs *ctx,
                                                     go_offset_const wbuf_offset,
                                                     bool frame_length_ready) {
    if (!g_bpf_header_propagation) {
        return 0;
    }

    void *entry_framer = frame_length_ready ? 0 : GO_PARAM1(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, GOROUTINE_PTR(ctx));
    grpc_framer_func_invocation_t *grpc_info =
        bpf_map_lookup_elem(&grpc_framer_invocation_map, &g_key);
    if (grpc_info && grpc_info->framer_ptr &&
        (frame_length_ready || grpc_info->framer_ptr == (u64)entry_framer)) {
        commit_go_h2_preflush(&grpc_info->stream,
                              k_go_h2_protocol_grpc,
                              grpc_info->frame_type,
                              (void *)grpc_info->framer_ptr,
                              wbuf_offset,
                              frame_length_ready,
                              grpc_info->reserved_padding);
    }

    framer_func_invocation_t *http_info = bpf_map_lookup_elem(&framer_invocation_map, &g_key);
    if (http_info && http_info->framer_ptr &&
        (frame_length_ready || http_info->framer_ptr == (u64)entry_framer)) {
        commit_go_h2_preflush(&http_info->stream,
                              k_go_h2_protocol_http,
                              http_info->frame_type,
                              (void *)http_info->framer_ptr,
                              wbuf_offset,
                              frame_length_ready,
                              http_info->reserved_padding);
    }
    return 0;
}

SEC("uprobe/goH2FramerEndWrite")
int GUARDED_PROG(obi_uprobe_goH2FramerEndWrite, struct pt_regs *, ctx) {
    return on_go_h2_framer_end_write(ctx, _framer_wbuf_pos, false);
}

SEC("uprobe/goH2FramerEndWriteVendored")
int GUARDED_PROG(obi_uprobe_goH2FramerEndWriteVendored, struct pt_regs *, ctx) {
    return on_go_h2_framer_end_write(ctx, _framer_wbuf_vendored_pos, false);
}

SEC("uprobe/goH2FramerPreWrite")
int GUARDED_PROG(obi_uprobe_goH2FramerPreWrite, struct pt_regs *, ctx) {
    return on_go_h2_framer_end_write(ctx, _framer_wbuf_pos, true);
}

SEC("uprobe/goH2FramerPreWriteVendored")
int GUARDED_PROG(obi_uprobe_goH2FramerPreWriteVendored, struct pt_regs *, ctx) {
    return on_go_h2_framer_end_write(ctx, _framer_wbuf_vendored_pos, true);
}

SEC("uprobe/controlBuffer_executeAndPut")
int GUARDED_PROG(obi_uprobe_grpc_controlBuffer_executeAndPut, struct pt_regs *, ctx) {
    if (!g_bpf_header_propagation) {
        return 0;
    }
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    transport_new_client_invocation_t *wrapper =
        bpf_map_lookup_elem(&transport_new_client_invocations, &g_key);
    if (!wrapper) {
        return 0; // not from a NewStream goroutine — ignore
    }

    void *hdr = (void *)GO_PARAM4(ctx); // it.data
    if (!hdr) {
        return 0;
    }
    go_addr_key_t hdr_key = {};
    go_addr_key_from_id(&hdr_key, hdr);
    pending_h2_invocation_t pending = {
        .tp = wrapper->inv.tp,
        .request_key = wrapper->request_key,
        .conn_ptr = wrapper->s_key.conn_ptr,
        .updated_ns = bpf_ktime_get_ns(),
    };
    if (bpf_map_update_elem(&pending_h2_invocations, &hdr_key, &pending, BPF_ANY) == 0) {
        bpf_map_update_elem(&pending_h2_execute_calls, &g_key, &hdr_key, BPF_ANY);
    }
    return 0;
}

SEC("uprobe/controlBuffer_executeAndPut_returns")
int GUARDED_PROG(obi_uprobe_grpc_controlBuffer_executeAndPut_returns, struct pt_regs *, ctx) {
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, GOROUTINE_PTR(ctx));
    go_addr_key_t *hdr_key = bpf_map_lookup_elem(&pending_h2_execute_calls, &g_key);
    if (!hdr_key) {
        return 0;
    }

    const bool queued = (bool)GO_PARAM1(ctx);
    const void *err_type = (void *)GO_PARAM2(ctx);
    if (!queued || err_type) {
        bpf_map_delete_elem(&pending_h2_invocations, hdr_key);
    }
    bpf_map_delete_elem(&pending_h2_execute_calls, &g_key);
    return 0;
}

static __always_inline int on_grpc_client_header_handler(struct pt_regs *ctx) {
    if (!g_bpf_header_propagation) {
        return 0;
    }
    void *hdr = (void *)GO_PARAM2(ctx);
    if (!hdr) {
        return 0;
    }
    go_addr_key_t hdr_key = {};
    go_addr_key_from_id(&hdr_key, hdr);
    pending_h2_invocation_t *pending = bpf_map_lookup_elem(&pending_h2_invocations, &hdr_key);
    if (!pending) {
        return 0;
    }
    if (!go_h2_timestamp_is_fresh(pending->updated_ns, bpf_ktime_get_ns())) {
        bpf_map_delete_elem(&pending_h2_invocations, &hdr_key);
        return 0;
    }
    const tp_info_t tp = pending->tp;
    const go_addr_key_t request_key = pending->request_key;
    const u64 conn_ptr = pending->conn_ptr;
    bpf_map_delete_elem(&pending_h2_invocations, &hdr_key);

    u32 stream_id = 0;
    if (bpf_probe_read_user(&stream_id, sizeof(stream_id), hdr) != 0 || stream_id == 0) {
        return 0;
    }

    go_addr_key_t conn_key = {};
    go_addr_key_from_id(&conn_key, (void *)conn_ptr);
    connection_info_t *conn_info = bpf_map_lookup_elem(&grpc_conn_ptr_to_conn, &conn_key);
    if (!conn_info || !valid_trace(tp.trace_id)) {
        return 0;
    }

    const u64 now = bpf_ktime_get_ns();
    const u32 pid = pid_from_pid_tgid(bpf_get_current_pid_tgid());
    go_h2_stream_key_t stream = {
        .p_conn = {.conn = *conn_info, .pid = pid},
        .stream_id = stream_id,
    };
    set_go_h2_stream_process_identity(&stream);
    go_h2_stream_value_t state = {
        .tp = tp,
        .updated_ns = now,
        .state = k_go_h2_state_observing,
        .protocol = k_go_h2_protocol_grpc,
    };
    mark_go_h2_client_conn(go_h2_stream_conn_key(&stream), k_go_h2_protocol_grpc, now);
    if (!publish_go_h2_stream_state(&stream, &state)) {
        audit_go_h2_stream(
            &stream, k_go_h2_protocol_grpc, k_go_h2_audit_missing, k_go_h2_state_skip, &state.tp);
        return 0;
    }

    go_addr_key_t handler_key = {};
    go_addr_key_from_id(&handler_key, GOROUTINE_PTR(ctx));
    active_h2_invocation_t active = {
        .stream = stream,
    };
    if (bpf_map_update_elem(&active_h2_invocations, &handler_key, &active, BPF_NOEXIST) != 0 ||
        bpf_map_update_elem(&grpc_stream_by_request, &request_key, &stream, BPF_ANY) != 0) {
        go_h2_stream_value_t *current = fresh_go_h2_stream_state(&stream, bpf_ktime_get_ns());
        if (current) {
            current->state = k_go_h2_state_skip;
            current->updated_ns = bpf_ktime_get_ns();
        }
        bpf_map_delete_elem(&active_h2_invocations, &handler_key);
        return 0;
    }
    audit_go_h2_stream(
        &stream, k_go_h2_protocol_grpc, k_go_h2_audit_published, state.state, &state.tp);
    return 0;
}

SEC("uprobe/loopyWriter_headerHandler")
int GUARDED_PROG(obi_uprobe_grpc_loopyWriter_headerHandler, struct pt_regs *, ctx) {
    return on_grpc_client_header_handler(ctx);
}

SEC("uprobe/loopyWriter_clientHeaderHandler")
int GUARDED_PROG(obi_uprobe_grpc_loopyWriter_clientHeaderHandler, struct pt_regs *, ctx) {
    return on_grpc_client_header_handler(ctx);
}

SEC("uprobe/loopyWriter_clientHeaderHandler_returns")
int GUARDED_PROG(obi_uprobe_grpc_loopyWriter_clientHeaderHandler_returns, struct pt_regs *, ctx) {
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, GOROUTINE_PTR(ctx));
    bpf_map_delete_elem(&active_h2_invocations, &g_key);
    return 0;
}

SEC("uprobe/grpcHpackEncoderWriteField")
int GUARDED_PROG(obi_uprobe_grpcHpackEncoderWriteField, struct pt_regs *, ctx) {
    if (!g_bpf_header_propagation) {
        return 0;
    }
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, GOROUTINE_PTR(ctx));
    active_h2_invocation_t *active = bpf_map_lookup_elem(&active_h2_invocations, &g_key);
    if (!active) {
        return 0;
    }
    if (!active->observed) {
        active->observed = true;
        go_h2_stream_value_t *state = fresh_go_h2_stream_state(&active->stream, bpf_ktime_get_ns());
        audit_go_h2_stream(&active->stream,
                           k_go_h2_protocol_grpc,
                           k_go_h2_audit_encode_hit,
                           state ? state->state : k_go_h2_state_unknown,
                           state ? &state->tp : 0);
    }

    if ((u64)GO_PARAM3(ctx) != W3C_KEY_LENGTH) {
        return 0;
    }
    unsigned char name[W3C_KEY_LENGTH] = {};
    if (bpf_probe_read_user(name, sizeof(name), (void *)GO_PARAM2(ctx)) != 0) {
        active->read_failed = true;
        go_h2_stream_value_t *state = fresh_go_h2_stream_state(&active->stream, bpf_ktime_get_ns());
        if (state && state->state == k_go_h2_state_observing) {
            state->state = k_go_h2_state_skip;
            state->updated_ns = bpf_ktime_get_ns();
        }
        return 0;
    }
    if (!stricmp((const char *)name, "traceparent", W3C_KEY_LENGTH)) {
        return 0;
    }

    go_h2_stream_value_t *state = fresh_go_h2_stream_state(&active->stream, bpf_ktime_get_ns());
    if (!state || state->state != k_go_h2_state_observing) {
        return 0;
    }
    state->state = k_go_h2_state_app;
    state->updated_ns = bpf_ktime_get_ns();

    egress_key_t e_key = {
        .d_port = active->stream.p_conn.conn.d_port,
        .s_port = active->stream.p_conn.conn.s_port,
        .stream_id = active->stream.stream_id,
    };
    sort_egress_key(&e_key);
    audit_go_h2_stream(
        &active->stream, k_go_h2_protocol_grpc, k_go_h2_audit_observed, state->state, &state->tp);
    return 0;
}
