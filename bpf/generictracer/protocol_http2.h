// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/globals.h>
#include <common/h2_defs.h>
#include <common/iov_iter.h>
#include <common/preempt_guard.h>
#include <common/scratch_mem.h>
#include <common/http_buf_size.h>
#include <common/ringbuf.h>
#include <common/trace_lifecycle.h>
#include <common/trace_parent.h>

#include <maps/tp_info_mem.h>

#include <generictracer/hpack_traceparent_parse.h>
#include <generictracer/http2_grpc.h>
#include <generictracer/k_tracer_tailcall.h>
#include <generictracer/protocol_common.h>
#include <generictracer/types/http2_conn_info_data.h>

#include <generictracer/maps/grpc_frames_ctx_mem.h>
#include <generictracer/maps/http2_info_mem.h>

#include <generictracer/maps/ongoing_http2_grpc.h>

#include <maps/active_ssl_connections.h>
#include <maps/ongoing_http2_connections.h>

// These are bit flags, if you add any use power of 2 values
enum {
    http2_conn_flag_ssl = WITH_SSL,
    http2_conn_flag_new = 0x2,
    h2_hpack_req_unreliable = 0x1,
    h2_hpack_resp_unreliable = 0x2,
    h2_hpack_new_connection = 0x4,
};

// decoder scratch buffers, kept off the BPF stack
SCRATCH_MEM_SIZED(h2_tp_huff_win, k_h2_tp_huff_window)
SCRATCH_MEM_SIZED(h2_tp_huff_out, k_hpack_value_len_tp)

static __always_inline grpc_frames_ctx_t *grpc_ctx() {
    return bpf_map_lookup_elem(&grpc_frames_ctx_mem, &(int){0});
}

static __always_inline u8 http2_flag_ssl(u8 flags) {
    return flags & http2_conn_flag_ssl;
}

static __always_inline u8 http2_flag_new(u8 flags) {
    return flags & http2_conn_flag_new;
}

static __always_inline http2_grpc_request_t *empty_http2_info() {
    http2_grpc_request_t *value = http2_info_mem();
    if (value) {
        // zeroed in two spans around the capture buffers: the struct as a whole
        // is too large for an inline memset, and data is fully overwritten at
        // request start, ret_data at request end
        bpf_memset(value, 0, __builtin_offsetof(http2_grpc_request_t, data));
        bpf_memset(&value->len,
                   0,
                   sizeof(http2_grpc_request_t) - __builtin_offsetof(http2_grpc_request_t, len));
    }
    return value;
}

static __always_inline u64 uniqueHTTP2ConnId(pid_connection_info_t *p_conn) {
    u64 random_id = (u64)bpf_get_prandom_u32() << 32;

    random_id |= ((u32)p_conn->conn.d_port << 16) | p_conn->conn.s_port;

    return random_id;
}

// Use the trace the Go uprobe wrote to outgoing_trace_map (replaces what find_trace_for_client_request returned).
// Returns 1 when the injected context replaced the inferred one.
static __always_inline u8 adopt_injected_trace(http2_conn_stream_t *s_key, tp_info_t *tp) {
    egress_key_t sorted_e = {
        .d_port = s_key->pid_conn.conn.d_port,
        .s_port = s_key->pid_conn.conn.s_port,
        .stream_id = s_key->stream_id,
    };
    sort_egress_key(&sorted_e);
    tp_info_pid_t *injected = bpf_map_lookup_elem(&outgoing_trace_map, &sorted_e);
    // written=1 means a uprobe wrote the entry (not a kprobe's random one).
    if (injected && injected->valid && injected->written && valid_trace(injected->tp.trace_id)) {
        bpf_memcpy(tp->trace_id, injected->tp.trace_id, TRACE_ID_SIZE_BYTES);
        bpf_memcpy(tp->span_id, injected->tp.span_id, SPAN_ID_SIZE_BYTES);
        bpf_memcpy(tp->parent_id, injected->tp.parent_id, SPAN_ID_SIZE_BYTES);

        return 1;
    }

    return 0;
}

// HPACK payload length + start offset within h2g_info->data
static __always_inline u32 h2_hpack_window(const http2_grpc_request_t *h2g_info,
                                           u32 *hpack_offset) {
    const u8 flags = h2g_info->data[4];
    const u8 padded = (flags >> 3) & 1;
    const u32 prefix = padded + ((flags >> 5) & 1) * k_h2_priority_prefix_len;
    const u32 frame_len =
        ((u32)h2g_info->data[0] << 16) | ((u32)h2g_info->data[1] << 8) | (u32)h2g_info->data[2];
    const u32 raw_len = frame_len < k_h2_max_payload ? frame_len : k_h2_max_payload;
    const u32 skip = prefix + (padded * h2g_info->data[k_h2_frame_header_len]);
    *hpack_offset = k_h2_frame_header_len + prefix;
    return raw_len > skip ? raw_len - skip : 0;
}

static __always_inline void
http2_poison_hpack(http2_conn_stream_t *stream, http2_grpc_request_t *info, u8 flags) {
    http2_conn_info_data_t *conn =
        bpf_map_lookup_elem(&ongoing_http2_connections, &stream->pid_conn);
    http2_grpc_request_t *stored = bpf_map_lookup_elem(&ongoing_http2_grpc, stream);
    if (flags & h2_hpack_req_unreliable) {
        if (conn) {
            conn->req_hpack_poisoned = 1;
        }
        if (info) {
            info->hpack_flags |= h2_hpack_req_unreliable;
        }
        if (stored) {
            stored->hpack_flags |= h2_hpack_req_unreliable;
        }
    }
    if (flags & h2_hpack_resp_unreliable) {
        if (conn) {
            conn->resp_hpack_poisoned = 1;
        }
        if (info) {
            info->hpack_flags |= h2_hpack_resp_unreliable;
        }
        if (stored) {
            stored->hpack_flags |= h2_hpack_resp_unreliable;
        }
    }
}

static __always_inline u8 http2_emit_hpack_event(grpc_frames_ctx_t *g_ctx,
                                                 const frame_header_t *frame,
                                                 u8 event_type) {
    http2_grpc_request_t *event = bpf_ringbuf_reserve(&events, sizeof(http2_grpc_request_t), 0);
    if (!event) {
        return 0;
    }

    bpf_memset(event, 0, __builtin_offsetof(http2_grpc_request_t, data));
    bpf_memset(&event->data, 0, sizeof(*event) - __builtin_offsetof(http2_grpc_request_t, data));
    event->flags = event_type;
    event->ssl = g_ctx->args.ssl;
    event->type = request_type_by_direction(
        g_ctx->args.direction,
        event_type == EVENT_K_HTTP2_REQUEST_HEADERS ? PACKET_TYPE_REQUEST : PACKET_TYPE_RESPONSE);
    task_pid(&event->pid);
    event->stream_id = frame->stream_id;
    event->len = g_ctx->args.bytes_len - g_ctx->pos;
    event->hpack_flags = 0;

    http2_conn_info_data_t *conn =
        bpf_map_lookup_elem(&ongoing_http2_connections, &g_ctx->stream.pid_conn);
    event->new_conn_id = conn ? conn->id : 0;
    if (conn) {
        event->hpack_flags = (conn->req_hpack_poisoned * h2_hpack_req_unreliable) |
                             (conn->resp_hpack_poisoned * h2_hpack_resp_unreliable);
        if (http2_flag_new(conn->flags)) {
            event->hpack_flags |= h2_hpack_new_connection;
            conn->flags &= ~http2_conn_flag_new;
        }
    } else {
        event->hpack_flags |= h2_hpack_req_unreliable | h2_hpack_resp_unreliable;
    }

    const void *buf = (const unsigned char *)g_ctx->args.u_buf + g_ctx->pos;
    if (event_type == EVENT_K_HTTP2_REQUEST_HEADERS) {
        bpf_probe_read(event->data, sizeof(event->data), buf);
    } else {
        bpf_probe_read(event->ret_data, sizeof(event->ret_data), buf);
    }
    bpf_ringbuf_submit(event, get_flags());
    return 1;
}

// SERVER finalize: shared post-branch tail of http2_grpc_start. h2g_info /
// tp_p are populated in per-CPU scratch by the caller
static __always_inline void http2_grpc_start_finalize_server(http2_conn_stream_t *s_key,
                                                             http2_grpc_request_t *h2g_info,
                                                             tp_info_pid_t *tp_p,
                                                             u8 found_tp,
                                                             u8 ssl,
                                                             u16 orig_dport) {
    if (!found_tp) {
        new_trace_id(&tp_p->tp);
        bpf_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));
    }

    h2g_info->tp = tp_p->tp;

    set_trace_info_for_connection(&h2g_info->conn_info, TRACE_TYPE_SERVER, tp_p);
    server_or_client_trace(EVENT_HTTP_REQUEST,
                           &h2g_info->conn_info,
                           k_lw_thread_none,
                           tp_p,
                           ssl,
                           orig_dport,
                           0,
                           BPF_ANY);

    trace_key_t t_key = {0};
    task_tid(&t_key.p_key);
    java_vt_translate_tid(&t_key.p_key);
    t_key.extra_id = extra_runtime_id();
    bpf_map_update_elem(&server_traces, &t_key, tp_p, BPF_ANY);

    bpf_map_update_elem(&ongoing_http2_grpc, s_key, h2g_info, BPF_ANY);
}

static __always_inline void http2_grpc_start(void *ctx,
                                             http2_conn_stream_t *s_key,
                                             void *u_buf,
                                             int len,
                                             u8 direction,
                                             u8 ssl,
                                             u16 orig_dport) {
    http2_grpc_request_t *existing = bpf_map_lookup_elem(&ongoing_http2_grpc, s_key);
    if (existing) {
        bpf_dbg_printk("already found existing grpcstart, ignoring this exchange");
        if (existing->type == EVENT_HTTP_CLIENT && adopt_injected_trace(s_key, &existing->tp)) {
            // the uprobe's context comes from the running request itself
            existing->parent_status = k_parent_status_live;
        }
        return;
    }
    http2_grpc_request_t *h2g_info = empty_http2_info();
    bpf_dbg_printk("http2/grpc start direction=%d stream=%d", direction, s_key->stream_id);
    //dbg_print_http_connection_info(&s_key->pid_conn.conn); // commented out since GitHub CI doesn't like this call
    if (!h2g_info) {
        return;
    }

    http_connection_metadata_t *meta = connection_meta_by_direction(direction, PACKET_TYPE_REQUEST);
    if (!meta) {
        bpf_dbg_printk("Can't get meta memory or connection not found");
        return;
    }

    h2g_info->flags = EVENT_K_HTTP2_REQUEST;
    h2g_info->start_monotime_ns = bpf_ktime_get_ns();
    h2g_info->len = len;
    h2g_info->ssl = ssl;
    h2g_info->conn_info = s_key->pid_conn.conn;
    if (meta) { // keep verifier happy
        h2g_info->pid = meta->pid;
        h2g_info->type = meta->type;
    }

    h2g_info->new_conn_id = 0;
    h2g_info->stream_id = s_key->stream_id;
    h2g_info->hpack_flags = 0;
    http2_conn_info_data_t *h2g = bpf_map_lookup_elem(&ongoing_http2_connections, &s_key->pid_conn);
    if (h2g) {
        h2g_info->new_conn_id = h2g->id;
    }
    if (h2g) {
        h2g_info->hpack_flags = (h2g->req_hpack_poisoned * h2_hpack_req_unreliable) |
                                (h2g->resp_hpack_poisoned * h2_hpack_resp_unreliable);
    } else {
        h2g_info->hpack_flags = h2_hpack_req_unreliable | h2_hpack_resp_unreliable;
    }

    const u8 is_client = (meta->type == EVENT_HTTP_CLIENT);
    fixup_connection_info(&h2g_info->conn_info, is_client, orig_dport);
    bpf_probe_read(h2g_info->data, k_kprobes_http2_buf_size, u_buf);

    tp_info_pid_t *tp_p = tp_info_mem();
    if (!tp_p) {
        bpf_map_update_elem(&ongoing_http2_grpc, s_key, h2g_info, BPF_ANY);
        return;
    }

    // Clear trace/parent IDs — per-CPU scratch carries stale data and the
    // server finalize uses valid_trace(trace_id) to decide whether to keep
    // a parsed/looked-up traceparent or generate a fresh one
    bpf_memset(tp_p->tp.trace_id, 0, sizeof(tp_p->tp.trace_id));
    bpf_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));
    tp_p->tp.ts = bpf_ktime_get_ns();
    tp_p->tp.flags = 1;
    tp_p->valid = 1;
    tp_p->written = 0;
    tp_p->pid = s_key->pid_conn.pid;
    tp_p->req_type = meta->type;
    urand_bytes(tp_p->tp.span_id, SPAN_ID_SIZE_BYTES);

    if (!is_client) {
        // Server finalize tail-called to stay under verifier insn limit on 5.15
        preempt_guarded_tail_call(
            ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server);
        return;
    }

    cp_support_data_t *cp = bpf_map_lookup_elem(&cp_support_connect_info, &s_key->pid_conn);
    if (cp) {
        // Refresh per stream — persistent H2 clients (Node grpc-js) carry a
        // stale extra_id from the first connect
        task_tid(&cp->t_key.p_key);
        java_vt_translate_tid(&cp->t_key.p_key);
        cp->t_key.extra_id = extra_runtime_id();
        cp->ts = bpf_ktime_get_ns();
    }
    u8 found_tp =
        find_trace_for_client_request(&s_key->pid_conn, orig_dport, k_lw_thread_none, &tp_p->tp);
    h2g_info->parent_status = found_tp;
    if (adopt_injected_trace(s_key, &tp_p->tp)) {
        // the uprobe's context comes from the running request itself
        h2g_info->parent_status = k_parent_status_live;
    }
    if (valid_trace(tp_p->tp.trace_id)) {
        found_tp = 1;
    }

    if (!found_tp) {
        new_trace_id(&tp_p->tp);
        bpf_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));
    }

    h2g_info->tp = tp_p->tp;

    set_trace_info_for_connection(&h2g_info->conn_info, TRACE_TYPE_CLIENT, tp_p);
    // BPF_NOEXIST so a Go uprobe's HPACK-injected entry (written=1) isn't clobbered
    server_or_client_trace(EVENT_HTTP_CLIENT,
                           &h2g_info->conn_info,
                           k_lw_thread_none,
                           tp_p,
                           ssl,
                           orig_dport,
                           s_key->stream_id,
                           BPF_NOEXIST);

    bpf_map_update_elem(&ongoing_http2_grpc, s_key, h2g_info, BPF_ANY);
}

static __always_inline void
http2_grpc_end(http2_conn_stream_t *stream, http2_grpc_request_t *prev_info, void *u_buf) {
    bpf_dbg_printk("http2/grpc end prev_info=%llx", prev_info);
    if (prev_info) {
        prev_info->end_monotime_ns = bpf_ktime_get_ns();
        bpf_dbg_printk("stream_id = %d", stream->stream_id);
        //dbg_print_http_connection_info(&stream->pid_conn.conn); // commented out since GitHub CI doesn't like this call

        http2_conn_info_data_t *conn =
            bpf_map_lookup_elem(&ongoing_http2_connections, &stream->pid_conn);
        if (conn) {
            prev_info->hpack_flags = (conn->req_hpack_poisoned * h2_hpack_req_unreliable) |
                                     (conn->resp_hpack_poisoned * h2_hpack_resp_unreliable);
        } else {
            prev_info->hpack_flags |= h2_hpack_req_unreliable | h2_hpack_resp_unreliable;
        }

        http2_grpc_request_t *trace = bpf_ringbuf_reserve(&events, sizeof(*trace), 0);
        if (trace) {
            bpf_probe_read(prev_info->ret_data, k_kprobes_http2_ret_buf_size, u_buf);
            __builtin_memcpy(trace, prev_info, sizeof(http2_grpc_request_t));
            bpf_ringbuf_submit(trace, get_flags());
        }
        if (prev_info->type == EVENT_HTTP_CLIENT) {
            obi_ctx__restore_server();
        }
    }

    bpf_map_delete_elem(&ongoing_http2_grpc, stream);

    // delete_client_trace_info only clears stream_id=0 — without this the
    // per-stream entries would leak until the LRU evicts them
    egress_key_t e_key = {
        .d_port = stream->pid_conn.conn.d_port,
        .s_port = stream->pid_conn.conn.s_port,
        .stream_id = stream->stream_id,
    };
    sort_egress_key(&e_key);
    bpf_map_delete_elem(&outgoing_trace_map, &e_key);
}

static __always_inline frame_header_t next_frame(const grpc_frames_ctx_t *g_ctx) {
    // read next frame
    const void *offset = (const unsigned char *)g_ctx->args.u_buf + g_ctx->pos;

    frame_header_t header;

    if (bpf_probe_read(&header, sizeof(header), offset) != 0) {
        bpf_dbg_printk("failed to read frame header");
        return header; // the caller will deal with an invalid header
    }

    if (header.length == 0 || header.type > FrameContinuation) {
        return header; // the caller will deal with an invalid header
    }

    header.length = bpf_ntohl(header.length << 8);
    header.stream_id = bpf_ntohl(header.stream_id << 1);

    //bpf_dbg_printk("http2 frame type = %u, len = %u", header.type, header.length);
    //bpf_dbg_printk("http2 frame stream_id = %u, flags = %u", header.stream_id, header.flags);

    return header;
}

static __always_inline void update_prev_info(grpc_frames_ctx_t *g_ctx) {
    const http2_grpc_request_t *prev_info =
        bpf_map_lookup_elem(&ongoing_http2_grpc, &g_ctx->stream);

    g_ctx->has_prev_info = 0;
    if (prev_info) {
        g_ctx->prev_info = *prev_info;
        g_ctx->has_prev_info = 1;
    }
}

static __always_inline u8 h2_next_frame_changes_hpack(const grpc_frames_ctx_t *g_ctx,
                                                      const frame_header_t *frame) {
    const u32 frame_size = frame->length + k_frame_header_len;
    if (frame_size >= g_ctx->args.bytes_len || g_ctx->pos >= g_ctx->args.bytes_len - frame_size) {
        return 0;
    }

    frame_header_t next = {0};
    const void *offset = (const unsigned char *)g_ctx->args.u_buf + g_ctx->pos + frame_size;
    if (bpf_probe_read(&next, sizeof(next), offset) != 0) {
        return 1;
    }

    return next.type == FrameHeaders || next.type == FramePushPromise;
}

static __always_inline int
handle_headers_frame(void *ctx, grpc_frames_ctx_t *g_ctx, const frame_header_t *frame) {
    g_ctx->stream.stream_id = frame->stream_id;

    // if we don't have prev_info, try looking it up...
    update_prev_info(g_ctx);

    if (g_ctx->has_prev_info) {
        g_ctx->saved_stream_id = g_ctx->stream.stream_id;
        g_ctx->saved_buf_pos = g_ctx->pos;

        const u8 response_type =
            request_type_by_direction(g_ctx->args.direction, PACKET_TYPE_RESPONSE);
        const u8 response = response_type == g_ctx->prev_info.type;
        const u8 event_type =
            response ? EVENT_K_HTTP2_RESPONSE_HEADERS : EVENT_K_HTTP2_REQUEST_HEADERS;
        const u8 poison = response ? h2_hpack_resp_unreliable : h2_hpack_req_unreliable;
        if (!http2_emit_hpack_event(g_ctx, frame, event_type)) {
            http2_poison_hpack(&g_ctx->stream, &g_ctx->prev_info, poison);
        }
        const u32 capture_size = response ? k_kprobes_http2_ret_buf_size : k_kprobes_http2_buf_size;
        if (frame->length + k_frame_header_len > capture_size) {
            http2_poison_hpack(&g_ctx->stream, &g_ctx->prev_info, poison);
        }

        if (http_grpc_stream_ended(frame)) {
            if (h2_next_frame_changes_hpack(g_ctx, frame)) {
                http2_poison_hpack(&g_ctx->stream, &g_ctx->prev_info, poison);
            }
            preempt_guarded_tail_call(
                ctx, &jump_table, k_tail_protocol_http2_grpc_handle_end_frame);
            return 0; // normally unreachable
        }
    } else {
        // Not starting new grpc request, found end frame in a start, likely
        // just terminating prev connection
        if (!(is_flags_only_frame(frame) && http_grpc_stream_ended(frame))) {
            if (!http2_emit_hpack_event(g_ctx, frame, EVENT_K_HTTP2_REQUEST_HEADERS)) {
                http2_poison_hpack(&g_ctx->stream, 0, h2_hpack_req_unreliable);
            }
            if (frame->length + k_frame_header_len > k_kprobes_http2_buf_size) {
                http2_poison_hpack(&g_ctx->stream, 0, h2_hpack_req_unreliable);
            }
            if (h2_next_frame_changes_hpack(g_ctx, frame)) {
                http2_poison_hpack(&g_ctx->stream, 0, h2_hpack_req_unreliable);
            }
            preempt_guarded_tail_call(
                ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame);
            return 0; // normally unreachable
        }
    }

    return 1;
}

static __always_inline void handle_data_frame(void *ctx, grpc_frames_ctx_t *g_ctx) {
    if (!g_ctx->has_prev_info || !g_ctx->saved_stream_id) {
        // we haven't found anything useful...
        return;
    }

    const u8 type = g_ctx->prev_info.type;
    const u8 direction = g_ctx->args.direction;

    if (g_ctx->found_data_frame || ((type == EVENT_HTTP_REQUEST) && (direction == TCP_SEND)) ||
        ((type == EVENT_HTTP_CLIENT) && (direction == TCP_RECV))) {

        g_ctx->stream.pid_conn = g_ctx->args.pid_conn;
        g_ctx->stream.stream_id = g_ctx->saved_stream_id;

        preempt_guarded_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_end_frame);
    }
}

// k_tail_protocol_http2_grpc_handle_start_frame
SEC("kprobe/http2")
int GUARDED_PROG(obi_protocol_http2_grpc_handle_start_frame, void *, ctx) {
    (void)ctx;

    grpc_frames_ctx_t *g_ctx = grpc_ctx();

    if (!g_ctx) {
        return 0;
    }

    const call_protocol_args_t *args = &g_ctx->args;

    void *offset = (unsigned char *)args->u_buf + g_ctx->pos;

    http2_grpc_start(
        ctx, &g_ctx->stream, offset, args->bytes_len, args->direction, args->ssl, args->orig_dport);

    return 0;
}

// SERVER tail call: HPACK parse first (per-stream, no trace_map race), per-conn
// fallback if missed. Skips optional PADDED/PRIORITY prefix + trailing pad
SEC("kprobe/http2")
int GUARDED_PROG(obi_protocol_http2_grpc_handle_start_frame_server, void *, ctx) {
    grpc_frames_ctx_t *g_ctx = grpc_ctx();
    if (!g_ctx) {
        return 0;
    }
    http2_grpc_request_t *h2g_info = http2_info_mem();
    if (!h2g_info) {
        return 0;
    }
    tp_info_pid_t *tp_p = tp_info_mem();
    if (!tp_p) {
        return 0;
    }

    u32 hpack_off;
    const u32 hpack_len = h2_hpack_window(h2g_info, &hpack_off);
    g_ctx->huff.next = k_h2_huff_then_finalize;

    if (parse_hpack_traceparent(h2g_info->data + hpack_off, hpack_len, &tp_p->tp, &g_ctx->huff)) {
        preempt_guarded_tail_call(
            ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_finalize);
        return 0;
    }

    // without bpf_loop the decode program is a dummy, so skip the detour entirely
    if (g_bpf_loop_enabled) {
        // name matched, value compressed: decoding needs its own program
        if (g_ctx->huff.len) {
            preempt_guarded_tail_call(
                ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_huffman);
            return 0;
        }

        preempt_guarded_tail_call(
            ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_huffscan);
        return 0;
    }

    preempt_guarded_tail_call(
        ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_finalize);
    return 0;
}

// SERVER huffscan: an indexed name leaves nothing to fingerprint, so locate the compressed
// value alone; ranked above the connection heuristic, unlike the weak fingerprint in finalize
SEC("kprobe/http2")
int GUARDED_PROG(obi_protocol_http2_grpc_handle_start_frame_server_huffscan, void *, ctx) {
    grpc_frames_ctx_t *g_ctx = grpc_ctx();
    if (!g_ctx) {
        return 0;
    }
    http2_grpc_request_t *h2g_info = http2_info_mem();
    if (!h2g_info) {
        return 0;
    }
    tp_info_pid_t *tp_p = tp_info_mem();
    if (!tp_p) {
        return 0;
    }

    u32 hpack_off;
    const u32 hpack_len = h2_hpack_window(h2g_info, &hpack_off);
    g_ctx->huff.next = k_h2_huff_then_finalize;
    g_ctx->huff_scan.done = 1;

    if (find_hpack_traceparent_huffman(h2g_info->data, hpack_off, hpack_len, &g_ctx->huff_scan)) {
        g_ctx->huff.at = g_ctx->huff_scan.at[0];
        g_ctx->huff.len = g_ctx->huff_scan.len[0];
        preempt_guarded_tail_call(
            ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_huffman);
        return 0;
    }

    preempt_guarded_tail_call(
        ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_finalize);
    return 0;
}

// SERVER huffman: decodes the value the scan located, in its own tail-call program
SEC("kprobe/http2")
int GUARDED_PROG(obi_protocol_http2_grpc_handle_start_frame_server_huffman, void *, ctx) {
    // needs bpf_loop; without it the block keeps its existing fallback
    if (!g_bpf_loop_enabled) {
        preempt_guarded_tail_call(
            ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_finalize);
        return 0;
    }

    grpc_frames_ctx_t *g_ctx = grpc_ctx();
    if (!g_ctx) {
        return 0;
    }
    http2_grpc_request_t *h2g_info = http2_info_mem();
    if (!h2g_info) {
        return 0;
    }
    tp_info_pid_t *tp_p = tp_info_mem();
    if (!tp_p) {
        return 0;
    }

    u32 hpack_off;
    const u32 hpack_len = h2_hpack_window(h2g_info, &hpack_off);
    unsigned char *w = h2_tp_huff_win_mem();
    unsigned char *out = h2_tp_huff_out_mem();
    if (!w || !out) {
        return 0;
    }

    (void)try_parse_tp_huffman_value(
        h2g_info->data + hpack_off, hpack_len, &g_ctx->huff, w, out, &tp_p->tp);

    if (g_ctx->huff.next == k_h2_huff_then_commit) {
        preempt_guarded_tail_call(
            ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
        return 0;
    }

    // rejected candidate: name-matched falls back to the scan, scan advances
    if (!g_ctx->huff_scan.done) {
        preempt_guarded_tail_call(
            ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_huffscan);
        return 0;
    }

    u8 next_idx = g_ctx->huff_scan.idx + 1;
    if (next_idx < g_ctx->huff_scan.count && next_idx < k_h2_tp_huff_max_candidates) {
        // reloads of map scalars reach the verifier unbounded
        bpf_clamp_umax(next_idx, k_h2_tp_huff_max_candidates - 1);
        g_ctx->huff.at = g_ctx->huff_scan.at[next_idx];
        g_ctx->huff.len = g_ctx->huff_scan.len[next_idx];
        g_ctx->huff.next = k_h2_huff_then_finalize;
        g_ctx->huff_scan.idx = next_idx;
        preempt_guarded_tail_call(
            ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_huffman);
        return 0;
    }

    // a full list may have starved later candidates: rescan past the last one;
    // falls through to finalize when the tail call budget runs out
    if (g_ctx->huff_scan.count == k_h2_tp_huff_max_candidates) {
        g_ctx->huff_scan.resume = g_ctx->huff_scan.at[k_h2_tp_huff_max_candidates - 1];
        preempt_guarded_tail_call(
            ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_huffscan);
    }

    preempt_guarded_tail_call(
        ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_finalize);
    return 0;
}

// SERVER finalize: dyn-table traceparent scan, then tail-calls commit
SEC("kprobe/http2")
int GUARDED_PROG(obi_protocol_http2_grpc_handle_start_frame_server_finalize, void *, ctx) {
    grpc_frames_ctx_t *g_ctx = grpc_ctx();
    if (!g_ctx) {
        return 0;
    }
    http2_grpc_request_t *h2g_info = http2_info_mem();
    if (!h2g_info) {
        return 0;
    }
    tp_info_pid_t *tp_p = tp_info_mem();
    if (!tp_p) {
        return 0;
    }

    if (!valid_trace(tp_p->tp.trace_id)) {
        find_trace_for_server_request(&g_ctx->stream.pid_conn.conn, &tp_p->tp, EVENT_HTTP_REQUEST);
    }

    if (!valid_trace(tp_p->tp.trace_id)) {
        u32 hpack_off;
        const u32 hpack_len = h2_hpack_window(h2g_info, &hpack_off);
        // a miss leaves tp invalid and commit assigns a new trace id
        (void)find_hpack_traceparent_value(h2g_info->data + hpack_off, hpack_len, &tp_p->tp);
    }

    preempt_guarded_tail_call(
        ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
    return 0;
}

// SERVER commit: shared post-branch — new_trace_id if missing, commit tp,
// set_trace_info_for_connection, server_or_client_trace, server_traces,
// ongoing_http2_grpc.
SEC("kprobe/http2")
int GUARDED_PROG(obi_protocol_http2_grpc_handle_start_frame_server_commit, void *, ctx) {
    (void)ctx;
    grpc_frames_ctx_t *g_ctx = grpc_ctx();
    if (!g_ctx) {
        return 0;
    }
    http2_grpc_request_t *h2g_info = http2_info_mem();
    if (!h2g_info) {
        return 0;
    }
    tp_info_pid_t *tp_p = tp_info_mem();
    if (!tp_p) {
        return 0;
    }

    const u8 found_tp = valid_trace(tp_p->tp.trace_id);
    http2_grpc_start_finalize_server(
        &g_ctx->stream, h2g_info, tp_p, found_tp, g_ctx->args.ssl, g_ctx->args.orig_dport);

    return 0;
}

// k_tail_protocol_http2_grpc_handle_end_frame
SEC("kprobe/http2")
int GUARDED_PROG(obi_protocol_http2_grpc_handle_end_frame, void *, ctx) {
    (void)ctx;

    grpc_frames_ctx_t *g_ctx = grpc_ctx();

    if (!g_ctx) {
        return 0;
    }

    const u8 req_type = request_type_by_direction(g_ctx->args.direction, PACKET_TYPE_RESPONSE);

    if (req_type == g_ctx->prev_info.type) {
        u32 buf_pos = g_ctx->saved_buf_pos;

        bpf_clamp_umax(buf_pos, k_iovec_max_len);

        void *offset = (unsigned char *)g_ctx->args.u_buf + buf_pos;
        http2_grpc_end(&g_ctx->stream, &g_ctx->prev_info, offset);

        bpf_map_delete_elem(&active_ssl_connections, &g_ctx->args.pid_conn);
    } else {
        // Wrong-direction end flag (e.g. a CLIENT request's own HEADERS
        // carries END_STREAM=1). Keep ongoing_http2_grpc so the correct
        // -direction end can fire later (response trailers for CLIENT,
        // request send for SERVER).
        bpf_dbg_printk("grpc request/response mismatch, req_type %d, prev_info->type %d",
                       req_type,
                       g_ctx->prev_info.type);
    }

    return 0;
}

// k_tail_protocol_http2_grpc_frames
// this function scans a raw buffer and tries to find GRPC frames on it
// (represented by 'frame_header_t'). We care about 3 kinds of frames: start
// frames, end frames and data frames. Start and end frames are used as anchor
// points to determine the lifespan of a GRPC connection, and the data frames
// are used as a fallback mechanism in case those are found. We use that
// information to evaluate whether the parsed data is potentially a GRPC
// frame, and if so, we ship it to userspace for further processing.
SEC("kprobe/http2")
int GUARDED_PROG(obi_protocol_http2_grpc_frames, void *, ctx) {
    const u8 k_max_loop_iterations = 4; // the maximum number of the for loop iterations
    const u8 k_loop_count = 3;          // the number of times we will retry the loop
    const u8 k_iterations = k_max_loop_iterations * k_loop_count;

    grpc_frames_ctx_t *g_ctx = grpc_ctx();

    if (!g_ctx) {
        return 0;
    }

    // this loop will effectively run for k_iterations, split between the
    // unrolled for loop and the tail call (see comment after the loop)
    for (u8 i = 0; i < k_max_loop_iterations; ++i) {
        g_ctx->iterations++;

        if (g_ctx->pos >= g_ctx->args.bytes_len) {
            break;
        }

        const frame_header_t frame = next_frame(g_ctx);

        if (frame.type == FramePushPromise) {
            g_ctx->stream.stream_id = frame.stream_id;
            update_prev_info(g_ctx);
            http2_poison_hpack(&g_ctx->stream,
                               g_ctx->has_prev_info ? &g_ctx->prev_info : 0,
                               h2_hpack_resp_unreliable);
        }

        // if handle_headers_frame returns 0, it means bpf_tail_call has
        // failed and something is very wrong, so we just bail...
        if (is_headers_frame(&frame) && !handle_headers_frame(ctx, g_ctx, &frame)) {
            //bpf_dbg_printk("http2 bpf_tail_call failed");
            return 0;
        }

        if (is_data_frame(&frame)) {
            g_ctx->found_data_frame = 1;
        }

        if (is_invalid_frame(&frame)) {
            g_ctx->terminate_search = 1;
            //bpf_dbg_printk("Invalid frame, terminating search");
            break;
        }

        const u32 frame_size = frame.length + k_frame_header_len;
        const u32 remaining = g_ctx->args.bytes_len - g_ctx->pos;
        if (frame_size >= remaining) {
            g_ctx->terminate_search = 1;
            //bpf_dbg_printk("Frame length bigger than bytes len");
            break;
        }

        g_ctx->pos += frame_size;
        //bpf_dbg_printk("New buf read g_ctx.pos = %d", g_ctx->pos);
    }

    // this is a weird recursion - we can't loop many times above because the
    // verifier will reject this program as too complex, we don't want to use
    // bpf_loop() as we need to support kernels < 5.17, and finally we don't
    // want to abuse bpf_tail_call as things can get slow (and limited), so we
    // use this mirror-cracking hybrid approach
    if (!g_ctx->terminate_search && g_ctx->iterations < k_iterations) {
        preempt_guarded_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_frames);
        http2_poison_hpack(&g_ctx->stream,
                           g_ctx->has_prev_info ? &g_ctx->prev_info : 0,
                           h2_hpack_req_unreliable | h2_hpack_resp_unreliable);
        return 0;
    }

    if (!g_ctx->terminate_search && g_ctx->pos < g_ctx->args.bytes_len) {
        http2_poison_hpack(&g_ctx->stream,
                           g_ctx->has_prev_info ? &g_ctx->prev_info : 0,
                           h2_hpack_req_unreliable | h2_hpack_resp_unreliable);
    }

    // We only loop N times looking for the stream termination. If the data
    // packed is large we'll miss the frame saying the stream closed. In that
    // case we try this backup path, which will tail call on success.
    handle_data_frame(ctx, g_ctx);

    return 0;
}

// k_tail_protocol_http2
SEC("kprobe/http2")
int GUARDED_PROG(obi_protocol_http2, void *, ctx) {
    call_protocol_args_t *args = protocol_args();

    if (!args) {
        return 0;
    }

    grpc_frames_ctx_t *g_ctx = grpc_ctx();

    if (!g_ctx) {
        return 0;
    }

    // prev_info is skipped: the whole struct outgrew an inline memset, and every
    // read of prev_info is guarded by has_prev_info, which this does clear
    bpf_memset(&g_ctx->has_prev_info,
               0,
               sizeof(*g_ctx) - __builtin_offsetof(grpc_frames_ctx_t, has_prev_info));
    g_ctx->args = *args;
    g_ctx->stream.pid_conn = args->pid_conn;

    preempt_guarded_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_frames);

    return 0;
}
