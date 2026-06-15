// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/h2_defs.h>
#include <common/iov_iter.h>
#include <common/http_buf_size.h>
#include <common/ringbuf.h>
#include <common/trace_lifecycle.h>
#include <common/trace_parent.h>

#include <maps/tp_info_mem.h>

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
enum { http2_conn_flag_ssl = WITH_SSL, http2_conn_flag_new = 0x2 };

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
        bpf_memset(value, 0, sizeof(http2_grpc_request_t));
    }
    return value;
}

static __always_inline u64 uniqueHTTP2ConnId(pid_connection_info_t *p_conn) {
    u64 random_id = (u64)bpf_get_prandom_u32() << 32;

    random_id |= ((u32)p_conn->conn.d_port << 16) | p_conn->conn.s_port;

    return random_id;
}

static __always_inline u8 try_parse_tp_value(const unsigned char *val, tp_info_t *tp) {
    if (val[k_tp_val_dash1] != '-' || val[k_tp_val_dash2] != '-' || val[k_tp_val_dash3] != '-') {
        return 0;
    }
    decode_hex(tp->trace_id, &val[k_tp_val_trace_id_start], TRACE_ID_CHAR_LEN);
    decode_hex(tp->parent_id, &val[k_tp_val_span_id_start], SPAN_ID_CHAR_LEN);
    tp->flags = 1;
    return 1;
}

// Look for traceparent in HPACK bytes. Handles plaintext (sk_msg) and huffman (Go uprobe) encodings.
static __always_inline u8 parse_hpack_traceparent(const unsigned char *data,
                                                  u32 data_len,
                                                  tp_info_t *tp) {
    if (data_len < k_h2_tp_hpack_huffman_size) {
        return 0;
    }

    const u32 max_pos = data_len - k_h2_tp_hpack_huffman_size;

    for (u16 i = 0; i < k_hpack_tp_max_scan && i <= max_pos; i++) {
        if (data[i] != k_hpack_literal_no_index) {
            continue;
        }

        const u8 name_len_byte = data[i + 1];

        if (name_len_byte == k_hpack_tp_name_len) { // plaintext
            if (i + k_h2_tp_hpack_size > data_len) {
                continue;
            }
            if (bpf_memcmp(
                    &data[i + k_hpack_tp_name_offset], k_hpack_tp_name, k_hpack_tp_name_len) != 0) {
                continue;
            }
            if (data[i + k_hpack_tp_name_offset + k_hpack_tp_name_len] != k_hpack_value_len_tp) {
                continue;
            }
            return try_parse_tp_value(&data[i + k_hpack_tp_val_offset], tp);
        }

        if (name_len_byte == (k_hpack_tp_name_huffman_len | 0x80)) { // huffman
            if (bpf_memcmp(&data[i + k_hpack_tp_name_offset],
                           k_hpack_tp_huffman,
                           k_hpack_tp_name_huffman_len) != 0) {
                continue;
            }
            if (data[i + k_hpack_tp_name_offset + k_hpack_tp_name_huffman_len] !=
                k_hpack_value_len_tp) {
                continue;
            }
            return try_parse_tp_value(&data[i + k_hpack_tp_val_offset_huffman], tp);
        }
    }

    return 0;
}

// Use the trace the Go uprobe wrote to outgoing_trace_map (replaces what find_trace_for_client_request returned).
static __always_inline void adopt_injected_trace(http2_conn_stream_t *s_key, tp_info_t *tp) {
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
    }
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
        if (existing->type == EVENT_HTTP_CLIENT) {
            adopt_injected_trace(s_key, &existing->tp);
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
    http2_conn_info_data_t *h2g = bpf_map_lookup_elem(&ongoing_http2_connections, &s_key->pid_conn);
    if (h2g && http2_flag_new(h2g->flags)) {
        h2g_info->new_conn_id = h2g->id;
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
        bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server);
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
    adopt_injected_trace(s_key, &tp_p->tp);
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

        http2_grpc_request_t *trace = bpf_ringbuf_reserve(&events, sizeof(http2_grpc_request_t), 0);
        if (trace) {
            bpf_probe_read(prev_info->ret_data, k_kprobes_http2_ret_buf_size, u_buf);
            __builtin_memcpy(trace, prev_info, sizeof(http2_grpc_request_t));
            bpf_ringbuf_submit(trace, get_flags());
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
    if (g_ctx->has_prev_info) {
        return;
    }

    const http2_grpc_request_t *prev_info =
        bpf_map_lookup_elem(&ongoing_http2_grpc, &g_ctx->stream);

    if (prev_info) {
        g_ctx->prev_info = *prev_info;
        g_ctx->has_prev_info = 1;
    }
}

static __always_inline int
handle_headers_frame(void *ctx, grpc_frames_ctx_t *g_ctx, const frame_header_t *frame) {
    g_ctx->stream.stream_id = frame->stream_id;

    // if we don't have prev_info, try looking it up...
    update_prev_info(g_ctx);

    if (g_ctx->has_prev_info) {
        g_ctx->saved_stream_id = g_ctx->stream.stream_id;
        g_ctx->saved_buf_pos = g_ctx->pos;

        if (http_grpc_stream_ended(frame)) {
            bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_end_frame);
            return 0; // normally unreachable
        }
    } else {
        // Not starting new grpc request, found end frame in a start, likely
        // just terminating prev connection
        if (!(is_flags_only_frame(frame) && http_grpc_stream_ended(frame))) {
            bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame);
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

        bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_end_frame);
    }
}

// k_tail_protocol_http2_grpc_handle_start_frame
SEC("kprobe/http2")
int obi_protocol_http2_grpc_handle_start_frame(void *ctx) {
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
int obi_protocol_http2_grpc_handle_start_frame_server(void *ctx) {
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

    const u8 flags = h2g_info->data[4];
    const u8 padded = (flags >> 3) & 1;
    const u32 prefix = padded + ((flags >> 5) & 1) * k_h2_priority_prefix_len;
    const u32 frame_len =
        ((u32)h2g_info->data[0] << 16) | ((u32)h2g_info->data[1] << 8) | (u32)h2g_info->data[2];
    const u32 raw_len = frame_len < k_h2_max_payload ? frame_len : k_h2_max_payload;
    const u32 skip = prefix + padded * h2g_info->data[k_h2_frame_header_len];
    const u32 hpack_len = raw_len > skip ? raw_len - skip : 0;
    if (!parse_hpack_traceparent(
            h2g_info->data + k_h2_frame_header_len + prefix, hpack_len, &tp_p->tp)) {
        find_trace_for_server_request(&g_ctx->stream.pid_conn.conn, &tp_p->tp, EVENT_HTTP_REQUEST);
    }

    bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_finalize);
    return 0;
}

// SERVER finalize: shared post-branch — new_trace_id if missing, commit tp,
// set_trace_info_for_connection, server_or_client_trace, server_traces,
// ongoing_http2_grpc.
SEC("kprobe/http2")
int obi_protocol_http2_grpc_handle_start_frame_server_finalize(void *ctx) {
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
int obi_protocol_http2_grpc_handle_end_frame(void *ctx) {
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
int obi_protocol_http2_grpc_frames(void *ctx) {
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

        if (frame.length + k_frame_header_len >= g_ctx->args.bytes_len) {
            g_ctx->terminate_search = 1;
            //bpf_dbg_printk("Frame length bigger than bytes len");
            break;
        }

        if (g_ctx->pos < (g_ctx->args.bytes_len - (frame.length + k_frame_header_len))) {
            g_ctx->pos += (frame.length + k_frame_header_len);
            //bpf_dbg_printk("New buf read g_ctx.pos = %d", g_ctx->pos);
        }
    }

    // this is a weird recursion - we can't loop many times above because the
    // verifier will reject this program as too complex, we don't want to use
    // bpf_loop() as we need to support kernels < 5.17, and finally we don't
    // want to abuse bpf_tail_call as things can get slow (and limited), so we
    // use this mirror-cracking hybrid approach
    if (!g_ctx->terminate_search && g_ctx->iterations < k_iterations) {
        bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_frames);
        return 0; // unreachable, but bail safely if bpf_tail_call fails
    }

    // We only loop N times looking for the stream termination. If the data
    // packed is large we'll miss the frame saying the stream closed. In that
    // case we try this backup path, which will tail call on success.
    handle_data_frame(ctx, g_ctx);

    return 0;
}

// k_tail_protocol_http2
SEC("kprobe/http2")
int obi_protocol_http2(void *ctx) {
    call_protocol_args_t *args = protocol_args();

    if (!args) {
        return 0;
    }

    grpc_frames_ctx_t *g_ctx = grpc_ctx();

    if (!g_ctx) {
        return 0;
    }

    __builtin_memset(g_ctx, 0, sizeof(*g_ctx));
    g_ctx->args = *args;
    g_ctx->stream.pid_conn = args->pid_conn;

    bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_frames);

    return 0;
}
