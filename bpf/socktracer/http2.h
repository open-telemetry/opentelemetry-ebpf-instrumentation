// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/utils.h>

#include <common/common.h>
#include <common/h2_defs.h>
#include <common/ringbuf.h>

#include <logger/bpf_dbg.h>

#include <socktracer/helpers.h>
#include <socktracer/socket_data.h>
#include <socktracer/tcp.h>

#include <socktracer/maps/h2_pending.h>

const unsigned char k_http2_preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const u32 k_http2_preface_len = sizeof(k_http2_preface) - 1;

static __always_inline bool is_http2_preface(const unsigned char *buf, const unsigned char *end) {
    if (buf + k_http2_preface_len > end) {
        return false;
    }

    return bpf_memcmp(buf, k_http2_preface, k_http2_preface_len) == 0;
}

// Extract the stream id of the first HEADERS frame in an already-copied HTTP/2
// buffer. Walks at most k_h2_max_frame_scan frames, skipping the client
// connection preface and any leading non-HEADERS frames (SETTINGS,
// WINDOW_UPDATE, ...). Returns false when no HEADERS frame is present in the
// captured bytes — the caller then treats the packet as a non-boundary frame
// (DATA/SETTINGS/...) and ignores it. Reads a fixed map-backed array, so there
// are no data_end concerns; the offset is clamped to keep the verifier happy.
static __always_inline bool
h2_buf_stream_id(const unsigned char *buf, u32 buf_len, u32 *out_sid) {
    if (buf_len > (u32)k_tcp_max_len) {
        buf_len = k_tcp_max_len;
    }

    u32 off = 0;

    // Skip the 24-byte client connection preface on the first request packet.
    if (buf_len >= k_h2_preface_len && buf[0] == 'P' && buf[1] == 'R' && buf[2] == 'I' &&
        buf[3] == ' ') {
        off = k_h2_preface_len;
    }

    for (u32 i = 0; i < k_h2_max_frame_scan; i++) {
        bpf_clamp_umax(off, k_tcp_max_len - k_h2_frame_header_len);

        if (off + k_h2_frame_header_len > buf_len) {
            return false;
        }

        const u32 payload_len =
            ((u32)buf[off] << 16) | ((u32)buf[off + 1] << 8) | (u32)buf[off + 2];

        if (buf[off + 3] == k_h2_frame_headers) {
            *out_sid = ((u32)(buf[off + 5] & 0x7f) << 24) | ((u32)buf[off + 6] << 16) |
                       ((u32)buf[off + 7] << 8) | (u32)buf[off + 8];
            return true;
        }

        off += k_h2_frame_header_len + payload_len;
    }

    return false;
}

// emit_http2_buffer pairs an HTTP/2 request with its response in BPF, keyed by
// {socket cookie, stream id} in the h2_pending map, and emits one combined
// tcp_req_t event (buf = request, rbuf = response) — mirroring how handle_tcp
// pairs a plain TCP request/response within sk_data. The request side stashes
// the record; the response side completes and emits it. Packets without a
// HEADERS frame (DATA, SETTINGS, ...) are not request/response boundaries and
// are ignored. out_tp (egress only) hands the request span's tp to the HPACK
// inject chain so the wire traceparent matches the emitted span.
static __always_inline void emit_http2_buffer(void *ctx,
                                              struct socket_data *sk_data,
                                              packet_direction_t pkt_dir,
                                              tp_info_t *out_tp) {
    tcp_req_t *tcp = &sk_data->request.tcp;

    const u32 len = ctx_len(ctx);
    const u8 direction = tcp_direction(sk_data, pkt_dir);

    tcp->flags = EVENT_K_HTTP2_BUFFER;
    tcp->is_server = sk_data->sk_type == sk_type_server;
    // emit the normalized tuple so userspace sees the listening port as d_port
    tcp->conn_info = sk_data->sorted_conn;
    tcp->ssl = false;
    tcp->direction = direction;
    tcp->start_monotime_ns = bpf_ktime_get_ns();
    tcp->end_monotime_ns = bpf_ktime_get_ns();
    tcp->resp_len = 0;
    tcp->len = len;
    tcp->req_len = len;
    tcp->extra_id = 0;
    tcp->pid = sk_data->pid_info;
    tcp->tp.ts = bpf_ktime_get_ns();

    init_tp(sk_data, &tcp->tp);
    urand_bytes(tcp->tp.span_id, sizeof(tcp->tp.span_id));

    // Hand the request span's tp to the caller so the inject chain reuses it.
    if (out_tp) {
        *out_tp = tcp->tp;
    }

    __builtin_memset(tcp->buf, 0, sizeof(tcp->buf));

    u32 copied = 0;

    if (len > 0) {
        const u32 nbytes = min(len, (u32)sizeof(tcp->buf));

        ctx_pull_data(ctx, nbytes);

        const unsigned char *ptr = ctx_data(ctx);
        const unsigned char *e = ctx_data_end(ctx);

        if (ptr + nbytes <= e) {
            for (u32 i = 0; i < nbytes; ++i) {
                if (ptr + 1 > e) {
                    break;
                }
                tcp->buf[i] = *ptr++;
                ++copied;
            }
        }
    }

    u32 stream_id = 0;

    if (h2_buf_stream_id(tcp->buf, copied, &stream_id)) {
        h2_pending_key_t key = {
            .cookie = sk_data->cookie,
            .stream_id = stream_id,
            ._pad = 0,
        };

        if (direction == TCP_SEND) {
            // Request side (client egress / server ingress): stash, don't emit.
            tcp->req_len = copied;
            bpf_map_update_elem(&h2_pending, &key, tcp, BPF_ANY);
        } else {
            // Response side: attach the response bytes to the stashed request
            // and emit one combined event.
            tcp_req_t *pending = bpf_map_lookup_elem(&h2_pending, &key);

            if (pending) {
                pending->end_monotime_ns = bpf_ktime_get_ns();
                pending->resp_len = copied;

                // Fixed-size copy, not a byte loop: a data-dependent byte loop
                // here blows the egress program's 1M verifier instruction budget.
                // tcp->buf is zero-padded past `copied`, so copying all of rbuf is
                // safe and resp_len marks the valid length.
                __builtin_memcpy(pending->rbuf, tcp->buf, sizeof(pending->rbuf));

                bpf_ringbuf_output(&events, pending, sizeof(*pending), get_flags());
                bpf_map_delete_elem(&h2_pending, &key);
            }
        }
    }

    // Reset request state but preserve the HTTP/2 marker so subsequent packets
    // on this connection are also handled by this path.
    __builtin_memset(&sk_data->request, 0, sizeof(sk_data->request));
    sk_data->request.flags = EVENT_K_HTTP2_BUFFER;
}

static __always_inline bool handle_http2(void *ctx, struct socket_data *sk_data) {
    if (sk_data->request.flags == EVENT_K_HTTP2_BUFFER) {
        tailcall_ctx *t_ctx = tailcall_ctx_mem();
        if (!t_ctx) {
            return false;
        }
        t_ctx->sock_cookie = sk_data->cookie;
        bpf_tail_call_static(ctx, prog_map(), tail_http2());
        return true;
    }

    if (sk_data->request.flags != 0) {
        return false;
    }

    ctx_pull_data(ctx, k_http2_preface_len);

    const unsigned char *ptr = ctx_data(ctx);
    const unsigned char *e = ctx_data_end(ctx);

    if (!is_http2_preface(ptr, e)) {
        return false;
    }

    bpf_dbg_printk("handle_http2: detected preface cookie=%llu", sk_data->cookie);

    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    if (!t_ctx) {
        return false;
    }
    t_ctx->sock_cookie = sk_data->cookie;
    bpf_tail_call_static(ctx, prog_map(), tail_http2());
    return true;
}
