// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/common.h>
#include <common/ringbuf.h>

#include <logger/bpf_dbg.h>

#include <socktracer/helpers.h>
#include <socktracer/socket_data.h>
#include <socktracer/tcp.h>

const unsigned char k_http2_preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const u32 k_http2_preface_len = sizeof(k_http2_preface) - 1;

static __always_inline bool is_http2_preface(const unsigned char *buf, const unsigned char *end) {
    if (buf + k_http2_preface_len > end) {
        return false;
    }

    return bpf_memcmp(buf, k_http2_preface, k_http2_preface_len) == 0;
}

static __always_inline void
emit_http2_buffer(void *ctx, struct socket_data *sk_data, packet_direction_t pkt_dir) {
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

    __builtin_memset(tcp->buf, 0, sizeof(tcp->buf));

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
            }
        }
    }

    bpf_dbg_printk("handle_http2: emitting buffer len=%u dir=%u", len, direction);

    bpf_ringbuf_output(&events, tcp, sizeof(*tcp), get_flags());

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
