// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/algorithm.h>
#include <common/common.h>
#include <common/sql.h>

#include <socktracer/common_defs.h>
#include <socktracer/large_buffers.h>
#include <socktracer/socket_data.h>
#include <socktracer/tcp_core.h>

typedef enum {
    k_packet_direction_egress,
    k_packet_direction_ingress,
} packet_direction_t;

static __always_inline u8 tcp_direction(const struct socket_data *sk_data,
                                        packet_direction_t pkt_dir) {
    if (pkt_dir == k_packet_direction_ingress) {
        return sk_data->sk_type == sk_type_client ? TCP_RECV : TCP_SEND;
    }

    return sk_data->sk_type == sk_type_client ? TCP_SEND : TCP_RECV;
}

static __always_inline void
send_tcp_large_buffer(void *ctx, struct socket_data *sk_data, u8 packet_type, u8 action) {
    if (tcp_max_captured_bytes == 0) {
        return;
    }

    tcp_req_t *tcp = &sk_data->request.tcp;

    u32 *bytes_sent =
        packet_type == k_packet_type_request ? &tcp->lb_req_bytes : &tcp->lb_res_bytes;

    if (*bytes_sent >= tcp_max_captured_bytes) {
        return;
    }

    const u8 direction =
        (packet_type == k_packet_type_response) ? (tcp->direction ^ 1u) : tcp->direction;

    send_large_buffer(ctx,
                      packet_type,
                      direction,
                      tcp->conn_info,
                      tcp->tp,
                      action,
                      tcp_max_captured_bytes,
                      bytes_sent,
                      &tcp->has_large_buffers);
}

static __always_inline bool
handle_tcp_req(void *ctx, struct socket_data *sk_data, packet_direction_t pkt_dir) {
    bpf_dbg_enter();

    tcp_req_t *tcp = &sk_data->request.tcp;

    const u32 len = ctx_len(ctx);
    const u8 direction = tcp_direction(sk_data, pkt_dir);

    tcp->flags = EVENT_TCP_REQUEST;
    tcp->event_source = k_event_source_socktracer;
    tcp->is_server = sk_data->sk_type == sk_type_server;
    // emit the normalized tuple so userspace sees the listening port as d_port
    // (server sockets capture local=listening / remote=ephemeral, which is inverted)
    tcp->conn_info = sk_data->sorted_conn;
    tcp->ssl = false;
    tcp->direction = direction;
    tcp->start_monotime_ns = bpf_ktime_get_ns();
    tcp->end_monotime_ns = bpf_ktime_get_ns();
    tcp->resp_len = 0;
    tcp->len = len;
    tcp->req_len = len;
    tcp->extra_id = 0;
    tcp->protocol_type = k_protocol_type_unknown;
    tcp->pid = sk_data->pid_info;

    tcp->tp.ts = bpf_ktime_get_ns();

    init_tp(sk_data, &tcp->tp);

    urand_bytes(tcp->tp.span_id, sizeof(tcp->tp.span_id));

    tp_info_pid_t *tp_p = tp_buf_mem();

    if (tp_p) {
        tp_p->tp = tcp->tp;
        tp_p->tp.flags = 1;
        tp_p->valid = 1;
        tp_p->written = 1;
        tp_p->pid = sk_data->pid_tgid;
        tp_p->req_type = EVENT_TCP_REQUEST;

        set_trace(sk_data, tp_p);
    }

    send_tcp_large_buffer(ctx, sk_data, k_packet_type_request, k_large_buf_action_init);

    __builtin_memset(tcp->buf, 0, sizeof(tcp->buf));

    if (len == 0) {
        return true;
    }

    const u32 nbytes = min(len, sizeof(tcp->buf));
    bpf_dbg_printk("pulling %u bytes", nbytes);

    ctx_pull_data(ctx, nbytes);

    const unsigned char *ptr = ctx_data(ctx);
    const unsigned char *e = ctx_data_end(ctx);

    if (ptr + nbytes > e) {
        return true;
    }

    u32 copied = 0;
    for (u32 i = 0; i < nbytes; ++i) {
        if (ptr + 1 > e) {
            break;
        }

        ++copied;
        tcp->buf[i] = *ptr++;
    }

    bpf_dbg_printk("copied %u bytes: %s", copied, tcp->buf);
    return true;
}

static __always_inline bool handle_tcp_res(void *ctx, struct socket_data *data) {
    bpf_dbg_enter();

    if (data->request.flags != EVENT_TCP_REQUEST) {
        return false;
    }

    // if SSL was detected mid-connection after we already started a TCP request,
    // discard the partial trace as the SSL uprobes will produce the correct span
    if (data->ssl_state == ssl_state_yes) {
        __builtin_memset(&data->request, 0, sizeof(data->request));
        return true;
    }

    tcp_req_t *tcp = &data->request.tcp;

    const u32 len = ctx_len(ctx);

    tcp->end_monotime_ns = bpf_ktime_get_ns();
    tcp->resp_len = len;

    const u32 nbytes = min(len, (u32)sizeof(tcp->rbuf));

    ctx_pull_data(ctx, nbytes);

    const unsigned char *ptr = ctx_data(ctx);
    const unsigned char *e = ctx_data_end(ctx);

    if (ptr + nbytes > e) {
        send_tcp_large_buffer(ctx, data, k_packet_type_response, k_large_buf_action_init);
        finish_tcp(data);
        return true;
    }

    for (u32 i = 0; i < nbytes; ++i) {
        if (ptr + 1 > e) {
            break;
        }
        tcp->rbuf[i] = *ptr++;
    }

    send_tcp_large_buffer(ctx, data, k_packet_type_response, k_large_buf_action_init);

    finish_tcp(data);
    return true;
}

static __always_inline bool
handle_tcp(void *ctx, struct socket_data *sk_data, packet_direction_t pkt_dir) {
    bpf_dbg_enter();

    tcp_req_t *tcp = &sk_data->request.tcp;

    if (sk_data->request.flags == EVENT_TCP_REQUEST) {
        const u8 cur_direction = tcp_direction(sk_data, pkt_dir);

        if (tcp->direction != cur_direction) {
            return handle_tcp_res(ctx, sk_data);
        }

        const u32 len = ctx_len(ctx);

        tcp->len += len;
        tcp->end_monotime_ns = bpf_ktime_get_ns();
        send_tcp_large_buffer(ctx, sk_data, k_packet_type_request, k_large_buf_action_append);
        return true;
    }

    if (sk_data->request.flags != 0) {
        return false;
    }

    return handle_tcp_req(ctx, sk_data, pkt_dir);
}
