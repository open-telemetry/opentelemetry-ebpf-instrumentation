// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/http_info.h>
#include <common/http_types.h>
#include <common/lw_thread.h>
#include <common/preempt_guard.h>
#include <common/protocol_http_helpers.h>
#include <common/usdt.h>

#include <generictracer/k_tracer_tailcall.h>
#include <generictracer/protocol_common.h>

#include <generictracer/maps/protocol_cache.h>

// Temporary tracking of tcp_recvmsg arguments
typedef struct recv_args {
    u64 sock_ptr; // linux sock or socket address
    // stashed at recv entry so the kretprobe can read msg_name, which the kernel
    // fills with the source address on return, to classify unconnected UDP DNS
    u64 msg_ptr;
    // this is done because bpf2go cannot generate the go bindings of this
    // struct containing a 'iovec_iter_ctx iovec_ctx' member
    unsigned char iovec_ctx[sizeof(iovec_iter_ctx)];
} recv_args_t;

static __always_inline enum protocol_type
protocol_type_for_conn_info(const pid_connection_info_t *info) {
    const enum protocol_type *cached_protocol_type =
        bpf_map_lookup_elem(&protocol_cache, &info->conn);
    if (!cached_protocol_type) {
        if (already_tracked_http(info)) {
            return k_protocol_type_http;
        }
    }
    return cached_protocol_type ? *cached_protocol_type : k_protocol_type_unknown;
}

static __always_inline call_protocol_args_t *make_protocol_args(const pid_connection_info_t *info,
                                                                const lw_thread_t lw_thread,
                                                                const protocol_selector_t protocols,
                                                                void *u_buf,
                                                                int bytes_len,
                                                                u8 ssl,
                                                                u8 direction,
                                                                u16 orig_dport,
                                                                struct sock *sk) {
    if (bytes_len <= 0) {
        return 0;
    }

    call_protocol_args_t *args = protocol_args();
    if (!args) {
        return 0;
    }

    args->ssl = ssl;
    args->bytes_len = bytes_len;
    args->direction = direction;
    args->orig_dport = orig_dport;
    args->sock_ptr = (u64)sk;
    args->u_buf = (u64)u_buf;
    args->lw_thread = lw_thread;
    args->protocols = protocols;
    args->protocol_type = protocol_type_for_conn_info(info);

    args->pid_conn = *info;
    __builtin_memset(args->small_buf, 0, sizeof(args->small_buf));
    u32 small_buf_len = (u32)bytes_len;
    bpf_clamp_umax(small_buf_len, sizeof(args->small_buf));
    bpf_probe_read(args->small_buf, small_buf_len, (void *)args->u_buf);

    return args;
}

static __always_inline void handle_buf_with_connection(void *ctx,
                                                       pid_connection_info_t *pid_conn,
                                                       void *u_buf,
                                                       int bytes_len,
                                                       u8 ssl,
                                                       u8 direction,
                                                       u16 orig_dport,
                                                       struct sock *sk) {
    call_protocol_args_t *args = make_protocol_args(pid_conn,
                                                    k_lw_thread_none,
                                                    k_protocol_selector_all,
                                                    u_buf,
                                                    bytes_len,
                                                    ssl,
                                                    direction,
                                                    orig_dport,
                                                    sk);
    if (!args) {
        return;
    }

    preempt_guarded_tail_call(ctx, &jump_table, k_tail_handle_buf_with_args);
}

static __always_inline void handle_light_weight_thread_buf(void *ctx,
                                                           const lw_thread_t lw_thread,
                                                           protocol_selector_t protocols,
                                                           pid_connection_info_t *pid_conn,
                                                           void *u_buf,
                                                           int bytes_len,
                                                           u8 ssl,
                                                           u8 direction,
                                                           u16 orig_dport) {
    call_protocol_args_t *args = make_protocol_args(
        pid_conn, lw_thread, protocols, u_buf, bytes_len, ssl, direction, orig_dport, 0);
    if (!args) {
        return;
    }

    preempt_guarded_tail_call(ctx, &jump_table, k_tail_handle_buf_with_args);
}

static __always_inline void
read_skb_bytes(const void *skb, u32 offset, unsigned char *buf, const u32 len) {
    enum : u32 { k_block_size = 16 };
    enum : u32 { k_max_len = FULL_BUF_SIZE };
    const u32 niter = k_max_len / k_block_size;

    // prevent register narrowing and the verifier from losing track of things
    u64 remaining = len;
    barrier_var(remaining);

    if (remaining > k_max_len) {
        remaining = k_max_len;
    }

    for (u32 i = 0; i < niter; ++i) {
        if (remaining <= k_block_size) {
            break;
        }

        bpf_skb_load_bytes(skb, offset, buf, k_block_size);

        buf += k_block_size;
        offset += k_block_size;
        remaining -= k_block_size;
    }

    // makes 5.15 happy
    u64 last = remaining - 1;
    barrier_var(last);

    if (last >= k_block_size) {
        return;
    }

    bpf_skb_load_bytes(skb, offset, buf, last + 1);
}
