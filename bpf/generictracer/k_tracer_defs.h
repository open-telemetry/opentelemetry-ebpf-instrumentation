// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/http_types.h>
#include <common/ringbuf.h>
#include <common/send_args.h>
#include <common/tc_common.h>
#include <common/trace_common.h>

#include <generictracer/k_tracer_tailcall.h>
#include <generictracer/protocol_common.h>
#include <generictracer/protocol_http.h>

#include <generictracer/maps/protocol_cache.h>

#include <pid/pid.h>

// Temporary tracking of tcp_recvmsg arguments
typedef struct recv_args {
    u64 sock_ptr; // linux sock or socket address
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
                                                                void *u_buf,
                                                                int bytes_len,
                                                                u8 ssl,
                                                                u8 direction,
                                                                u16 orig_dport) {
    call_protocol_args_t *args = protocol_args();
    if (!args) {
        return 0;
    }

    args->ssl = ssl;
    args->bytes_len = bytes_len;
    args->direction = direction;
    args->orig_dport = orig_dport;
    args->u_buf = (u64)u_buf;
    args->protocol_type = protocol_type_for_conn_info(info);

    return args;
}

static __always_inline void handle_buf_with_connection(void *ctx,
                                                       pid_connection_info_t *pid_conn,
                                                       void *u_buf,
                                                       int bytes_len,
                                                       u8 ssl,
                                                       u8 direction,
                                                       u16 orig_dport) {
    call_protocol_args_t *args =
        make_protocol_args(pid_conn, u_buf, bytes_len, ssl, direction, orig_dport);
    if (!args) {
        return;
    }

    __builtin_memcpy(&args->pid_conn, pid_conn, sizeof(pid_connection_info_t));
    bpf_probe_read(args->small_buf, MIN_HTTP2_SIZE, (void *)args->u_buf);
    bpf_tail_call(ctx, &jump_table, k_tail_handle_buf_with_args);
}

#define BUF_COPY_BLOCK_SIZE 16

static __always_inline void
read_skb_bytes(const void *skb, u32 offset, unsigned char *buf, const u32 len) {
    u32 max = offset + len;
    int b = 0;
    for (; b < (FULL_BUF_SIZE / BUF_COPY_BLOCK_SIZE); b++) {
        if ((offset + (BUF_COPY_BLOCK_SIZE - 1)) >= max) {
            break;
        }
        bpf_skb_load_bytes(
            skb, offset, (void *)(&buf[b * BUF_COPY_BLOCK_SIZE]), BUF_COPY_BLOCK_SIZE);
        offset += BUF_COPY_BLOCK_SIZE;
    }

    if ((b * BUF_COPY_BLOCK_SIZE) >= len) {
        return;
    }

    // This code is messy to make sure the eBPF verifier is happy. I had to cast to signed 64bit.
    s64 remainder = (s64)max - (s64)offset;

    if (remainder <= 0) {
        return;
    }

    int remaining_to_copy =
        (remainder < (BUF_COPY_BLOCK_SIZE - 1)) ? remainder : (BUF_COPY_BLOCK_SIZE - 1);
    int space_in_buffer = (len < (b * BUF_COPY_BLOCK_SIZE)) ? 0 : len - (b * BUF_COPY_BLOCK_SIZE);

    if (remaining_to_copy <= space_in_buffer) {
        bpf_skb_load_bytes(skb, offset, (void *)(&buf[b * BUF_COPY_BLOCK_SIZE]), remaining_to_copy);
    }
}
