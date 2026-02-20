// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/protocol_defs.h>
#include <common/ringbuf.h>

#include <generictracer/k_tracer_defs.h>

#include <generictracer/maps/active_recv_args.h>
#include <generictracer/maps/active_send_args.h>
#include <generictracer/maps/active_send_sock_args.h>

static __always_inline u8 same_direction(pid_connection_info_t *p_conn, u8 direction) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, p_conn);
    if (info && !info->submitted) {
        return ((info->type == EVENT_HTTP_REQUEST) && (direction == TCP_SEND)) ||
               ((info->type == EVENT_HTTP_CLIENT) && (direction == TCP_RECV));
    }
    return false;
}

static __always_inline void ensure_sent_event(u64 id, u64 *sock_p, u8 direction) {
    if (high_request_volume) {
        return;
    }

    send_args_t *s_args = (send_args_t *)bpf_map_lookup_elem(&active_send_args, &id);
    if (s_args) {
        bpf_dbg_printk("Checking if we need to finish the request per thread id");

        if (same_direction(&s_args->p_conn, direction)) {
            return;
        }

        finish_possible_delayed_http_request(&s_args->p_conn);
    } // see if we match on another thread, but same sock *
    s_args = (send_args_t *)bpf_map_lookup_elem(&active_send_sock_args, sock_p);
    if (s_args) {
        bpf_dbg_printk("Checking if we need to finish the request per socket");
        if (same_direction(&s_args->p_conn, direction)) {
            return;
        }
        finish_possible_delayed_http_request(&s_args->p_conn);
    }
}

static __always_inline void force_sent_event(u64 id, u64 *sock_p) {
    send_args_t *s_args = (send_args_t *)bpf_map_lookup_elem(&active_send_args, &id);
    if (s_args) {
        bpf_dbg_printk("Checking if we need to finish the request per thread id");
        force_finish_possible_delayed_http_request(&s_args->p_conn);
    } // see if we match on another thread, but same sock *
    s_args = (send_args_t *)bpf_map_lookup_elem(&active_send_sock_args, sock_p);
    if (s_args) {
        bpf_dbg_printk("Checking if we need to finish the request per socket");
        force_finish_possible_delayed_http_request(&s_args->p_conn);
    }
}