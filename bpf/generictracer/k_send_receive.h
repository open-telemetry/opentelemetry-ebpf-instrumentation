// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <generictracer/k_tracer_defs.h>

#include <generictracer/maps/active_recv_args.h>
#include <generictracer/maps/active_send_args.h>
#include <generictracer/maps/active_send_sock_args.h>

static __always_inline void ensure_sent_event_helper(u64 id, u64 *sock_p, u8 clean_up) {
    send_args_t *s_args = (send_args_t *)bpf_map_lookup_elem(&active_send_args, &id);
    if (s_args) {
        if (high_request_volume) {
            goto done;
        }
        bpf_dbg_printk("Checking if we need to finish the request per thread id");
        finish_possible_delayed_http_request(&s_args->p_conn);
    } // see if we match on another thread, but same sock *
    s_args = (send_args_t *)bpf_map_lookup_elem(&active_send_sock_args, sock_p);
    if (s_args) {
        if (high_request_volume) {
            goto done;
        }
        bpf_dbg_printk("Checking if we need to finish the request per socket");
        finish_possible_delayed_http_request(&s_args->p_conn);
    }

done:
    if (clean_up && s_args) {
        cleanup_http_info(&s_args->p_conn);
    }
}

static __always_inline void ensure_sent_event(u64 id, u64 *sock_p) {
    ensure_sent_event_helper(id, sock_p, 0);
}

static __always_inline void force_sent_event(u64 id, u64 *sock_p) {
    ensure_sent_event_helper(id, sock_p, 1);
}