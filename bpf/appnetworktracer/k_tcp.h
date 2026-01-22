// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#pragma once
#include <appnetworktracer/types.h>
#include <appnetworktracer/maps/app_network_events.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>

#include <common/connection_info.h>
#include <common/sockaddr.h>

#include <logger/bpf_dbg.h>

#include <pid/pid.h>

enum {
    k_usec_per_sec = 1000000ULL,
    k_max_srtt_allowed = 60 * k_usec_per_sec,
};

typedef struct app_net_tcp_rtt {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    u8 _pad[3];
    pid_info pid_info;
    u32 srtt;
    connection_info_t conn;
} app_net_tcp_rtt_t;

// This is a shared function between the appnetworktracer and the generictracer
// It will be used in both tcp_close probes to calculate the srtt and handle the event.
static __always_inline void handle_app_network_event_tcp_rtt(struct sock *sk,
                                                             connection_info_t *conn) {
    if (is_tcp_socket_never_connected(sk)) {
        return;
    }

    u32 srtt = BPF_CORE_READ((struct tcp_sock *)sk, srtt_us);

    srtt = srtt >> 3; // undo the scaling to have the real us

    if (srtt == 0) {
        return;
    }

    if (srtt > k_max_srtt_allowed) {
        return;
    }

    app_net_tcp_rtt_t *se = bpf_ringbuf_reserve(&app_network_events, sizeof(*se), 0);
    if (!se) {
        return;
    }
    se->flags = k_event_app_net_tcp_rtt;
    task_pid(&se->pid_info);
    se->srtt = srtt / 1000; // convert to millisecond
    se->conn = *conn;

    bpf_d_printk("pid %u, src port %d, dst port %d, srtt %d",
                 se->pid_info.host_pid,
                 se->conn.s_port,
                 se->conn.d_port,
                 se->srtt);

    bpf_ringbuf_submit(se, app_network_events_flags());
}
