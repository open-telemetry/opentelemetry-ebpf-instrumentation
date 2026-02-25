// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#pragma once
#include <statsolly/types.h>
#include <statsolly/maps/stats_events.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>

#include <common/connection_info.h>
#include <common/sockaddr.h>

#include <logger/bpf_dbg.h>


enum {
    k_usec_per_sec = 1000000ULL,
    k_max_srtt_allowed = 60 * k_usec_per_sec,
};

typedef struct tcp_rtt {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    u8 _pad[3];
    u32 srtt;
    connection_info_t conn;
} tcp_rtt_t;

SEC("kprobe/tcp_close")
int BPF_KPROBE(obi_kprobe_tcp_close_srtt, struct sock *sk) {
    (void)ctx;
    connection_info_t conn;
    if (!parse_sock_info(sk, &conn)) {
        return 0;
    }

    if (is_tcp_socket_never_connected(sk)) {
        return 0;
    }

    u32 srtt = BPF_CORE_READ((struct tcp_sock *)sk, srtt_us);

    srtt = srtt >> 3; // undo the scaling to have the real us

    if (srtt == 0) {
        return 0;
    }

    if (srtt > k_max_srtt_allowed) {
        return 0;
    }

    tcp_rtt_t *se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        return 0;
    }
    se->flags = k_event_stat_tcp_rtt;
    se->srtt = srtt / 1000; // convert to millisecond
    se->conn = conn;

    bpf_printk("src port %d, dst port %d, srtt %d",
                 se->conn.s_port,
                 se->conn.d_port,
                 se->srtt);
    // stats_events_flags()
    bpf_ringbuf_submit(se, 0);

    return 0;
}
