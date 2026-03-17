// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>

#include <common/connection_info.h>
#include <common/sockaddr.h>

#include <logger/bpf_dbg.h>

#include <statsolly/types.h>
#include <statsolly/maps/stats_events.h>

enum {
    k_usec_per_sec = 1000000ULL,
    k_max_srtt_allowed = 60 * k_usec_per_sec,
};

typedef struct tcp_rtt {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    u8 _pad[3];
    u32 srtt_us;
    connection_info_t conn;
} tcp_rtt_t;

// Force tcp_rtt_t
const tcp_rtt_t *unused_tcp_rtt __attribute__((unused));

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

    u32 srtt_us = BPF_CORE_READ((struct tcp_sock *)sk, srtt_us);

    srtt_us = srtt_us >> 3; // undo the scaling to have the real us

    if (srtt_us == 0) {
        return 0;
    }

    if (srtt_us > k_max_srtt_allowed) {
        return 0;
    }

    tcp_rtt_t *se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        return 0;
    }

    se->flags = k_event_stat_tcp_rtt;
    se->srtt_us = srtt_us;
    se->conn = conn;

    bpf_d_printk("s_port=%d, d_port=%d, srtt_us=%u", se->conn.s_port, se->conn.d_port, se->srtt_us);
    bpf_ringbuf_submit(se, stats_events_flags());

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
