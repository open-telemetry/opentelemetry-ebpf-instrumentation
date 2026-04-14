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

enum tcp_fail_reason {
    reason_unknown = 0,            // sk_err was 0, cause not determined
    reason_connection_refused = 1, // ECONNREFUSED (111)
    reason_connection_reset = 2,   // ECONNRESET (104)
    reason_timed_out = 3,          // ETIMEDOUT (110)
    reason_host_unreachable = 4,   // EHOSTUNREACH (113)
    reason_net_unreachable = 5,    // ENETUNREACH (101)
    reason_other = 255,            // anything else
};

static __always_inline u8 sk_err_to_reason(int err) {
    switch (err) {
    case 111:
        return reason_connection_refused;
    case 104:
        return reason_connection_reset;
    case 110:
        return reason_timed_out;
    case 113:
        return reason_host_unreachable;
    case 101:
        return reason_net_unreachable;
    case 0:
        return reason_unknown;
    default:
        return reason_other;
    }
}

typedef struct tcp_failed_connection {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    u8 reason;
    u8 _pad[2];
    connection_info_t conn;
} tcp_failed_connection_t;

// Force tcp_failed_connection_t
const tcp_failed_connection_t *unused_tcp_failed_connection __attribute__((unused));

SEC("tracepoint/sock/inet_sock_set_state")
int obi_tracepoint_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *args) {
    if (args->protocol != IPPROTO_TCP) {
        return 0;
    }

    if (args->newstate != TCP_CLOSE) {
        return 0;
    }

    // These are normal completions, not failures
    if (args->oldstate == TCP_LAST_ACK || args->oldstate == TCP_TIME_WAIT) {
        return 0;
    }

    struct sock *sk = (struct sock *)args->skaddr;

    connection_info_t conn;
    if (!parse_sock_info(sk, &conn)) {
        return 0;
    }

    int err = BPF_CORE_READ(sk, sk_err);
    u8 reason = sk_err_to_reason(err);

    bpf_d_printk("tcp failed: oldstate=%d, reason=%d, s_port=%d, d_port=%d",
                 args->oldstate,
                 reason,
                 conn.s_port,
                 conn.d_port);

    tcp_failed_connection_t *se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        return 0;
    }

    se->flags = k_event_stat_failed_connection;
    se->reason = reason;
    se->conn = conn;

    bpf_ringbuf_submit(se, 0);

    return 0;
}
