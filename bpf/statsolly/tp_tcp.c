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
#include <statsolly/maps/sock_role.h>

#ifndef ECONNREFUSED
#define ECONNREFUSED 111
#endif
#ifndef ECONNRESET
#define ECONNRESET 104
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT 110
#endif
#ifndef EHOSTUNREACH
#define EHOSTUNREACH 113
#endif
#ifndef ENETUNREACH
#define ENETUNREACH 101
#endif

enum tcp_fail_reason {
    reason_unknown = 0,
    reason_connection_refused = 1,
    reason_connection_reset = 2,
    reason_timed_out = 3,
    reason_host_unreachable = 4,
    reason_net_unreachable = 5,
    reason_other = 255,
};

enum tcp_handshake_role {
    role_unknown = 0,
    role_client = 1,
    role_server = 2,
};

static __always_inline u8 sk_err_to_reason(const int err) {
    switch (err) {
    case ECONNREFUSED:
        return reason_connection_refused;
    case ECONNRESET:
        return reason_connection_reset;
    case ETIMEDOUT:
        return reason_timed_out;
    case EHOSTUNREACH:
        return reason_host_unreachable;
    case ENETUNREACH:
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
    u8 role;
    u8 _pad[1];
    connection_info_t conn;
} tcp_failed_connection_t;

// Force tcp_failed_connection_t
const tcp_failed_connection_t *unused_tcp_failed_connection __attribute__((unused));

SEC("tracepoint/sock/inet_sock_set_state")
int obi_tracepoint_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *args) {
    if (args->protocol != IPPROTO_TCP) {
        return 0;
    }

    struct sock *const sk = (struct sock *)args->skaddr;

    if (args->oldstate == TCP_SYN_SENT || args->oldstate == TCP_SYN_RECV) {
        if (args->newstate == TCP_ESTABLISHED) {
            const u8 role = (args->oldstate == TCP_SYN_SENT) ? role_client : role_server;
            bpf_map_update_elem(&sock_role, &sk, &role, BPF_ANY);
        }
    }

    if (args->newstate != TCP_CLOSE) {
        return 0;
    }

    // {TCP_LAST_ACK|TCP_TIME_WAIT}->TCP_CLOSE are normal close transitions
    // TCP_LISTEN->TCP_CLOSE is what happens when a listener socket is shut down
    if (args->oldstate == TCP_LAST_ACK || args->oldstate == TCP_TIME_WAIT) {
        goto cleanup;
    }
    if (args->oldstate == TCP_LISTEN) {
        return 0;
    }

    const int err = BPF_CORE_READ(sk, sk_err);
    // Trust sk_err: err==0 means the kernel saw no problem (e.g. local close()
    // with unread data sends RST without setting sk_err).
    // Exception: aborted connect (TCP_SYN_SENT -> TCP_CLOSE) never established, still a failure.
    if (err == 0 && args->oldstate != TCP_SYN_SENT) {
        goto cleanup;
    }
    const u8 reason = sk_err_to_reason(err);

    connection_info_t conn;
    if (!parse_sock_info(sk, &conn)) {
        goto cleanup;
    }

    bpf_d_printk("tcp failed: s_port=%d, d_port=%d, reason=%d", conn.s_port, conn.d_port, reason);

    tcp_failed_connection_t *const se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        goto cleanup;
    }

    se->flags = k_event_stat_tcp_failed_connection;
    se->reason = reason;
    se->conn = conn;

    const u8 *role_ptr = bpf_map_lookup_elem(&sock_role, &sk);
    if (role_ptr) {
        se->role = *role_ptr;
    } else if (args->oldstate == TCP_SYN_SENT) {
        se->role = role_client;
    } else if (args->oldstate == TCP_SYN_RECV) {
        se->role = role_server;
    } else {
        se->role = role_unknown;
    }

    bpf_ringbuf_submit(se, stats_events_flags());

cleanup:
    bpf_map_delete_elem(&sock_role, &sk);
    return 0;
}
