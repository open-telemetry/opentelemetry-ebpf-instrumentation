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

static __always_inline enum tcp_fail_reason sk_err_to_reason(const int err) {
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
    enum tcp_fail_reason reason;
    enum tcp_handshake_role role;
    u8 _pad[1];
    connection_info_t conn;
} tcp_failed_connection_t;

typedef struct tcp_retransmit {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    u8 _pad[3];
    connection_info_t conn;
} tcp_retransmit_t;

// Force structs into the ELF for automatic creation of Golang struct
const tcp_failed_connection_t *unused_tcp_failed_connection __attribute__((unused));
const tcp_retransmit_t *unused_tcp_retransmit_t __attribute__((unused));

// obi_stats_tp_inet_sock_set_state_conn_role is the sole owner of the sock_role map.
// It writes the role (client/server) when a connection is established and
// it also handles all cleanup: any transition to TCP_CLOSE removes the entry,
// covering both normal graceful closes and abnormal ones.
//
// Attachment order invariant: this program must be attached AFTER
// obi_stats_tp_inet_sock_set_state_tcp_failed_connection (or any future tp probes that need the role)
// on the same tracepoint. BPF programs on a tracepoint run FIFO, so the probe(s) read sock_role first,
// then this program deletes it. Reversing the order would cause tcp_failed_conn or any other probes
// to see a stale NULL on the same TCP_CLOSE event.
SEC("tracepoint/sock/inet_sock_set_state")
int obi_stats_tp_inet_sock_set_state_conn_role(struct trace_event_raw_inet_sock_set_state *args) {
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

    if (args->newstate == TCP_CLOSE) {
        bpf_map_delete_elem(&sock_role, &sk);
        return 0;
    }

    return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int obi_stats_tp_inet_sock_set_state_tcp_failed_connection(
    struct trace_event_raw_inet_sock_set_state *args) {
    if (args->protocol != IPPROTO_TCP) {
        return 0;
    }

    struct sock *const sk = (struct sock *)args->skaddr;

    if (args->newstate != TCP_CLOSE) {
        return 0;
    }

    // {TCP_LAST_ACK|TCP_TIME_WAIT}->TCP_CLOSE are normal close transitions
    // TCP_LISTEN->TCP_CLOSE is what happens when a listener socket is shut down
    if (args->oldstate == TCP_LAST_ACK || args->oldstate == TCP_TIME_WAIT ||
        args->oldstate == TCP_LISTEN) {
        return 0;
    }

    const int err = BPF_CORE_READ(sk, sk_err);
    // Trust sk_err: err==0 means the kernel saw no problem (e.g. local close()
    // with unread data sends RST without setting sk_err).
    // Exception: aborted connect (TCP_SYN_SENT -> TCP_CLOSE) never established, still a failure.
    if (err == 0 && args->oldstate != TCP_SYN_SENT) {
        return 0;
    }
    const u8 reason = sk_err_to_reason(err);

    connection_info_t conn;
    if (!parse_sock_info(sk, &conn)) {
        return 0;
    }

    bpf_d_printk("tcp failed: s_port=%d, d_port=%d, reason=%d", conn.s_port, conn.d_port, reason);

    tcp_failed_connection_t *const se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        return 0;
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

    return 0;
}

SEC("raw_tracepoint/tcp_retransmit_skb")
int obi_stats_raw_tp_tcp_retransmit_skb(struct bpf_raw_tracepoint_args *ctx) {

    struct sock *const sk = (struct sock *)ctx->args[0];

    connection_info_t conn;
    if (!parse_sock_info(sk, &conn)) {
        return 0;
    }

    bpf_d_printk("tcp retransmit: s_port=%d, d_port=%d", conn.s_port, conn.d_port);

    tcp_retransmit_t *const se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        return 0;
    }

    se->flags = k_event_stat_tcp_retransmit;
    se->conn = conn;

    bpf_ringbuf_submit(se, stats_events_flags());

    return 0;
}
