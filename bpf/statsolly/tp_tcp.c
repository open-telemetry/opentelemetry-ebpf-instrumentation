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

typedef struct tcp_successful_connection {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    enum tcp_handshake_role role;
    u8 _pad[2];
    connection_info_t conn;
} tcp_successful_connection_t;

typedef struct tcp_reset {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    enum network_io_direction direction;
    enum tcp_reset_cause cause;
    u8 _pad[1];
    connection_info_t conn;
} tcp_reset_t;

// Force structs into the ELF for automatic creation of Golang struct
const tcp_failed_connection_t *unused_tcp_failed_connection __attribute__((unused));
const tcp_retransmit_t *unused_tcp_retransmit_t __attribute__((unused));
const tcp_successful_connection_t *unused_tcp_successful_connection __attribute__((unused));
const tcp_reset_t *unused_tcp_reset __attribute__((unused));

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

    se->flags = k_stat_type_tcp_failed_connection;
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

SEC("tracepoint/sock/inet_sock_set_state")
int obi_stats_tp_inet_sock_set_state_tcp_successful_connection(
    struct trace_event_raw_inet_sock_set_state *args) {
    if (args->protocol != IPPROTO_TCP) {
        return 0;
    }

    const int newstate = args->newstate;
    const int oldstate = args->oldstate;

    if (newstate == TCP_ESTABLISHED && (oldstate == TCP_SYN_SENT || oldstate == TCP_SYN_RECV)) {
        struct sock *const sk = (struct sock *)args->skaddr;
        connection_info_t conn;
        if (!parse_sock_info(sk, &conn)) {
            return 0;
        }

        bpf_d_printk("tcp successful: s_port=%d, d_port=%d", conn.s_port, conn.d_port);

        tcp_successful_connection_t *const se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
        if (!se) {
            return 0;
        }

        se->flags = k_stat_type_tcp_successful_connection;
        se->conn = conn;
        if (oldstate == TCP_SYN_SENT) {
            se->role = role_client;
        } else {
            se->role = role_server;
        }

        bpf_ringbuf_submit(se, stats_events_flags());
    }
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

    se->flags = k_stat_type_tcp_retransmit;
    se->conn = conn;

    bpf_ringbuf_submit(se, stats_events_flags());

    return 0;
}

// NOTE: Resets sent or received while the connection is being established are
// counted as failed connections instead, so they are skipped here.
static __always_inline bool tcp_reset_during_handshake(const u8 state) {
    switch (state) {
    case TCP_LISTEN:
    case TCP_SYN_SENT:
    case TCP_SYN_RECV:
    case TCP_NEW_SYN_RECV:
        return true;
    default:
        return false;
    }
}

// The cause follows the code path that sends the reset. close() with unread
// data, SO_LINGER{0} and TCP_LINGER2 < 0 move the socket to TCP_CLOSE first.
// Keepalive, user-timeout and orphan timers, and tcp_abort() (ss -K,
// bpf_sock_destroy), send it with the state unchanged. Resets answering an
// incoming segment carry that segment and have no inferable cause.
static __always_inline enum tcp_reset_cause sent_reset_cause(const u8 state,
                                                             const bool answers_segment) {
    if (answers_segment) {
        return reset_cause_unknown;
    }
    if (state == TCP_CLOSE) {
        return reset_cause_application;
    }
    return reset_cause_timeout;
}

static __always_inline void submit_tcp_reset(struct sock *sk,
                                             const u8 state,
                                             const enum network_io_direction direction,
                                             const enum tcp_reset_cause cause) {
    connection_info_t conn;
    if (!parse_sock_info(sk, &conn)) {
        return;
    }

    // Moving the socket to TCP_CLOSE released its local port (inet_put_port()
    // zeroes skc_num) before an application abort sends the reset. Only full
    // sockets reach TCP_CLOSE, and inet_sport still holds the port.
    if (state == TCP_CLOSE && conn.s_port == 0) {
        const struct inet_sock *inet = (const struct inet_sock *)sk;
        conn.s_port = bpf_ntohs(BPF_CORE_READ(inet, inet_sport));
    }

    bpf_d_printk(
        "tcp reset: s_port=%d, d_port=%d, direction=%d", conn.s_port, conn.d_port, direction);

    tcp_reset_t *const se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        return;
    }

    se->flags = k_stat_type_tcp_reset;
    se->direction = direction;
    se->cause = cause;
    se->conn = conn;

    bpf_ringbuf_submit(se, stats_events_flags());
}

// Since kernel 6.10 the tracepoint also fires for non-full sockets (only the
// sock_common fields are read here) and without a socket at all, when nothing
// listens on the destination port. 5.8 traces neither case: the call sat behind
// sk_fullsock() until commit 19822a980e19 ("trace: tcp: fully support
// trace_tcp_send_reset").
SEC("raw_tracepoint/tcp_send_reset")
int obi_stats_raw_tp_tcp_send_reset(struct bpf_raw_tracepoint_args *ctx) {
    struct sock *const sk = (struct sock *)ctx->args[0];
    if (!sk) {
        return 0;
    }

    const u8 state = BPF_CORE_READ(sk, __sk_common.skc_state);
    if (tcp_reset_during_handshake(state)) {
        return 0;
    }

    const bool answers_segment = ctx->args[1] != 0;
    submit_tcp_reset(sk, state, direction_transmit, sent_reset_cause(state, answers_segment));

    return 0;
}

// Fires at the top of tcp_reset(), before the socket state changes.
SEC("raw_tracepoint/tcp_receive_reset")
int obi_stats_raw_tp_tcp_receive_reset(struct bpf_raw_tracepoint_args *ctx) {
    struct sock *const sk = (struct sock *)ctx->args[0];

    const u8 state = BPF_CORE_READ(sk, __sk_common.skc_state);
    if (tcp_reset_during_handshake(state)) {
        return 0;
    }

    // A received reset carries no reason on the wire.
    submit_tcp_reset(sk, state, direction_receive, reset_cause_unknown);

    return 0;
}
