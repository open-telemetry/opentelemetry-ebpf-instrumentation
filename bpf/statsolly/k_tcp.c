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
#include <statsolly/maps/tcp_sendmsg_sock.h>

enum {
    k_usec_per_sec = 1000000ULL,
    k_max_srtt_allowed = 60 * k_usec_per_sec,
};

typedef struct tcp_rtt {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    enum tcp_handshake_role role;
    u8 _pad[2];
    u32 srtt_us;
    connection_info_t conn;
} tcp_rtt_t;

typedef struct tcp_io {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    enum network_io_direction direction;
    u8 _pad[2];
    u32 bytes;
    connection_info_t conn;
} tcp_io_t;

// Force structs into the ELF for automatic creation of Golang struct
const tcp_rtt_t *unused_tcp_rtt __attribute__((unused));
const tcp_io_t *unused_tcp_io __attribute__((unused));

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
    const u8 *role_ptr = bpf_map_lookup_elem(&sock_role, &sk);
    se->role = role_ptr ? *role_ptr : role_unknown;

    bpf_d_printk(
        "tcp rtt: s_port=%d, d_port=%d, srtt_us=%u", se->conn.s_port, se->conn.d_port, se->srtt_us);
    bpf_ringbuf_submit(se, stats_events_flags());

    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(obi_kprobe_tcp_sendmsg_io, struct sock *sk, struct msghdr *msg, size_t size) {
    (void)ctx;
    (void)msg;
    (void)size;
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tcp_sendmsg_sock, &pid_tgid, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(obi_kretprobe_tcp_sendmsg_io) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *const *skp = bpf_map_lookup_elem(&tcp_sendmsg_sock, &pid_tgid);

    if (!skp) {
        return 0;
    }
    struct sock *const sk = *skp;
    bpf_map_delete_elem(&tcp_sendmsg_sock, &pid_tgid);

    const long sent = PT_REGS_RC(ctx);
    if (sent <= 0) {
        return 0;
    }

    connection_info_t conn;
    if (!parse_sock_info(sk, &conn)) {
        return 0;
    }

    tcp_io_t *se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        return 0;
    }

    se->flags = k_event_stat_tcp_io;
    se->direction = direction_transmit;
    se->bytes = (u32)sent;
    se->conn = conn;

    bpf_ringbuf_submit(se, stats_events_flags());
    return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(obi_kprobe_tcp_cleanup_rbuf_io, struct sock *sk, int copied) {
    (void)ctx;

    if (copied <= 0) {
        return 0;
    }

    connection_info_t conn;
    if (!parse_sock_info(sk, &conn)) {
        return 0;
    }

    tcp_io_t *se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        return 0;
    }

    se->flags = k_event_stat_tcp_io;
    se->direction = direction_receive;
    se->bytes = (u32)copied;
    se->conn = conn;

    bpf_ringbuf_submit(se, stats_events_flags());

    return 0;
}
