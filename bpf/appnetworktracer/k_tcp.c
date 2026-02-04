// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#pragma once
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>
#include <common/protocol_defs.h>
#include <logger/bpf_dbg.h>
#include <pid/pid.h>
#include <maps/app_network_events.h>
#include <common/connection_info.h>
#include <common/ringbuf.h>
#include <common/sockaddr.h>
#include <generictracer/protocol_common.h>

#include <pid/pid.h>
#include "types.h"

#define USEC_PER_SEC 1000000ULL
#define MAX_SRTT_ALLOWED (60 * USEC_PER_SEC)

typedef struct app_net_tcp_rtt {
    u8 flags;     // Must be first, we use it to tell what kind of event we have on the ring buffer
    u8 direction; // 1 = Outbound, 2 = Inbound
    u8 _pad[2];
    pid_info pid_info;
    u32 srtt;
    connection_info_t conn;
} app_net_tcp_rtt_t;


SEC("kprobe/tcp_close")
int BPF_KPROBE(obi_kprobe_tcp_close_rtt, struct sock *sk) {
    (void)ctx;

    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    connection_info_t conn;
    if (!parse_sock_info(sk, &conn)) {
        return 0;
    }
    sort_connection_info(&conn);

    if (is_tcp_socket_never_connected(sk)) {
        return 0;
    }

    u32 srtt = BPF_CORE_READ((struct tcp_sock *)sk, srtt_us);

    if (srtt == 0) {
        return 0;
    }
    srtt = srtt >> 3; // undo the scaling to have the real us
    if (srtt == 0) {
        return 0;
    }

    if (srtt > MAX_SRTT_ALLOWED) {
        return 0;
    }

    app_net_tcp_rtt_t *se = bpf_ringbuf_reserve(&app_network_events, sizeof(*se), 0);
    if (!se) {
        return 0;
    }
    se->flags = EVENT_APP_NET_TCP_RTT;
    task_pid(&se->pid_info);
    se->srtt = srtt / 1000; // convert to millisecond
    se->conn = conn;
    u32 netns = task_netns();

    bool is_server = is_listening(se->conn.s_port, netns);
    if (is_server) {
        se->direction = INBOUND;
    } else {
        se->direction = OUTBOUND;
    }
    bpf_d_printk("pid %u, src port %d, dst port %d, direction %d, is_server %d",
                 se->pid_info.host_pid,
                 se->conn.s_port,
                 se->conn.d_port,
                se->direction,
                 is_server);

    bpf_ringbuf_submit(se, 0);
    return 0;
}
