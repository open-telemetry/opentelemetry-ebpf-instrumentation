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
#include <common/sock_port_ns.h>
#include <maps/app_network_events.h>
#include <common/common.h>
#include <common/ringbuf.h>

#include <pid/pid.h>
#include "types.h"

#define USEC_PER_SEC 1000000ULL
#define MAX_SRTT_ALLOWED (60 * USEC_PER_SEC)

typedef struct app_net_tcp_rtt {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    u8 _pad[1];
    u16 sport;
    pid_info pid_info;
    u32 netns;
    u32 srtt;
} app_net_tcp_rtt_t;

SEC("kprobe/tcp_close")
int BPF_KPROBE(obi_kprobe_tcp_close_rtt, struct sock *sk) {
    (void)ctx;

    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (family != AF_INET && family != AF_INET6) {
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

    struct sock_port_ns pn = sock_port_ns_from_sk(sk);

    app_net_tcp_rtt_t *se = bpf_ringbuf_reserve(&app_network_events, sizeof(*se), 0);
    if (!se) {
        return 0;
    }
    se->flags = EVENT_APP_NET_TCP_RTT;
    task_pid(&se->pid_info);
    se->srtt = srtt / 1000; // convert to millisecond
    se->netns = pn.netns;
    se->sport = pn.port;
    bpf_d_printk(
        "pid %u, netns %u, port %d, srtt %u", se->pid_info.host_pid, pn.netns, pn.port, se->srtt);
    bpf_ringbuf_submit(se, 0);
    return 0;
}
