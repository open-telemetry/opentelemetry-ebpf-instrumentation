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

typedef struct app_net_tcp_rtt {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    u8 _pad[1];
    u16 sport;
    pid_info pid_info;
    u32 pid;
    u32 netns;
    u32 srtt;
} app_net_tcp_rtt_t;

SEC("kprobe/tcp_close")
int BPF_KPROBE(obi_kprobe_tcp_close_rtt, struct sock *sk) {

    u64 id = bpf_get_current_pid_tgid();

    // TODO pino: check it very carefully
    if (!valid_pid(id)) {
        return 0;
    }

    if (!sk) {
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

    u64 rtt_us = srtt >> 3;
    if (rtt_us == 0) {
        return 0;
    }

    if (rtt_us > 60ULL * 1000 * 1000) {
        return 0;
    }

    const struct sock_common *skc = 0;
    BPF_CORE_READ_INTO(&skc, sk, __sk_common);
    struct sock_port_ns pn = sock_port_ns_from_skc(skc);

    app_net_tcp_rtt_t *se = bpf_ringbuf_reserve(&app_network_events, sizeof(*se), 0);
    if (!se)
        return 0;
    se->flags = EVENT_APP_NET_TCP_RTT;
    task_pid(&se->pid_info);
    se->srtt = srtt;
    se->netns = pn.netns;
    se->sport = pn.port;
    se->pid = id;
    bpf_ringbuf_submit(se, 0);
    bpf_d_printk("pid %u, netns %u, port %d, srtt %u", id, pn.netns, pn.port, srtt);
    return 0;
}
