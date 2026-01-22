// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#pragma once
#include <appnetworktracer/k_tcp.h>

SEC("kprobe/tcp_close")
int BPF_KPROBE(obi_kprobe_tcp_close_rtt, struct sock *sk) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    connection_info_t conn;
    if (!parse_sock_info(sk, &conn)) {
        return 0;
    }

    handle_app_network_event_tcp_rtt(sk, &conn);
    return 0;
}
