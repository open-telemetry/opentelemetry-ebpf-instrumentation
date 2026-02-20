// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include "k_tcp.c"
#include "types.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Event for application network metrics
const app_net_tcp_rtt_t *unused_1 __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} app_network_events SEC(".maps");

static __always_inline long app_network_events_flags() {
    const u64 avail_data = bpf_ringbuf_query(&app_network_events, BPF_RB_AVAIL_DATA);
    return avail_data >= 4096 ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}
