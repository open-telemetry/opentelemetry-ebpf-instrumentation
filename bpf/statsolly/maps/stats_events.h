// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} stats_events SEC(".maps");

static __always_inline long stats_events_flags() {
    const u64 avail_data = bpf_ringbuf_query(&stats_events, BPF_RB_AVAIL_DATA);
    return avail_data >= 4096 ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}
