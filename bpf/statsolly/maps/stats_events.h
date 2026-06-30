// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
    __uint(pinning, OBI_PIN_INTERNAL);
} stats_events SEC(".maps");

// To be injected from userspace during eBPF program load & initialization.
// When 0, every submission wakes up userspace immediately.
volatile const u32 stats_wakeup_data_bytes;

static __always_inline long stats_events_flags() {
    if (!stats_wakeup_data_bytes) {
        return 0;
    }
    const u64 avail_data = bpf_ringbuf_query(&stats_events, BPF_RB_AVAIL_DATA);
    return avail_data >= stats_wakeup_data_bytes ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}
