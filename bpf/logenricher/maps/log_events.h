// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>
#include <common/ringbuf_metrics.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
    __uint(pinning, OBI_PIN_INTERNAL);
} log_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, ringbuf_write_stats_t);
    __uint(max_entries, 1);
    __uint(pinning, OBI_PIN_INTERNAL);
} log_ringbuf_write_stats_storage SEC(".maps");

volatile const bool ringbuf_metrics_enabled;

static __always_inline long log_events_flags() {
    const u64 sz = bpf_ringbuf_query(&log_events, BPF_RB_AVAIL_DATA);
    return sz >= 4096 ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

static __always_inline long log_events_ringbuf_output(void *data, u64 size, u64 flags) {
    const long err = bpf_ringbuf_output(&log_events, data, size, flags);
    account_ringbuf_write(&log_ringbuf_write_stats_storage, ringbuf_metrics_enabled, err != 0);
    return err;
}
