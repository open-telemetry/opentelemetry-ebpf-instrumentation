// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/ringbuf_types.h>
#include <common/pin_internal.h>

#include <bpfcore/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, ringbuf_write_stats_t);
    __uint(max_entries, RINGBUF_COUNT);
    __uint(pinning, OBI_PIN_INTERNAL);
} ringbuf_write_stats_storage SEC(".maps");

volatile const bool ringbuf_metrics_enabled = false;

static __always_inline void account_ringbuf_write(enum ringbuf_id ringbuf, bool failed) {
    if (!ringbuf_metrics_enabled) {
        return;
    }

    ringbuf_write_stats_t *stats = bpf_map_lookup_elem(&ringbuf_write_stats_storage, &ringbuf);
    if (!stats) {
        return;
    }

    __sync_fetch_and_add(&stats->writes, 1);
    if (failed) {
        __sync_fetch_and_add(&stats->failures, 1);
    }
}
