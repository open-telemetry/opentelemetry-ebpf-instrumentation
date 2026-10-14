// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>
#include <common/pin_internal.h>
#include <common/ringbuf_metrics.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
    __uint(pinning, OBI_PIN_INTERNAL);
} gpu_events SEC(".maps");

static __always_inline void *gpu_events_ringbuf_reserve(u64 size, u64 flags) {
    void *event = bpf_ringbuf_reserve(&gpu_events, size, flags);
    account_ringbuf_write(RINGBUF_GPU_EVENTS, !event);
    return event;
}
