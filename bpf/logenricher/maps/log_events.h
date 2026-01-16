// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
    __uint(pinning, OBI_PIN_INTERNAL);
} log_events SEC(".maps");

static __always_inline long log_events_flags() {
    long sz = bpf_ringbuf_query(&log_events, BPF_RB_AVAIL_DATA);
    return sz >= 4096 ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}
