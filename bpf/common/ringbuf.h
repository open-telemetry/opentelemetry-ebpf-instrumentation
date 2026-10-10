// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

#include <common/event_defs.h>
#include <common/pin_internal.h>
#include <common/ringbuf_metrics.h>

// setting here the following map definitions without pinning them to a global namespace
// would lead that services running both HTTP and GRPC server would duplicate
// the events ringbuffer and goroutines map.
// This is an edge inefficiency that allows us avoiding the gotchas of
// pinning maps to the global namespace (e.g. like not cleaning them up when
// the autoinstrumenter ends abruptly)
// https://ants-gitlab.inf.um.es/jorgegm/xdp-tutorial/-/blob/master/basic04-pinning-maps/README.org
// we can share them later if we find is worth not including code per duplicate
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
    __uint(pinning, OBI_PIN_INTERNAL);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, ringbuf_write_stats_t);
    __uint(max_entries, 1);
    __uint(pinning, OBI_PIN_INTERNAL);
} ringbuf_write_stats_storage SEC(".maps");

// To be Injected from the user space during the eBPF program load & initialization
volatile const u32 wakeup_data_bytes;
volatile const bool ringbuf_metrics_enabled;

// get_flags prevents waking the userspace process up on each ringbuf message.
// If wakeup_data_bytes > 0, it will wait until wakeup_data_bytes are accumulated
// into the buffer before waking the userspace.
static __always_inline long get_flags() {

    if (!wakeup_data_bytes) {
        return 0;
    }

    const u64 sz = bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA);
    return sz >= wakeup_data_bytes ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

static __always_inline void *events_ringbuf_reserve(u64 size, u64 flags) {
    void *event = bpf_ringbuf_reserve(&events, size, flags);
    account_ringbuf_write(&ringbuf_write_stats_storage, ringbuf_metrics_enabled, !event);
    return event;
}

static __always_inline long events_ringbuf_output(void *data, u64 size, u64 flags) {
    const long err = bpf_ringbuf_output(&events, data, size, flags);
    account_ringbuf_write(&ringbuf_write_stats_storage, ringbuf_metrics_enabled, err != 0);
    return err;
}
