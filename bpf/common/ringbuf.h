// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

#include <common/event_defs.h>
#include <common/pin_internal.h>
#include <common/ringbuf_metrics.h>
#include <common/ringbuf_record.h>

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

// To be Injected from the user space during the eBPF program load & initialization
volatile const u32 wakeup_data_bytes;

static __always_inline long wakeup_flags(u64 pending_bytes) {
    if (!wakeup_data_bytes) {
        return 0;
    }

    const u64 sz = bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA) + pending_bytes;
    return sz >= wakeup_data_bytes ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

// get_flags prevents waking the userspace process up on each ringbuf message.
// If wakeup_data_bytes > 0, it will wait until wakeup_data_bytes are accumulated
// into the buffer before waking the userspace.
// Use it after bpf_ringbuf_reserve: BPF_RB_AVAIL_DATA already counts the reserved record.
static __always_inline long get_flags() {
    return wakeup_flags(0);
}

// get_output_flags is get_flags for bpf_ringbuf_output, which reserves the record only after
// the flags are computed, so the record of the given size is added to the queued bytes.
static __always_inline long get_output_flags(u64 size) {
    return wakeup_flags(ringbuf_record_size(size));
}

static __always_inline void *events_ringbuf_reserve(u64 size, u64 flags) {
    void *event = bpf_ringbuf_reserve(&events, size, flags);
    account_ringbuf_write(RINGBUF_EVENTS, !event);
    return event;
}

// events_ringbuf_output picks the wakeup flags itself: the caller cannot pass get_flags(),
// which would not count this record.
static __always_inline long events_ringbuf_output(void *data, u64 size) {
    const long err = bpf_ringbuf_output(&events, data, size, get_output_flags(size));
    account_ringbuf_write(RINGBUF_EVENTS, err != 0);
    return err;
}
