// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

#include <common/event_defs.h>
#include <common/pin_internal.h>

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

typedef struct ringbuf_write_count_t {
    u64 total;
    u64 failed;
} ringbuf_write_count;

// Per-CPU counters of attempted and failed writes to the events ringbuffer.
// OBI_PIN_INTERNAL, like events itself, so all tracers share one instance.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, ringbuf_write_count);
    __uint(max_entries, 1);
    __uint(pinning, OBI_PIN_INTERNAL);
} rb_write_stats SEC(".maps");

// To be Injected from the user space during the eBPF program load & initialization
volatile const u32 wakeup_data_bytes;

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

// Records one events-ringbuffer write attempt, flagged failed when the
// reserve/output did not reach userspace. Call after each write on &events.
static __always_inline void account_ringbuf_write(bool failed) {
    const u32 key = 0;
    ringbuf_write_count *stats = bpf_map_lookup_elem(&rb_write_stats, &key);
    if (!stats) {
        return;
    }

    stats->total++;
    if (failed) {
        stats->failed++;
    }
}
