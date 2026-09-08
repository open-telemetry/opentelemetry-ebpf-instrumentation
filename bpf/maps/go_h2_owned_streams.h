// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>

#include <common/go_h2_owned_stream.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_h2_owned_stream_key_t);
    __type(value, u64);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_h2_owned_streams SEC(".maps");

static __always_inline void set_go_h2_owned_stream_process_identity(go_h2_owned_stream_key_t *key) {
    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    const u64 start_time = BPF_CORE_READ(task, group_leader, start_time);
    key->process_start_lo = (u32)start_time;
    key->process_start_hi = (u32)(start_time >> 32);
}

static __always_inline bool fresh_go_h2_owned_stream(const go_h2_owned_stream_key_t *key, u64 now) {
    u64 *marked_ns = bpf_map_lookup_elem(&go_h2_owned_streams, key);
    if (!marked_ns) {
        return false;
    }
    if (!go_h2_owned_stream_is_fresh(*marked_ns, now)) {
        bpf_map_delete_elem(&go_h2_owned_streams, key);
        return false;
    }
    return true;
}
