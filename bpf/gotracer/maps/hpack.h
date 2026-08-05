// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/event_defs.h>
#include <common/go_addr_key.h>
#include <common/map_sizing.h>
#include <common/outgoing_trace_handoff.h>
#include <common/pin_internal.h>
#include <common/scratch_mem.h>

#include <gotracer/go_hpack.h>
#include <gotracer/maps/outgoing_trace_handoff.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_exact_process_addr_key_t);
    __type(value, go_hpack_block_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_hpack_traceparents SEC(".maps");

SCRATCH_MEM_TYPED(go_hpack_block_scratch, go_hpack_block_t);

static __always_inline u8 go_hpack_current_key(const go_addr_key_t *key,
                                               go_exact_process_addr_key_t *exact) {
    if (!key || !exact) {
        return 0;
    }
    const u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    const u64 process_start_time = OBI_CURRENT_PROCESS_START_BOOTTIME_NS();
    if (!process_start_time || key->pid != pid) {
        return 0;
    }
    *exact = go_exact_process_addr_key(pid, process_start_time, key->addr);
    return 1;
}

static __always_inline u8 read_go_hpack_traceparent(const go_addr_key_t *key,
                                                    go_hpack_block_t *block) {
    go_exact_process_addr_key_t exact = {};
    if (!go_hpack_current_key(key, &exact)) {
        return k_go_hpack_traceparent_unknown;
    }
    go_hpack_block_t *stored = bpf_map_lookup_elem(&go_hpack_traceparents, &exact);
    if (!stored) {
        return k_go_hpack_traceparent_unknown;
    }

    *block = *stored;
    return go_hpack_traceparent_class(stored);
}

static __always_inline void clear_go_hpack_traceparent(const go_addr_key_t *key) {
    go_exact_process_addr_key_t exact = {};
    if (go_hpack_current_key(key, &exact)) {
        bpf_map_delete_elem(&go_hpack_traceparents, &exact);
    }
}

static __always_inline long replace_go_hpack_traceparent(const go_addr_key_t *key,
                                                         const go_hpack_block_t *block) {
    go_exact_process_addr_key_t exact = {};
    if (!block || !go_hpack_current_key(key, &exact)) {
        return -1;
    }
    bpf_map_delete_elem(&go_hpack_traceparents, &exact);
    return bpf_map_update_elem(&go_hpack_traceparents, &exact, block, BPF_ANY);
}

static __always_inline u8 publish_go_hpack_traceparent(const connection_info_t *conn,
                                                       u32 stream_id,
                                                       const tp_info_t *tp,
                                                       u32 pid,
                                                       const go_addr_key_t *request_key,
                                                       outgoing_trace_token_t *published_token) {
    if (!conn || !tp || !request_key || !published_token) {
        return 0;
    }

    const egress_key_t egress = make_egress_key(conn, pid, stream_id);

    tp_info_pid_t outgoing = {
        .tp = *tp,
        .pid = pid,
        .valid = 1,
        // sk_msg promotes this only after observing or injecting the HPACK field.
        .written = 0,
        .req_type = EVENT_HTTP_CLIENT,
    };
    outgoing_trace_token_t token = {};
    if (!reserve_outgoing_trace_handoff(&egress, &outgoing, &token)) {
        return 0;
    }
    if (!register_go_outgoing_trace_handoff(request_key, &egress, &token)) {
        request_outgoing_trace_handoff_retirement(&egress, &token, &outgoing, 1);
        return 0;
    }

    // Preserve the legacy publication for older consumers, but never let it
    // replace another request. The non-evicting handoff above is authoritative.
    bpf_map_update_elem(&outgoing_trace_map, &egress, &outgoing, BPF_NOEXIST);
    *published_token = token;
    return 1;
}
