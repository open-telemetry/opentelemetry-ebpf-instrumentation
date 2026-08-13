// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>

#include <common/go_h2_stream_state.h>
#include <common/globals.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/scratch_mem.h>

SCRATCH_MEM_TYPED(go_h2_audit_key, go_h2_audit_key_t);
SCRATCH_MEM_TYPED(go_h2_audit_value, go_h2_audit_value_t);

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_h2_stream_key_t);
    __type(value, go_h2_stream_value_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_h2_stream_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_h2_conn_key_t);
    __type(value, go_h2_conn_value_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_h2_client_conns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_h2_audit_key_t);
    __type(value, go_h2_audit_value_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_h2_audit SEC(".maps");

static __always_inline void set_go_h2_process_identity(u32 *start_lo, u32 *start_hi) {
    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    const u64 start_time = BPF_CORE_READ(task, group_leader, start_time);
    *start_lo = (u32)start_time;
    *start_hi = (u32)(start_time >> 32);
}

static __always_inline void set_go_h2_stream_process_identity(go_h2_stream_key_t *key) {
    set_go_h2_process_identity(&key->process_start_lo, &key->process_start_hi);
}

static __always_inline const go_h2_conn_key_t *
go_h2_stream_conn_key(const go_h2_stream_key_t *stream) {
    return (const go_h2_conn_key_t *)stream;
}

static __always_inline void
mark_go_h2_client_conn(const go_h2_conn_key_t *key, u8 protocol, u64 now) {
    const go_h2_conn_value_t value = {
        .updated_ns = now,
        .protocol = protocol,
    };
    bpf_map_update_elem(&go_h2_client_conns, key, &value, BPF_ANY);
}

static __always_inline go_h2_conn_value_t *fresh_go_h2_client_conn(const go_h2_conn_key_t *key,
                                                                   u64 now) {
    go_h2_conn_value_t *value = bpf_map_lookup_elem(&go_h2_client_conns, key);
    if (!value) {
        return 0;
    }
    if (!go_h2_timestamp_is_fresh(value->updated_ns, now)) {
        bpf_map_delete_elem(&go_h2_client_conns, key);
        return 0;
    }
    return value;
}

static __always_inline go_h2_stream_value_t *fresh_go_h2_stream_state(const go_h2_stream_key_t *key,
                                                                      u64 now) {
    go_h2_stream_value_t *value = bpf_map_lookup_elem(&go_h2_stream_states, key);
    if (!value) {
        return 0;
    }
    if (!go_h2_timestamp_is_fresh(value->updated_ns, now)) {
        bpf_map_delete_elem(&go_h2_stream_states, key);
        return 0;
    }
    return value;
}

static __always_inline bool publish_go_h2_stream_state(const go_h2_stream_key_t *key,
                                                       const go_h2_stream_value_t *value) {
    return bpf_map_update_elem(&go_h2_stream_states, key, value, BPF_ANY) == 0;
}

static __always_inline void audit_go_h2_stream(
    const go_h2_stream_key_t *stream, u8 protocol, u8 event, u8 state, const tp_info_t *tp) {
    if (!g_go_h2_audit) {
        return;
    }

    go_h2_audit_key_t *key = go_h2_audit_key_mem();
    go_h2_audit_value_t *value = go_h2_audit_value_mem();
    if (!key || !value) {
        return;
    }
    __builtin_memset(key, 0, sizeof(*key));
    key->stream = *stream;
    key->protocol = protocol;
    key->event = event;
    go_h2_audit_value_t *existing = bpf_map_lookup_elem(&go_h2_audit, key);
    if (existing) {
        existing->updated_ns = bpf_ktime_get_ns();
        existing->state = state;
        existing->count++;
        if (tp) {
            __builtin_memcpy(existing->trace_id, tp->trace_id, sizeof(existing->trace_id));
        }
        return;
    }

    __builtin_memset(value, 0, sizeof(*value));
    value->updated_ns = bpf_ktime_get_ns();
    value->count = 1;
    value->state = state;
    if (tp) {
        __builtin_memcpy(value->trace_id, tp->trace_id, sizeof(value->trace_id));
    }
    bpf_map_update_elem(&go_h2_audit, key, value, BPF_ANY);
}
