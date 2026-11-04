// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_builtins.h>

#include <common/connection_info.h>
#include <common/globals.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>

typedef struct java_http1_parent {
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
    u8 flags;
    u8 parent_status;
} java_http1_parent_t;

_Static_assert(sizeof(java_http1_parent_t) == TRACE_ID_SIZE_BYTES + SPAN_ID_SIZE_BYTES + 2,
               "Java HTTP/1 parent context is a packed wire format");

typedef struct java_http1_request_data {
    pid_connection_info_t conn;
    tp_info_pid_t tp;
    u32 value_offset;
    u8 parent_status;
    u8 _pad[3];
} java_http1_request_data_t;

// Array slots have stable addresses. The state is zero when free, a unique
// request ID while readable, or that ID with the top bit set while owned.
// A retired request ID is never published again, even when its slot is reused.
typedef struct java_http1_request {
    u64 state;
    java_http1_request_data_t data;
} java_http1_request_t;

enum { k_java_http1_owned_bit = 63, k_java_http1_reserve_attempts = 16 };
const volatile u32 java_http1_max_requests = MAX_CONCURRENT_REQUESTS;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, java_http1_request_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_http1_requests SEC(".maps");

// The index contains only a request ID, never a pointer to recyclable hash data.
// Insert-only ownership keeps a connection occupied until its slot owner deletes
// the index. A stale cleanup must first claim its original array generation.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, pid_connection_info_t);
    __type(value, u64);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_http1_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_http1_sequence SEC(".maps");

static __always_inline u64 java_http1_next_id(void) {
    const u32 zero = 0;
    u64 *sequence = bpf_map_lookup_elem(&java_http1_sequence, &zero);
    if (!sequence) {
        return 0;
    }
    // Bounded contention skips injection. Saturation never wraps to a live ID.
    for (u8 attempt = 0; attempt < k_java_http1_reserve_attempts; ++attempt) {
        const u64 previous = *(volatile u64 *)sequence;
        if (previous >= (1ULL << k_java_http1_owned_bit) - 1) {
            return 0;
        }
        if (__sync_val_compare_and_swap(sequence, previous, previous + 1) == previous) {
            return previous + 1;
        }
    }
    return 0;
}

static __always_inline u64 java_http1_request_reserve(const java_http1_request_data_t *data) {
    if (!g_bpf_java_http1_enabled || !java_http1_max_requests) {
        return 0;
    }
    for (u8 attempt = 0; attempt < k_java_http1_reserve_attempts; ++attempt) {
        const u64 id = java_http1_next_id();
        if (!id) {
            return 0;
        }
        const u32 index = id % java_http1_max_requests;
        java_http1_request_t *slot = bpf_map_lookup_elem(&java_http1_requests, &index);
        const u64 owned = id | (1ULL << k_java_http1_owned_bit);
        if (!slot || __sync_val_compare_and_swap(&slot->state, 0, owned) != 0) {
            continue;
        }
        slot->data = *data;
        if (bpf_map_update_elem(&java_http1_connections, &data->conn, &id, BPF_NOEXIST) != 0) {
            __sync_val_compare_and_swap(&slot->state, owned, 0);
            return 0;
        }
        // Publish complete immutable data before acknowledging the reservation.
        __sync_val_compare_and_swap(&slot->state, owned, id);
        return id;
    }
    return 0;
}

static __always_inline java_http1_request_t *
java_http1_request_lookup(const pid_connection_info_t *conn, u64 id) {
    if (!id || id >= (1ULL << k_java_http1_owned_bit) || !java_http1_max_requests) {
        return NULL;
    }
    const u32 index = id % java_http1_max_requests;
    java_http1_request_t *slot = bpf_map_lookup_elem(&java_http1_requests, &index);
    // This atomic read orders the following data reads after slot publication.
    if (!slot || __sync_val_compare_and_swap(&slot->state, id, id) != id ||
        bpf_memcmp(&slot->data.conn, conn, sizeof(*conn)) != 0) {
        return NULL;
    }
    return slot;
}

static __always_inline u64 java_http1_request_id(const pid_connection_info_t *conn) {
    const u64 *id = bpf_map_lookup_elem(&java_http1_connections, conn);
    return id ? *id : 0;
}

static __always_inline bool
java_http1_request_retire(const pid_connection_info_t *conn, java_http1_request_t *slot, u64 id) {
    if (!g_bpf_java_http1_enabled || !slot || !id) {
        return false;
    }
    const u64 owned = id | (1ULL << k_java_http1_owned_bit);
    if (__sync_val_compare_and_swap(&slot->state, id, owned) != id) {
        return false;
    }
    // Only this generation's winner can delete the connection index. New
    // reservations cannot install the same key until that deletion completes.
    bpf_map_delete_elem(&java_http1_connections, conn);
    __sync_val_compare_and_swap(&slot->state, owned, 0);
    return true;
}
