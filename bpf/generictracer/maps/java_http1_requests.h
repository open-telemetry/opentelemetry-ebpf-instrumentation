// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

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

// Save the client span chosen before TLS encryption until the HTTP parser sees
// the matching plaintext. Cleanup may race with that parser or socket closure.
typedef struct java_http1_request {
    tp_info_pid_t tp;
    // Zero while available; atomically changed once before removing the entry.
    u64 retired;
    u32 value_offset;
    u8 parent_status;
    u8 _pad[3];
} java_http1_request_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    // Keep deleted values immutable until RCU readers finish; preallocated hash
    // nodes can be recycled while a delayed cleanup still holds their address.
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, pid_connection_info_t);
    __type(value, java_http1_request_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_http1_requests SEC(".maps");

static __always_inline bool java_http1_request_retire(const pid_connection_info_t *conn,
                                                      java_http1_request_t *request) {
    if (!g_bpf_java_http1_enabled || !request) {
        return false;
    }

    enum { k_available = 0, k_retired = 1 };
    const u64 previous_state =
        __sync_val_compare_and_swap(&request->retired, k_available, k_retired);
    if (previous_state != k_available) {
        return false;
    }
    // Only the retirement winner deletes. BPF_NOEXIST prevents a replacement
    // from being installed before this deletion; stale readers cannot win again.
    bpf_map_delete_elem(&java_http1_requests, conn);
    return true;
}
