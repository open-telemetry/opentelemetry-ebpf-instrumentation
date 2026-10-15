// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>

// Must be a power of two (it masks the index for the verifier).
enum { k_python_outer_tasks_max = 4 };

typedef struct python_thread_state {
    u64 current_task;
    u64 current_context;
    u64 inflight_task;
    u64 start_monotime_ns;
    // Tasks whose step is still running under a nested step on this thread (an eager task
    // starting inside its parent), innermost last. Restored when the nested step returns.
    u64 outer_tasks[k_python_outer_tasks_max];
    u8 outer_depth;
    u8 outer_overflow;
    u8 _pad[6];
} python_thread_state_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // pid:tgid
    __type(value, python_thread_state_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} python_thread_state SEC(".maps");
