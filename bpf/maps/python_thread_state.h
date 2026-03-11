// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>

typedef struct python_thread_state {
    u64 current_task;
    u64 current_context;
    u64 inflight_task;
} python_thread_state_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // pid:tgid
    __type(value, python_thread_state_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
} python_thread_state SEC(".maps");
