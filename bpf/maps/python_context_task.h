// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>

typedef struct python_context_task {
    u64 task;    // task that owned this PyContext* when the mapping was written
    u64 version; // task version captured at bind time to reject TaskObj* reuse
} python_context_task_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // PyContext*
    __type(value, python_context_task_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} python_context_task SEC(".maps");
