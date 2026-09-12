// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/python_addr_key.h>

typedef struct python_context_task {
    python_task_ref_t task; // task that owned this PyContext* when the mapping was written
    u64 vars;               // ctx_vars at bind time, to reject recycled PyContext* addresses
} python_context_task_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, python_addr_key_t); // host PID + PyContext*
    __type(value, python_context_task_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} python_context_task SEC(".maps");
