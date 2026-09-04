// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/python_addr_key.h>

typedef struct python_task_state {
    python_task_ref_t parent;
    u64 generation; // changes when a reused TaskObj* address represents a new task instance
    connection_info_part_t conn;
} python_task_state_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, python_addr_key_t); // host PID + TaskObj*
    __type(value, python_task_state_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} python_task_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
    __uint(pinning, OBI_PIN_INTERNAL);
} python_task_generation SEC(".maps");
