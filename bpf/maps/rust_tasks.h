// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>

enum { k_rust_poll_depth = 8 };

typedef struct rust_task_key {
    u64 addr;
    u32 pid;
    u32 _pad;
} rust_task_key_t;

typedef struct rust_thread_state {
    u64 tasks[k_rust_poll_depth];
    u32 depth;
    u32 spawn_depth;
} rust_thread_state_t;

typedef struct rust_capabilities {
    u8 task_context;
    u8 client_context;
    u8 tokio_runtime;
} rust_capabilities_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, rust_capabilities_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_capabilities SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, rust_thread_state_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_threads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, rust_task_key_t);
    __type(value, tp_info_pid_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_task_context SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, rust_task_key_t);
    __type(value, tp_info_pid_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_channel_context SEC(".maps");
