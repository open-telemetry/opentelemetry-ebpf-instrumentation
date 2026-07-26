// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/event_defs.h>
#include <common/go_addr_key.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>
#include <gotracer/go_constants.h>
#include <pid/types/pid_info.h>

typedef struct chan_handoff {
    tp_info_t tp;
} chan_handoff_t;

typedef struct chan_func_invocation {
    u64 chan_ptr;
    u64 recvx;
    chan_handoff_t handoff;
    bool has_handoff;
    bool direct_handoff;
    u8 _pad[6];
} chan_func_invocation_t;

typedef struct chan_handoff_key {
    go_addr_key_t chan;
    u64 slot;
} chan_handoff_key_t;

typedef struct direct_chan_handoff {
    chan_handoff_t handoff;
    bool ambiguous;
    u8 _pad[7];
} direct_chan_handoff_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // *m
    __type(value, u32);
    __uint(max_entries, 5000);
} mptr_to_root_tid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);
    __type(value, chan_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} chansend_invocations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);
    __type(value, chan_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} chanrecv_invocations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, chan_handoff_key_t);
    __type(value, chan_handoff_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} buffered_channel_senders SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);
    __type(value, direct_chan_handoff_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} direct_channel_senders SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);
    __type(value, direct_chan_handoff_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} direct_channel_receivers SEC(".maps");

typedef struct go_runtime_metric_target {
    u64 memstats_addr;
    u64 gc_controller_addr;
    u64 gomaxprocs_addr;
    u64 work_addr;
    u64 available_mask;
    u64 size_class_to_sizes_addr;
} go_runtime_metric_target_t;

// Metric group bits shared by go_runtime_metric_target.available_mask and
// go_runtime_metric_snapshot.valid_mask. A snapshot bit is set only when the
// corresponding available metric group was populated successfully.
// Keep in sync with pkg/internal/ebpf/gotracer/gotracer.go and
// pkg/runtimemetrics/reader.go.
typedef enum go_runtime_metric_valid {
    go_runtime_metric_valid_gc_cycles = 1 << 0,
    go_runtime_metric_valid_memory_limit = 1 << 1,
    go_runtime_metric_valid_processor_limit = 1 << 2,
    go_runtime_metric_valid_gogc = 1 << 3,
    go_runtime_metric_valid_cpu_time = 1 << 4,
    go_runtime_metric_valid_memory_used = 1 << 5,
    go_runtime_metric_valid_memory_allocations = 1 << 6,
} go_runtime_metric_valid_t;

typedef struct go_runtime_metric_snapshot {
    // Presence bits for the zero-initialized fields below.
    u64 valid_mask;
    u32 num_gc;
    u32 _pad;
    s32 gomaxprocs;
    s32 gc_percent;
    s64 memory_limit;
    s64 cpu_gc_assist_time;
    s64 cpu_gc_dedicated_time;
    s64 cpu_gc_idle_time;
    s64 cpu_gc_pause_time;
    s64 cpu_scavenge_assist_time;
    s64 cpu_scavenge_bg_time;
    s64 cpu_idle_time;
    s64 cpu_user_time;
    s64 memory_used_stack;
    s64 memory_used_other;
    u64 memory_allocated;
    u64 memory_allocations;
} go_runtime_metric_snapshot_t;

typedef struct go_runtime_metric_event {
    u8 type;
    u8 _pad[3];
    pid_info pid;
    go_runtime_metric_snapshot_t snapshot;
} go_runtime_metric_event_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_info);
    __type(value, go_runtime_metric_target_t);
    __uint(max_entries, MAX_GO_PROGRAMS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_runtime_metric_targets SEC(".maps");
