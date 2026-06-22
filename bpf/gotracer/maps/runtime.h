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

typedef struct chan_func_invocation {
    u64 chan_ptr;
} chan_func_invocation_t;

typedef struct chan_handoff {
    tp_info_t tp;
} chan_handoff_t;

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
} go_runtime_metric_target_t;

typedef struct go_runtime_metric_snapshot {
    u32 num_gc;
    u32 num_forced_gc;
    s32 gomaxprocs;
    s32 gc_percent;
    s64 memory_limit;
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
