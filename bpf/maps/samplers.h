// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>
#include <common/process_incarnation.h>

#include <pid/maps/map_sizing.h>

enum sampler_type : u8 {
    k_sampler_invalid = 0,
    k_sampler_always_on = 1,
    k_sampler_always_off = 2,
    k_sampler_trace_id_ratio = 3,
    k_sampler_parent_based = 4,
};

typedef struct sampler_delegate {
    u64 trace_id_upper_bound;
    u8 type;
    u8 _pad[7];
} sampler_delegate_t;

typedef struct sampler_config {
    u64 trace_id_upper_bound;
    sampler_delegate_t root;
    sampler_delegate_t remote_parent_sampled;
    sampler_delegate_t remote_parent_not_sampled;
    sampler_delegate_t local_parent_sampled;
    sampler_delegate_t local_parent_not_sampled;
    u32 publication_epoch;
    u8 type;
    u8 _pad[3];
} sampler_config_t;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, sampler_config_t);
    __uint(max_entries, 1);
    __uint(pinning, OBI_PIN_INTERNAL);
} global_sampler_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, sampler_config_t);
    __uint(max_entries, k_max_concurrent_pids);
    __uint(pinning, OBI_PIN_INTERNAL);
} sampler_overrides SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, process_readiness_t);
    __uint(max_entries, k_max_concurrent_pids);
    __uint(pinning, OBI_PIN_INTERNAL);
} sampler_ready_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, process_readiness_t);
    __uint(max_entries, k_max_concurrent_pids);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_auto_sdk_ready SEC(".maps");
