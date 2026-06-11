// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

// https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/hotspot/share/gc/shared/gcWhen.hpp#L32-L37
enum jvm_gc_when_type {
    k_jvm_before_gc = 0,
    k_jvm_after_gc = 1,
    k_jvm_gc_when_end_sentinel = 2,
};

enum { k_jvm_raw_string_len = 64 };

struct jvm_gc_heap_summary_event {
    u8 type;
    u8 _pad[7];
    u64 timestamp;
    u32 global_pid;
    u32 global_tid;
    u32 ns_pid;
    u32 ns_tid;
    u32 pid_ns_id;
    u32 gc_when_type;
    u64 used;
};

struct jvm_mem_pool_gc_event {
    u8 type;
    u8 _pad[7];
    u64 timestamp;
    u32 global_pid;
    u32 global_tid;
    u32 ns_pid;
    u32 ns_tid;
    u32 pid_ns_id;
    u32 gc_when_type;
    u64 init_size;
    u64 used;
    u64 committed;
    u64 max_size;
    unsigned char manager[k_jvm_raw_string_len];
    unsigned char pool[k_jvm_raw_string_len];
};

struct jvm_heap_summary_key {
    u32 pid;
    u32 gc_when_type;
};

struct jvm_mem_pool_key {
    u32 pid;
    u32 gc_when_type;
    unsigned char manager[k_jvm_raw_string_len];
    unsigned char pool[k_jvm_raw_string_len];
};

struct jvm_sample_value {
    u64 last_ts;
};

#include <generictracer/maps/jvm_heap_summary_samples.h>
#include <generictracer/maps/jvm_mem_pool_samples.h>

// Use https://godbolt.org/z/YcodaPhvY to understand the memory layout of `GCHeapSummary` C++ class
// https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/hotspot/share/gc/shared/gcHeapSummary.hpp#L76
struct jvm_gc_heap_summary {
    u64 _s1;
    u64 _s2;
    u64 _s4;
    u64 _s5;
    u64 used;
};

volatile const u8 jvm_runtime_metrics_enabled = 0;
volatile const u64 jvm_sampling_interval_ns = 0;

static __always_inline bool jvm_should_report(u64 ts, u64 reference_ts) {
    if (jvm_sampling_interval_ns == 0) {
        return true;
    }

    return ts - reference_ts >= jvm_sampling_interval_ns;
}

static __always_inline bool jvm_should_sample_heap_summary(struct jvm_heap_summary_key *key,
                                                           u64 ts) {
    struct jvm_sample_value new_value = {.last_ts = ts};
    struct jvm_sample_value *value = bpf_map_lookup_elem(&jvm_heap_summary_samples, key);

    if (value && !jvm_should_report(ts, value->last_ts)) {
        return false;
    }

    bpf_map_update_elem(&jvm_heap_summary_samples, key, &new_value, BPF_ANY);
    return true;
}

static __always_inline bool jvm_should_sample_mem_pool(struct jvm_mem_pool_key *key, u64 ts) {
    struct jvm_sample_value new_value = {.last_ts = ts};
    struct jvm_sample_value *value = bpf_map_lookup_elem(&jvm_mem_pool_samples, key);

    if (value && !jvm_should_report(ts, value->last_ts)) {
        return false;
    }

    bpf_map_update_elem(&jvm_mem_pool_samples, key, &new_value, BPF_ANY);
    return true;
}
