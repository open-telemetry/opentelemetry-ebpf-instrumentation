// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <generictracer/types/jvm.h>

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

volatile const u64 jvm_sampling_interval_ns = 0;

static __always_inline bool jvm_runtime_metrics_are_enabled(void) {
    return jvm_sampling_interval_ns > 0;
}

static __always_inline bool jvm_should_report(u64 ts, u64 reference_ts) {
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
