// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

// https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/hotspot/share/gc/shared/gcWhen.hpp#L32-L37
enum jvm_gc_when_type {
    k_jvm_before_gc = 0,
    k_jvm_after_gc = 1,
    k_jvm_gc_when_end_sentinel = 2,
};

enum { k_jvm_raw_string_len = 64 };

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

struct jvm_runtime_metrics_event {
    u8 type;
    u8 _pad[7];
    u64 timestamp;
    u32 global_pid;
    u32 global_tid;
    u32 ns_pid;
    u32 ns_tid;
    u32 pid_ns_id;
    u32 _pad2;
    u64 loaded_class_count;
    u64 total_loaded_class_count;
    u64 unloaded_class_count;
    u64 thread_count;
    u64 daemon_thread_count;
    u64 available_processor_count;
    u64 process_cpu_time_ns;
    u64 recent_cpu_utilization_bits;
};

enum { k_jvm_runtime_metrics_payload_len = 8 * sizeof(u64) };

_Static_assert(sizeof(struct jvm_runtime_metrics_event) -
                       __builtin_offsetof(struct jvm_runtime_metrics_event, loaded_class_count) ==
                   k_jvm_runtime_metrics_payload_len,
               "JVM runtime metrics payload layout changed");

struct jvm_gc_duration_event {
    u8 type;
    u8 _pad[7];
    u64 timestamp;
    u32 global_pid;
    u32 global_tid;
    u32 ns_pid;
    u32 ns_tid;
    u32 pid_ns_id;
    u32 _pad2;
    u64 duration_ns;
    unsigned char collector_name[k_jvm_raw_string_len];
    unsigned char action[k_jvm_raw_string_len];
};

enum { k_jvm_gc_duration_payload_len = sizeof(u64) + 2 * k_jvm_raw_string_len };

_Static_assert(sizeof(struct jvm_gc_duration_event) -
                       __builtin_offsetof(struct jvm_gc_duration_event, duration_ns) ==
                   k_jvm_gc_duration_payload_len,
               "JVM GC duration payload layout changed");

struct jvm_mem_pool_key {
    u32 pid;
    u32 gc_when_type;
    unsigned char manager[k_jvm_raw_string_len];
    unsigned char pool[k_jvm_raw_string_len];
};

struct jvm_sample_value {
    u64 last_ts;
};
