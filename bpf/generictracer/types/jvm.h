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

struct jvm_mem_pool_key {
    u32 pid;
    u32 gc_when_type;
    unsigned char manager[k_jvm_raw_string_len];
    unsigned char pool[k_jvm_raw_string_len];
};

struct jvm_sample_value {
    u64 last_ts;
};
