// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

// Event loop metrics reported by the injected nodejs agent (fdextractor.js)
// through the uv_fs_access side channel. Field semantics:
//   - elu_* are cumulative nanoseconds since loop start
//     (performance.eventLoopUtilization()).
//   - delay_* are per-sampling-interval nanoseconds from
//     monitorEventLoopDelay(); the JS agent resets the histogram after each
//     read. delay_count == 0 means no delay samples were recorded (loop
//     blocked for the whole interval, or a pre-16.14 runtime without
//     Histogram.count); the delay fields are then zero.
//
// Mirrored in Go by nodejsEventLoopRawEvent (pkg/ebpf/common/nodejs.go);
// keep the layouts in sync.
struct nodejs_eventloop_event {
    u8 type;
    u8 _pad[7];
    u64 timestamp;
    u32 global_pid;
    u32 global_tid;
    u32 ns_pid;
    u32 ns_tid;
    u32 pid_ns_id;
    u32 _pad2;
    u64 elu_idle_ns;
    u64 elu_active_ns;
    u64 delay_min_ns;
    u64 delay_max_ns;
    u64 delay_mean_ns;
    u64 delay_stddev_ns;
    u64 delay_p50_ns;
    u64 delay_p90_ns;
    u64 delay_p99_ns;
    u64 delay_count;
};

// One garbage-collection cycle reported by the injected agent. kind carries
// the OBI wire code assigned in fdextractor.js (1=minor, 2=major,
// 3=incremental, 4=weakcb) — deliberately NOT the Node constant values,
// which differ across Node versions.
// Mirrored in Go by nodejsGCRawEvent (pkg/ebpf/common/nodejs.go).
struct nodejs_gc_event {
    u8 type;
    u8 kind;
    u8 _pad[6];
    u64 timestamp;
    u32 global_pid;
    u32 global_tid;
    u32 ns_pid;
    u32 ns_tid;
    u32 pid_ns_id;
    u32 _pad2;
    u64 duration_ns;
};

enum {
    k_nodejs_heap_space_name_max = 32,
};

// One V8 heap space sampled by the injected agent (one event per space per
// sampling interval). The space name is engine-defined and version-dependent,
// so it travels verbatim (name_len bytes, not NUL-terminated).
// Mirrored in Go by nodejsHeapSpaceRawEvent (pkg/ebpf/common/nodejs.go).
struct nodejs_heap_space_event {
    u8 type;
    u8 name_len;
    u8 _pad[6];
    u64 timestamp;
    u32 global_pid;
    u32 global_tid;
    u32 ns_pid;
    u32 ns_tid;
    u32 pid_ns_id;
    u32 _pad2;
    u64 space_size;
    u64 space_used_size;
    u64 space_available_size;
    u64 physical_space_size;
    unsigned char space_name[k_nodejs_heap_space_name_max];
};

enum {
    // names are MemoryInfoName() of Node's handle/request wrap classes; the
    // longest today (node source, src/*wrap*) is 19 (TraceSigintWatchdog)
    k_nodejs_resource_type_max = 32,
};

// One active-resource census entry reported by the injected agent (one event
// per resource type per sampling interval; count 0 marks a type that
// vanished since the previous interval). The type name is the Node-defined
// resource class name, passed through verbatim (name_len bytes, not
// NUL-terminated).
// Mirrored in Go by nodejsResourceRawEvent (pkg/ebpf/common/nodejs.go).
struct nodejs_resource_event {
    u8 type;
    u8 name_len;
    u8 _pad[6];
    u64 timestamp;
    u32 global_pid;
    u32 global_tid;
    u32 ns_pid;
    u32 ns_tid;
    u32 pid_ns_id;
    u32 _pad2;
    u64 count;
    unsigned char resource_type[k_nodejs_resource_type_max];
};
