// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

typedef struct go_addr_key {
    u64 pid;  // PID of the process
    u64 addr; // Address of the goroutine
} go_addr_key_t;

// Reusable Go pointers and stream IDs are process-local. Any staging bridge
// that outlives one probe invocation must include both host PID and the exact
// kernel process start time so simultaneous processes and PID reuse cannot
// alias.
typedef struct go_exact_process_addr_key {
    go_addr_key_t address;
    u64 process_start_time;
} go_exact_process_addr_key_t;

typedef struct go_exact_process_stream_key {
    u64 conn_ptr;
    u64 process_start_time;
    u32 pid;
    u32 stream_id;
} go_exact_process_stream_key_t;

static inline go_exact_process_addr_key_t
go_exact_process_addr_key(u32 pid, u64 process_start_time, u64 addr) {
    return (go_exact_process_addr_key_t){
        .address = {.pid = pid, .addr = addr},
        .process_start_time = process_start_time,
    };
}

static inline go_exact_process_stream_key_t
go_exact_process_stream_key(u32 pid, u64 process_start_time, u64 conn_ptr, u32 stream_id) {
    return (go_exact_process_stream_key_t){
        .conn_ptr = conn_ptr,
        .process_start_time = process_start_time,
        .pid = pid,
        .stream_id = stream_id,
    };
}
