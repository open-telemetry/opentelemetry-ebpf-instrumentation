// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#define TRACE_ID_SIZE_BYTES 16
#define SPAN_ID_SIZE_BYTES 8

// Values from https://www.w3.org/TR/trace-context/
enum tp_flags : u8 {
    k_flag_sampled = 1,
    k_flag_random = 2,
    k_flag_mask = k_flag_sampled | k_flag_random,
};

typedef struct tp_info {
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
    unsigned char parent_id[SPAN_ID_SIZE_BYTES];
    u64 ts;
    u8 flags;
    u8 sampling_decision;
    u8 parent_remote;
    u8 _pad[5];
} tp_info_t;

typedef struct tp_info_pid {
    tp_info_t tp;
    u32 pid;
    u8 valid;
    u8 written;
    u8 req_type;
    u8 response_sent;
} tp_info_pid_t;

typedef struct outgoing_trace_token {
    // Epoch of the pinned authority/counter map lifetime.
    u64 map_epoch;
    // Monotonic sequence within one CPU's guarded per-CPU counter.
    u64 sequence;
    // Full kernel process start time. Host PIDs and connection tuples can both
    // be reused, so a sequence alone must not make an old process's
    // reservation adoptable by a new incarnation.
    u64 process_start_time;
    u32 cpu;
    u32 _pad;
} outgoing_trace_token_t;
