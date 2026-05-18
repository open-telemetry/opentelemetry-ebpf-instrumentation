// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>

typedef struct pid_trace_id_key {
    u32 pid;                          // namespace PID (group leader)
    u32 ns;                           // PID namespace inode
    u8 trace_id[TRACE_ID_SIZE_BYTES]; // 16 bytes
} pid_trace_id_key_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_trace_id_key_t);
    __type(value, tp_info_pid_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} server_traces_by_trace_id SEC(".maps");
