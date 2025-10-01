// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

#include <pid/types/pid_info.h>

typedef struct conn_pid {
    pid_info p_info;
    pid_key_t p_key;
    u64 id;
    u64 ts;
} conn_pid_t;

// A map of sockets which we track to supply pid information
// to anything handled by the sock_filter
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(key_size, sizeof(connection_info_t));
    __uint(value_size, sizeof(conn_pid_t));
    __uint(pinning, OBI_PIN_INTERNAL);
} sock_pids SEC(".maps");
