// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <generictracer/types/puma_task_id.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, puma_task_id_t); // the array and item pair
    __type(value, connection_info_part_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} puma_task_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);              // the pid:tgid
    __type(value, puma_task_id_t); // the array and item pair
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} puma_worker_tasks SEC(".maps");
