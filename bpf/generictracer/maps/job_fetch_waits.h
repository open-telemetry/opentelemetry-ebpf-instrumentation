// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

#include <generictracer/redis_job_fetch.h>

typedef struct job_fetch_wait {
    pid_connection_info_t conn;
    enum redis_job_fetch fetch;
    u8 _pad[3];
} job_fetch_wait_t;

// threads blocked on a job fetch, until they touch another connection
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // key: pid_tgid of the thread
    __type(value, job_fetch_wait_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} job_fetch_waits SEC(".maps");
