// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>

#include <pid/types/pid_key.h>

// set when a service opts into job traces; otherwise the job code compiles away
volatile const bool g_job_traces_enabled = false;

typedef struct job_context {
    tp_info_pid_t tp; // the fetch that took the job, the root of its trace; must be first
    pid_key_t owner;  // the thread that took the job
    u8 inherited;     // started while the owner ran the job, rather than taking it
    u8 ended;         // sent its next fetch; kept for the threads it started during this job
    u8 _pad[2];
} job_context_t;

// threads running a job they took off a queue or were started for, until their next fetch
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_key_t); // key: the thread
    __type(value, job_context_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} job_contexts SEC(".maps");
