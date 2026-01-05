// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "pid/types/pid_key.h"
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <generictracer/types/puma_task_id.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_key_t);   // the client thread
    __type(value, pid_key_t); // the server thread
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} java_tasks SEC(".maps");
