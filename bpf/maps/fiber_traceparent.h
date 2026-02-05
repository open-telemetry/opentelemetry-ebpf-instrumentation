// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // fiber_id
    __type(value, tp_info_pid_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} fiber_traceparent SEC(".maps");
