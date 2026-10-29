// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);   // tid | fd
    __type(value, s32); // fd
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} nodejs_fd_map SEC(".maps");
