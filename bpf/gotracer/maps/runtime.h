// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // *m
    __type(value, u32);
    __uint(max_entries, 5000);
} mptr_to_root_tid SEC(".maps");
