// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/backup_buffer.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, backup_buffer_t);
    __uint(max_entries, 1);
} backup_buffer_mem SEC(".maps");

static __always_inline backup_buffer_t *backup_buf_memory() {
    const u32 zero = 0;
    return bpf_map_lookup_elem(&backup_buffer_mem, &zero);
}
