// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/tp_info.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, tp_info_t);
    __uint(max_entries, 1 << 14);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} obi_ctx SEC(".maps");

static __always_inline tp_info_t *obi_ctx__get(const u64 pid_tgid) {
    return bpf_map_lookup_elem(&obi_ctx, &pid_tgid);
}

static __always_inline long obi_ctx__set(const u64 pid_tgid, const tp_info_t *info) {
    return bpf_map_update_elem(&obi_ctx, &pid_tgid, info, BPF_ANY);
}
