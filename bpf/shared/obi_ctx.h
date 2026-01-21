// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_builtins.h>

#include <common/tp_info.h>

typedef struct obi_ctx_info {
    unsigned char trace_id[16];
    unsigned char span_id[8];
} obi_ctx_info_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, obi_ctx_info_t);
    __uint(max_entries, 1 << 14);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} obi_ctx SEC(".maps");

static __always_inline obi_ctx_info_t *obi_ctx__get(const u64 pid_tgid) {
    return bpf_map_lookup_elem(&obi_ctx, &pid_tgid);
}

static __always_inline long obi_ctx__set(const u64 pid_tgid, const tp_info_t *info) {
    obi_ctx_info_t obi_info = {};
    bpf_memcpy(obi_info.trace_id, info->trace_id, 16);
    bpf_memcpy(obi_info.span_id, info->span_id, 8);
    return bpf_map_update_elem(&obi_ctx, &pid_tgid, &obi_info, BPF_ANY);
}

static __always_inline long obi_ctx__del(const u64 pid_tgid) {
    return bpf_map_delete_elem(&obi_ctx, &pid_tgid);
}
