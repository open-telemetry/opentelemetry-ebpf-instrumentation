// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_builtins.h>

#include <common/tp_info.h>
#include <common/trace_helpers.h>

typedef struct obi_ctx_info {
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
} obi_ctx_info_t;

// NOTE: this map spec is part of an OTEP (https://github.com/open-telemetry/opentelemetry-specification/pull/4855).
// Changing its spec may break other components relying on it.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, obi_ctx_info_t);
    __uint(max_entries, 1 << 14);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} traces_ctx_v1 SEC(".maps");

static __always_inline obi_ctx_info_t *obi_ctx__get(const u64 pid_tgid) {
    return bpf_map_lookup_elem(&traces_ctx_v1, &pid_tgid);
}

static __always_inline long obi_ctx__set(const u64 pid_tgid, const tp_info_t *info) {
    obi_ctx_info_t obi_info = {};
    bpf_memcpy(obi_info.trace_id, info->trace_id, TRACE_ID_SIZE_BYTES);
    bpf_memcpy(obi_info.span_id, info->span_id, SPAN_ID_SIZE_BYTES);
    return bpf_map_update_elem(&traces_ctx_v1, &pid_tgid, &obi_info, BPF_ANY);
}

static __always_inline long
obi_ctx__set_(const u64 pid_tgid, const tp_info_t *info, obi_ctx_info_t *obi_info) {
    bpf_memcpy(obi_info->trace_id, info->trace_id, TRACE_ID_SIZE_BYTES);
    bpf_memcpy(obi_info->span_id, info->span_id, SPAN_ID_SIZE_BYTES);
    return bpf_map_update_elem(&traces_ctx_v1, &pid_tgid, obi_info, BPF_ANY);
}

static __always_inline long obi_ctx__del(const u64 pid_tgid) {
    return bpf_map_delete_elem(&traces_ctx_v1, &pid_tgid);
}

// Restores traces_ctx_v1 to the enclosing span's identity encoded in a
// finished child span's own tp (ip): same trace_id, and parent_id holds the
// enclosing span's span_id. Deletes the context when there was no enclosing
// span, so the finished child span can't leak into later work on this thread.
static __always_inline void obi_ctx__restore(const u64 pid_tgid, const tp_info_t *ip) {
    tp_info_t parent_tp = {0};
    bpf_memcpy(parent_tp.trace_id, ip->trace_id, TRACE_ID_SIZE_BYTES);
    bpf_memcpy(parent_tp.span_id, ip->parent_id, SPAN_ID_SIZE_BYTES);
    if (valid_span(parent_tp.span_id)) {
        obi_ctx__set(pid_tgid, &parent_tp);
    } else {
        obi_ctx__del(pid_tgid);
    }
}
