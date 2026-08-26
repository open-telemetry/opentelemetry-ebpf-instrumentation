// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_builtins.h>

#include <common/go_addr_key.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/scratch_mem.h>
#include <common/tp_info.h>

#include <shared/obi_ctx.h>

// Per-goroutine stack of ongoing trace contexts; the top frame owns the logs

enum obi_ctx_kind : u8 {
    k_obi_ctx_http_server = 1,
    k_obi_ctx_grpc_server = 2,
    k_obi_ctx_grpc_client = 3,
    k_obi_ctx_sql = 4,
    k_obi_ctx_redis = 5,
    k_obi_ctx_mongo = 6,
    k_obi_ctx_kafka_produce = 7,
    k_obi_ctx_kind_count = 7,
};

// one frame per kind, so this bounds the stack depth: it can never overflow
enum { k_obi_ctx_max_depth = 8 };

_Static_assert(k_obi_ctx_max_depth >= k_obi_ctx_kind_count,
               "the frame stack must fit one frame per kind");

typedef struct obi_ctx_frame {
    tp_info_t tp;
    u8 kind;
    u8 _pad[7];
} obi_ctx_frame_t;

typedef struct obi_ctx_stack {
    obi_ctx_frame_t frames[k_obi_ctx_max_depth];
    u32 depth;
    u32 _pad;
} obi_ctx_stack_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);
    __type(value, obi_ctx_stack_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} obi_ctx_stacks SEC(".maps");

SCRATCH_MEM_TYPED(obi_ctx_stack_scratch, obi_ctx_stack_t)

static __always_inline u32 obi_ctx__stack_top(const obi_ctx_stack_t *st) {
    return (st->depth - 1) & (k_obi_ctx_max_depth - 1);
}

static __always_inline u8 obi_ctx__same_span(const tp_info_t *a, const tp_info_t *b) {
    return *(const u64 *)a->span_id == *(const u64 *)b->span_id;
}

// Makes the invocation's context the goroutine's current one. At most one
// frame per kind: a same-kind begin replaces that frame, since entry probes
// can fire more than once per invocation
static __always_inline void
go_obi_ctx__begin(const go_addr_key_t *g_key, u8 kind, const tp_info_t *tp) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();

    obi_ctx_stack_t *st = bpf_map_lookup_elem(&obi_ctx_stacks, g_key);
    if (!st) {
        obi_ctx_stack_t *fresh = obi_ctx_stack_scratch_mem();
        if (!fresh) {
            return;
        }
        bpf_memset(fresh, 0, sizeof(*fresh));
        fresh->frames[0].tp = *tp;
        fresh->frames[0].kind = kind;
        fresh->depth = 1;
        bpf_map_update_elem(&obi_ctx_stacks, g_key, fresh, BPF_ANY);
        obi_ctx__set(pid_tgid, tp);
        return;
    }

    const u32 depth = st->depth < k_obi_ctx_max_depth ? st->depth : k_obi_ctx_max_depth;
    for (u32 i = 0; i < k_obi_ctx_max_depth; i++) {
        if (i >= depth) {
            break;
        }
        const u32 idx = (depth - 1 - i) & (k_obi_ctx_max_depth - 1);
        if (st->frames[idx].kind == kind) {
            st->frames[idx].tp = *tp;
            if (i == 0) {
                obi_ctx__set(pid_tgid, tp);
            }
            return;
        }
    }

    // one frame per kind: the stack holds every kind, so this cannot overflow
    const u32 slot = st->depth & (k_obi_ctx_max_depth - 1);
    st->frames[slot].tp = *tp;
    st->frames[slot].kind = kind;
    st->depth++;
    obi_ctx__set(pid_tgid, tp);
}

// Pops the ended span (NULL or unknown tp: newest of kind), restores the enclosing frame
static __always_inline void
go_obi_ctx__end(const go_addr_key_t *g_key, u8 kind, const tp_info_t *tp) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();

    obi_ctx_stack_t *st = bpf_map_lookup_elem(&obi_ctx_stacks, g_key);
    if (!st) {
        obi_ctx__del(pid_tgid);
        return;
    }

    const u32 depth = st->depth < k_obi_ctx_max_depth ? st->depth : k_obi_ctx_max_depth;
    u32 remove = k_obi_ctx_max_depth;

    for (u32 i = 0; i < k_obi_ctx_max_depth; i++) {
        if (i >= depth) {
            break;
        }
        const u32 idx = (depth - 1 - i) & (k_obi_ctx_max_depth - 1);
        if (tp ? obi_ctx__same_span(&st->frames[idx].tp, tp) : st->frames[idx].kind == kind) {
            remove = idx;
            break;
        }
    }

    if (tp && remove == k_obi_ctx_max_depth) {
        for (u32 i = 0; i < k_obi_ctx_max_depth; i++) {
            if (i >= depth) {
                break;
            }
            const u32 idx = (depth - 1 - i) & (k_obi_ctx_max_depth - 1);
            if (st->frames[idx].kind == kind) {
                remove = idx;
                break;
            }
        }
    }

    if (remove < k_obi_ctx_max_depth) {
        for (u32 i = 0; i < k_obi_ctx_max_depth - 1; i++) {
            if (i >= remove) {
                st->frames[i] = st->frames[i + 1];
            }
        }
        st->depth = depth - 1;
    }

    if (st->depth == 0 || st->depth > k_obi_ctx_max_depth) {
        bpf_map_delete_elem(&obi_ctx_stacks, g_key);
        obi_ctx__del(pid_tgid);
        return;
    }

    obi_ctx__set(pid_tgid, &st->frames[obi_ctx__stack_top(st)].tp);
}

// Installs the goroutine's context on this thread; clears leftovers
static __always_inline void go_obi_ctx__resume(u64 pid_tgid, const go_addr_key_t *g_key) {
    const obi_ctx_stack_t *st = bpf_map_lookup_elem(&obi_ctx_stacks, g_key);
    if (st && st->depth > 0) {
        obi_ctx__set(pid_tgid, &st->frames[obi_ctx__stack_top(st)].tp);
        return;
    }
    obi_ctx__del(pid_tgid);
}
