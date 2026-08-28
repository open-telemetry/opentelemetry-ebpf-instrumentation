// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/utils.h>

#include <common/go_addr_key.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/scratch_mem.h>
#include <common/tp_info.h>

#include <shared/obi_ctx.h>

// One stack per goroutine with the spans that are still running. Logs get the top span

enum obi_ctx_kind : u8 {
    k_obi_ctx_none = 0,
    k_obi_ctx_http_server = 1,
    k_obi_ctx_grpc_server = 2,
    k_obi_ctx_grpc_client = 3,
    k_obi_ctx_sql = 4,
    k_obi_ctx_redis = 5,
    k_obi_ctx_mongo = 6,
    k_obi_ctx_kafka_produce = 7,
};

enum { k_obi_ctx_max_depth = 4 };

enum { k_g_stack_hi_off = 8 }; // runtime.g.stack.hi

typedef struct obi_ctx_frame {
    tp_info_t tp;
    u32 stack_off;
    u8 kind;
    u8 _pad[3];
} obi_ctx_frame_t;

typedef struct obi_ctx_stack {
    obi_ctx_frame_t frames[k_obi_ctx_max_depth];
    u32 depth;
    // how many spans started after the stack was full and were not stored
    u32 overflow;
    // the last span that was not stored, so that its restart is not counted twice
    u32 unstored_stack_off;
    u8 unstored_kind;
    u8 _pad[3];
} obi_ctx_stack_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);
    __type(value, obi_ctx_stack_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} obi_ctx_stacks SEC(".maps");

SCRATCH_MEM_TYPED(obi_ctx_stack_scratch, obi_ctx_stack_t)

// How deep the probed call is in the goroutine stack. When Go grows the stack it
// restarts the function, so the entry probe fires twice at the same depth. A nested
// call of the same kind is always deeper
static __always_inline u32 go_obi_ctx__stack_off(struct pt_regs *ctx) {
    u64 stack_hi = 0;
    bpf_probe_read_user(
        &stack_hi, sizeof(stack_hi), (void *)((char *)GOROUTINE_PTR(ctx) + k_g_stack_hi_off));
    return (u32)(stack_hi - PT_REGS_SP(ctx));
}

static __always_inline u32 obi_ctx__depth(const obi_ctx_stack_t *st) {
    return st->depth < k_obi_ctx_max_depth ? st->depth : k_obi_ctx_max_depth;
}

static __always_inline u32 obi_ctx__top(const obi_ctx_stack_t *st) {
    return (st->depth - 1) & (k_obi_ctx_max_depth - 1);
}

static __always_inline u8 obi_ctx__same_span(const tp_info_t *a, const tp_info_t *b) {
    return *(const u64 *)a->span_id == *(const u64 *)b->span_id;
}

// a goroutine serves one request at a time: a second server begin is the same request
static __always_inline u8 obi_ctx__is_server(u8 kind) {
    return kind == k_obi_ctx_http_server || kind == k_obi_ctx_grpc_server;
}

// Newest frame of this span, or of this kind when tp is NULL. k_obi_ctx_max_depth if none
static __always_inline u32 obi_ctx__find(const obi_ctx_stack_t *st, u8 kind, const tp_info_t *tp) {
    const u32 depth = obi_ctx__depth(st);

    for (u32 i = 0; i < k_obi_ctx_max_depth; i++) {
        if (i >= depth) {
            break;
        }
        const u32 idx = (depth - 1 - i) & (k_obi_ctx_max_depth - 1);
        const obi_ctx_frame_t *frame = &st->frames[idx];
        if (tp ? obi_ctx__same_span(&frame->tp, tp) : frame->kind == kind) {
            return idx;
        }
    }

    return k_obi_ctx_max_depth;
}

// Frame already created for this call, if any
static __always_inline u32 obi_ctx__reentered(const obi_ctx_stack_t *st,
                                              u8 kind,
                                              const tp_info_t *tp,
                                              u32 stack_off) {
    u32 idx = obi_ctx__find(st, kind, tp);
    if (idx < k_obi_ctx_max_depth) {
        return idx;
    }

    if (obi_ctx__is_server(kind)) {
        return obi_ctx__find(st, kind, NULL);
    }

    if (st->depth > 0) {
        const obi_ctx_frame_t *top = &st->frames[obi_ctx__top(st)];
        if (top->kind == kind && top->stack_off == stack_off) {
            return obi_ctx__top(st);
        }
    }

    return k_obi_ctx_max_depth;
}

static __always_inline void
obi_ctx__publish_top(u64 pid_tgid, const go_addr_key_t *g_key, const obi_ctx_stack_t *st) {
    if (st->depth == 0) {
        bpf_map_delete_elem(&obi_ctx_stacks, g_key);
        obi_ctx__del(pid_tgid);
        return;
    }

    obi_ctx__set(pid_tgid, &st->frames[obi_ctx__top(st)].tp);
}

// A span started: it becomes the goroutine's current context
static __always_inline void
go_obi_ctx__begin(const go_addr_key_t *g_key, u8 kind, const tp_info_t *tp, u32 stack_off) {
    obi_ctx__set(bpf_get_current_pid_tgid(), tp);

    obi_ctx_stack_t *st = bpf_map_lookup_elem(&obi_ctx_stacks, g_key);
    if (!st) {
        obi_ctx_stack_t *fresh = obi_ctx_stack_scratch_mem();
        if (!fresh) {
            return;
        }
        bpf_memset(fresh, 0, sizeof(*fresh));
        fresh->frames[0].tp = *tp;
        fresh->frames[0].stack_off = stack_off;
        fresh->frames[0].kind = kind;
        fresh->depth = 1;
        bpf_map_update_elem(&obi_ctx_stacks, g_key, fresh, BPF_ANY);
        return;
    }

    // the call is already on the stack: it is the top of the real stack, so
    // anything above it has ended
    const u32 idx = obi_ctx__reentered(st, kind, tp, stack_off);
    if (idx < k_obi_ctx_max_depth) {
        st->frames[idx].tp = *tp;
        st->depth = idx + 1;
        st->overflow = 0;
        st->unstored_kind = k_obi_ctx_none;
        return;
    }

    if (st->depth >= k_obi_ctx_max_depth) {
        const u8 restarted =
            st->overflow > 0 && st->unstored_kind == kind && st->unstored_stack_off == stack_off;
        if (!restarted) {
            st->overflow++;
            st->unstored_kind = kind;
            st->unstored_stack_off = stack_off;
        }
        return;
    }

    obi_ctx_frame_t *frame = &st->frames[st->depth & (k_obi_ctx_max_depth - 1)];
    frame->tp = *tp;
    frame->stack_off = stack_off;
    frame->kind = kind;
    st->depth++;
    st->unstored_kind = k_obi_ctx_none;
}

// A span ended: drop its frame and everything above it, then make the span below current.
// Spans end in reverse start order, so while overflow > 0 an end we cannot find belongs
// to a span that was never stored
static __always_inline void
go_obi_ctx__end(const go_addr_key_t *g_key, u8 kind, const tp_info_t *tp) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();

    obi_ctx_stack_t *st = bpf_map_lookup_elem(&obi_ctx_stacks, g_key);
    if (!st) {
        obi_ctx__del(pid_tgid);
        return;
    }

    const u32 idx = obi_ctx__find(st, kind, tp);

    if (idx < k_obi_ctx_max_depth && (tp || st->overflow == 0)) {
        st->depth = idx;
        st->overflow = 0;
    } else if (st->overflow > 0) {
        st->overflow--;
    }
    st->unstored_kind = k_obi_ctx_none;

    obi_ctx__publish_top(pid_tgid, g_key, st);
}

// The goroutine got scheduled: put its current span on this thread, or clear the thread
static __always_inline void go_obi_ctx__resume(u64 pid_tgid, const go_addr_key_t *g_key) {
    const obi_ctx_stack_t *st = bpf_map_lookup_elem(&obi_ctx_stacks, g_key);
    if (st && st->depth > 0) {
        obi_ctx__set(pid_tgid, &st->frames[obi_ctx__top(st)].tp);
        return;
    }
    obi_ctx__del(pid_tgid);
}
