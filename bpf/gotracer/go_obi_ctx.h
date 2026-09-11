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

enum { k_obi_ctx_kind_count = k_obi_ctx_kafka_produce + 1 };

// saturation cap for the per-kind unstored span counters
enum { k_obi_ctx_overflow_max = 255 };

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
    u32 unstored_stack_off;
    // how many spans of each kind started after the stack was full and were not
    // stored, so that an end of an unrelated kind cannot consume their count
    u8 overflow[k_obi_ctx_kind_count];
    // the last span that was not stored, so that its restart is not counted twice
    // and its context survives a reschedule while it runs
    u8 unstored_kind;
    u8 _pad[7];
    tp_info_t unstored_tp;
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

// The bounds are clamped in asm so that older verifiers see a single consistent
// range for every frame index derived from the stored depth
static __always_inline u32 obi_ctx__depth(const obi_ctx_stack_t *st) {
    u32 depth = st->depth;
    bpf_clamp_umax(depth, k_obi_ctx_max_depth);
    return depth;
}

static __always_inline u32 obi_ctx__slot(u32 idx) {
    bpf_clamp_umax(idx, k_obi_ctx_max_depth - 1);
    return idx;
}

static __always_inline u32 obi_ctx__kind_slot(u8 kind) {
    u32 slot = kind;
    bpf_clamp_umax(slot, k_obi_ctx_kind_count - 1);
    return slot;
}

static __always_inline u8 obi_ctx__same_span(const tp_info_t *a, const tp_info_t *b) {
    return *(const u64 *)a->span_id == *(const u64 *)b->span_id;
}

// a goroutine serves one request at a time: a second server begin is the same request
static __always_inline u8 obi_ctx__is_server(u8 kind) {
    return kind == k_obi_ctx_http_server || kind == k_obi_ctx_grpc_server;
}

// Newest frame of this span, or of this kind when tp is NULL. k_obi_ctx_max_depth if none
static __always_inline u32 obi_ctx__find(const obi_ctx_stack_t *st,
                                         u32 depth,
                                         u8 kind,
                                         const tp_info_t *tp) {
    for (u32 i = 0; i < k_obi_ctx_max_depth; i++) {
        if (i >= depth) {
            break;
        }
        const obi_ctx_frame_t *frame = &st->frames[obi_ctx__slot(depth - 1 - i)];
        if (tp ? obi_ctx__same_span(&frame->tp, tp) : frame->kind == kind) {
            return depth - 1 - i;
        }
    }

    return k_obi_ctx_max_depth;
}

// Frame already created for this call, if any
static __always_inline u32 obi_ctx__reentered(
    const obi_ctx_stack_t *st, u32 depth, u8 kind, const tp_info_t *tp, u32 stack_off) {
    u32 idx = obi_ctx__find(st, depth, kind, tp);
    if (idx < k_obi_ctx_max_depth) {
        return idx;
    }

    if (obi_ctx__is_server(kind)) {
        return obi_ctx__find(st, depth, kind, NULL);
    }

    if (depth > 0) {
        const obi_ctx_frame_t *top = &st->frames[obi_ctx__slot(depth - 1)];
        if (top->kind == kind && top->stack_off == stack_off) {
            return depth - 1;
        }
    }

    return k_obi_ctx_max_depth;
}

// The goroutine's current span: the newest unstored one while it runs, else the
// top frame. NULL when nothing is running
static __always_inline const tp_info_t *obi_ctx__current(const obi_ctx_stack_t *st) {
    if (st->unstored_kind != k_obi_ctx_none) {
        return &st->unstored_tp;
    }

    const u32 depth = obi_ctx__depth(st);
    if (depth == 0) {
        return NULL;
    }

    return &st->frames[obi_ctx__slot(depth - 1)].tp;
}

static __always_inline void
obi_ctx__publish_current(u64 pid_tgid, const go_addr_key_t *g_key, const obi_ctx_stack_t *st) {
    const tp_info_t *tp = obi_ctx__current(st);
    if (!tp) {
        bpf_map_delete_elem(&obi_ctx_stacks, g_key);
        obi_ctx__del(pid_tgid);
        return;
    }

    obi_ctx__set(pid_tgid, tp);
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

    const u32 depth = obi_ctx__depth(st);

    // the call is already on the stack: it is the top of the real stack, so
    // anything above it has ended
    const u32 idx = obi_ctx__reentered(st, depth, kind, tp, stack_off);
    if (idx < k_obi_ctx_max_depth) {
        st->frames[obi_ctx__slot(idx)].tp = *tp;
        st->depth = idx + 1;
        bpf_memset(st->overflow, 0, sizeof(st->overflow));
        st->unstored_kind = k_obi_ctx_none;
        return;
    }

    if (depth >= k_obi_ctx_max_depth) {
        u8 *unstored = &st->overflow[obi_ctx__kind_slot(kind)];
        const u8 restarted =
            *unstored > 0 && st->unstored_kind == kind && st->unstored_stack_off == stack_off;
        if (restarted) {
            st->unstored_tp = *tp;
        } else if (*unstored < k_obi_ctx_overflow_max) {
            (*unstored)++;
            st->unstored_kind = kind;
            st->unstored_stack_off = stack_off;
            st->unstored_tp = *tp;
        }
        return;
    }

    obi_ctx_frame_t *frame = &st->frames[obi_ctx__slot(depth)];
    frame->tp = *tp;
    frame->stack_off = stack_off;
    frame->kind = kind;
    st->depth = depth + 1;
    st->unstored_kind = k_obi_ctx_none;
}

// A span ended: drop its frame and everything above it, then make the span below current.
// Spans of one kind end in reverse start order, so an end we cannot find, or an end
// without tp while its kind has unstored spans, belongs to a span that was never stored
static __always_inline void
go_obi_ctx__end(const go_addr_key_t *g_key, u8 kind, const tp_info_t *tp) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();

    obi_ctx_stack_t *st = bpf_map_lookup_elem(&obi_ctx_stacks, g_key);
    if (!st) {
        obi_ctx__del(pid_tgid);
        return;
    }

    u8 *unstored = &st->overflow[obi_ctx__kind_slot(kind)];
    const u32 idx = obi_ctx__find(st, obi_ctx__depth(st), kind, tp);

    if (idx < k_obi_ctx_max_depth && (tp || *unstored == 0)) {
        st->depth = idx;
        bpf_memset(st->overflow, 0, sizeof(st->overflow));
    } else if (*unstored > 0) {
        (*unstored)--;
    } else {
        // none of this goroutine's spans ended (e.g. ClientConn.Close without
        // a begin): leave the context and the restart marker alone
        return;
    }
    st->unstored_kind = k_obi_ctx_none;

    obi_ctx__publish_current(pid_tgid, g_key, st);
}

// The goroutine got scheduled: put its current span on this thread, or clear the thread
static __always_inline void go_obi_ctx__resume(u64 pid_tgid, const go_addr_key_t *g_key) {
    const obi_ctx_stack_t *st = bpf_map_lookup_elem(&obi_ctx_stacks, g_key);
    const tp_info_t *tp = st ? obi_ctx__current(st) : NULL;
    if (tp) {
        obi_ctx__set(pid_tgid, tp);
        return;
    }
    obi_ctx__del(pid_tgid);
}
