// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/go_addr_key.h>
#include <common/scratch_mem.h>

#include <gotracer/types/grpc.h>
#include <gotracer/maps/grpc.h>

SCRATCH_MEM_TYPED(grpc_client_stack_scratch, grpc_client_invocation_stack_t)

// Verifier-friendly clamped depth access mirroring obi_ctx__depth
static __always_inline u32 grpc_client_depth(const grpc_client_invocation_stack_t *st) {
    u32 depth = *(volatile const u32 *)&st->depth;
    bpf_clamp_umax(depth, k_grpc_client_max_depth);
    return depth;
}

static __always_inline u32 grpc_client_slot(u32 idx) {
    bpf_clamp_umax(idx, k_grpc_client_max_depth - 1);
    return idx;
}

// Current active invocation for this goroutine.
// While overflow > 0, an untracked deeper RPC is running: do not return a stale frame.
static __always_inline grpc_client_func_invocation_t *
grpc_client_current(grpc_client_invocation_stack_t *st) {
    if (!st || st->overflow > 0) {
        return NULL;
    }

    const u32 depth = grpc_client_depth(st);
    if (depth == 0) {
        return NULL;
    }

    return &st->frames[grpc_client_slot(depth - 1)];
}

// Push an invocation onto the goroutine's LIFO stack.
// Returns true if the invocation was stored in frames (tracked), or false if overflowed.
static __always_inline bool grpc_client_push(const go_addr_key_t *g_key,
                                             grpc_client_invocation_stack_t *st,
                                             const grpc_client_func_invocation_t *inv) {
    (void)g_key;
    if (!st) {
        return false;
    }

    const u32 depth = grpc_client_depth(st);

    // If the top frame has the same stack_off, Go restarted the function after stack growth
    if (depth > 0 && st->overflow == 0) {
        grpc_client_func_invocation_t *top = &st->frames[grpc_client_slot(depth - 1)];
        if (top->stack_off == inv->stack_off) {
            *top = *inv;
            return true;
        }
    }

    if (depth >= k_grpc_client_max_depth) {
        if (st->overflow > 0 && st->unstored_stack_off == inv->stack_off) {
            return false;
        }
        st->overflow++;
        st->unstored_stack_off = inv->stack_off;
        return false;
    }

    st->frames[grpc_client_slot(depth)] = *inv;
    st->depth = depth + 1;
    return true;
}

// Pop the top invocation from the goroutine's LIFO stack.
// Returns true if a tracked invocation was popped into *out, or false if overflowed / empty.
static __always_inline bool grpc_client_pop(const go_addr_key_t *g_key,
                                            grpc_client_invocation_stack_t *st,
                                            grpc_client_func_invocation_t *out) {
    if (!st) {
        return false;
    }

    if (st->overflow > 0) {
        st->overflow--;
        if (st->overflow == 0) {
            st->unstored_stack_off = 0;
        }
        return false;
    }

    const u32 depth = grpc_client_depth(st);
    if (depth == 0) {
        return false;
    }

    if (out) {
        *out = st->frames[grpc_client_slot(depth - 1)];
    }

    st->depth = depth - 1;
    if (st->depth == 0) {
        bpf_map_delete_elem(&ongoing_grpc_client_requests, g_key);
    }
    return true;
}

static __always_inline void grpc_client_constructor_begin(grpc_client_func_invocation_t *inv) {
    if (inv) {
        inv->stream_constructor_active = 1;
    }
}

static __always_inline void grpc_client_constructor_end(grpc_client_func_invocation_t *inv) {
    if (inv) {
        inv->stream_constructor_active = 0;
    }
}

// Establishes a fresh stream object generation at s_key (*clientStream pointer).
// Any stale tombstones or orphaned markers from previous defunct objects at this address
// are invalidated before the new stream can begin or finish.
static __always_inline void grpc_client_begin_stream_generation(const go_addr_key_t *s_key) {
    bpf_map_delete_elem(&completed_grpc_client_streams, s_key);
    bpf_map_delete_elem(&early_grpc_client_finishes, s_key);
    bpf_map_delete_elem(&ongoing_grpc_client_streams, s_key);

    const u8 tracked = 1;
    bpf_map_update_elem(&tracked_grpc_client_streams, s_key, &tracked, BPF_ANY);
}

static __always_inline bool grpc_client_claim_stream(const go_addr_key_t *s_key) {
    const u8 completed = 1;
    return bpf_map_update_elem(&completed_grpc_client_streams, s_key, &completed, BPF_NOEXIST) ==
           0;
}
