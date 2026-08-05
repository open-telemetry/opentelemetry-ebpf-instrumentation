// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_builtins.h>

#include <common/go_addr_key.h>
#include <common/map_sizing.h>
#include <common/outgoing_trace_handoff.h>
#include <common/pin_internal.h>

typedef struct go_outgoing_trace_handoff_ref {
    egress_key_t egress;
    u32 _pad;
    outgoing_trace_token_t token;
} go_outgoing_trace_handoff_ref_t;

typedef struct go_outgoing_trace_handoff_owner {
    go_addr_key_t request;
    u64 process_start_time;
} go_outgoing_trace_handoff_owner_t;

// A Go request can finish on a different probe than the wire producer. This
// bounded, evictable exact reference lets completion retire authority while
// missed hooks or dead processes cannot permanently exhaust finite capacity.
// Exact outgoing handoff authority remains non-evicting and is reaped when an
// evicted reference leaves it orphaned.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_outgoing_trace_handoff_owner_t);
    __type(value, go_outgoing_trace_handoff_ref_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_outgoing_trace_handoffs SEC(".maps");

// Serializes lookup/register/cleanup for a reusable Go object or goroutine
// address. Helpers never retain this claim across a probe return or tail call.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, go_outgoing_trace_handoff_owner_t);
    __type(value, u8);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_outgoing_trace_handoff_owner_claims SEC(".maps");

static __always_inline u8
claim_go_outgoing_trace_handoff_owner(const go_outgoing_trace_handoff_owner_t *owner) {
    const u8 claimed = 1;
    return owner && bpf_map_update_elem(
                        &go_outgoing_trace_handoff_owner_claims, owner, &claimed, BPF_NOEXIST) == 0;
}

static __always_inline void
release_go_outgoing_trace_handoff_owner(const go_outgoing_trace_handoff_owner_t *owner) {
    if (owner) {
        bpf_map_delete_elem(&go_outgoing_trace_handoff_owner_claims, owner);
    }
}

static __always_inline u8 register_go_outgoing_trace_handoff(const go_addr_key_t *request_key,
                                                             const egress_key_t *egress,
                                                             const outgoing_trace_token_t *token) {
    if (!request_key || !egress || !outgoing_trace_token_valid(token) ||
        !process_incarnation_matches_current_exact((u32)request_key->pid,
                                                   token->process_start_time)) {
        return 0;
    }
    const go_outgoing_trace_handoff_owner_t owner = {
        .request = *request_key,
        .process_start_time = token->process_start_time,
    };
    outgoing_trace_handoff_key_t authority_key = {};
    if (!claim_outgoing_trace_handoff_reference(egress, token, &authority_key)) {
        return 0;
    }
    if (!claim_go_outgoing_trace_handoff_owner(&owner)) {
        release_outgoing_trace_handoff_key(&authority_key);
        return 0;
    }

    go_outgoing_trace_handoff_ref_t ref = {
        .egress = *egress,
        .token = *token,
    };
    u8 registered =
        bpf_map_update_elem(&go_outgoing_trace_handoffs, &owner, &ref, BPF_NOEXIST) == 0;

    if (!registered) {
        const go_outgoing_trace_handoff_ref_t *existing =
            bpf_map_lookup_elem(&go_outgoing_trace_handoffs, &owner);
        registered = existing &&
                     bpf_memcmp(&existing->egress, &ref.egress, sizeof(ref.egress)) == 0 &&
                     outgoing_trace_tokens_match(&existing->token, &ref.token);
    }
    release_go_outgoing_trace_handoff_owner(&owner);
    release_outgoing_trace_handoff_key(&authority_key);
    return registered;
}

static __always_inline u8 cleanup_go_outgoing_trace_handoff(const go_addr_key_t *request_key) {
    if (!request_key) {
        return 0;
    }
    const u64 process_start_time = OBI_CURRENT_PROCESS_START_BOOTTIME_NS();
    if (!process_start_time) {
        return 0;
    }
    const go_outgoing_trace_handoff_owner_t owner = {
        .request = *request_key,
        .process_start_time = process_start_time,
    };
    if (!claim_go_outgoing_trace_handoff_owner(&owner)) {
        return 0;
    }
    const go_outgoing_trace_handoff_ref_t *ref =
        bpf_map_lookup_elem(&go_outgoing_trace_handoffs, &owner);
    if (!ref) {
        release_go_outgoing_trace_handoff_owner(&owner);
        return 0;
    }

    const go_outgoing_trace_handoff_ref_t exact = *ref;
    cleanup_outgoing_trace_handoff_token(
        &exact.egress, exact.egress.pid, EVENT_HTTP_CLIENT, &exact.token);
    bpf_map_delete_elem(&go_outgoing_trace_handoffs, &owner);
    release_go_outgoing_trace_handoff_owner(&owner);
    return 1;
}
