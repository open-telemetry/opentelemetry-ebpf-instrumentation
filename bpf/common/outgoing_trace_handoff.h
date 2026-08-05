// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_builtins.h>

#include <common/event_defs.h>
#include <common/process_incarnation.h>
#include <common/trace_util.h>

#include <maps/outgoing_trace_handoff.h>
#include <maps/outgoing_trace_map.h>

static __always_inline u8 outgoing_trace_identity_matches(const tp_info_pid_t *left,
                                                          const tp_info_pid_t *right) {
    return left && right && left->pid == right->pid && left->req_type == right->req_type &&
           left->tp.ts == right->tp.ts && left->tp.flags == right->tp.flags &&
           left->tp.sampling_decision == right->tp.sampling_decision &&
           left->tp.parent_remote == right->tp.parent_remote &&
           bpf_memcmp(left->tp.trace_id, right->tp.trace_id, TRACE_ID_SIZE_BYTES) == 0 &&
           bpf_memcmp(left->tp.span_id, right->tp.span_id, SPAN_ID_SIZE_BYTES) == 0 &&
           bpf_memcmp(left->tp.parent_id, right->tp.parent_id, SPAN_ID_SIZE_BYTES) == 0;
}

static __always_inline u8 outgoing_trace_identity_matches_tp(const tp_info_pid_t *candidate,
                                                             const tp_info_t *tp,
                                                             u32 pid,
                                                             u8 req_type) {
    return candidate && tp && candidate->pid == pid && candidate->req_type == req_type &&
           candidate->tp.ts == tp->ts && candidate->tp.flags == tp->flags &&
           candidate->tp.sampling_decision == tp->sampling_decision &&
           candidate->tp.parent_remote == tp->parent_remote &&
           bpf_memcmp(candidate->tp.trace_id, tp->trace_id, TRACE_ID_SIZE_BYTES) == 0 &&
           bpf_memcmp(candidate->tp.span_id, tp->span_id, SPAN_ID_SIZE_BYTES) == 0 &&
           bpf_memcmp(candidate->tp.parent_id, tp->parent_id, SPAN_ID_SIZE_BYTES) == 0;
}

static __always_inline void delete_outgoing_trace_if_matches(const egress_key_t *egress,
                                                             const tp_info_pid_t *expected) {
    tp_info_pid_t *current = bpf_map_lookup_elem(&outgoing_trace_map, egress);
    if (outgoing_trace_identity_matches(current, expected)) {
        bpf_map_delete_elem(&outgoing_trace_map, egress);
    }
}

static __always_inline u8 outgoing_trace_token_valid(const outgoing_trace_token_t *token) {
    return token && token->map_epoch && token->sequence && token->process_start_time;
}

static __always_inline u8 outgoing_trace_tokens_match(const outgoing_trace_token_t *left,
                                                      const outgoing_trace_token_t *right) {
    return left && right && left->map_epoch == right->map_epoch &&
           left->sequence == right->sequence &&
           left->process_start_time == right->process_start_time && left->cpu == right->cpu;
}

static __always_inline outgoing_trace_handoff_key_t
outgoing_trace_handoff_key(const egress_key_t *egress, const outgoing_trace_token_t *token) {
    outgoing_trace_handoff_key_t key = {};
    if (egress) {
        key.egress = *egress;
    }
    if (token) {
        key.token = *token;
    }
    return key;
}

static __always_inline outgoing_trace_handoff_t *
lookup_outgoing_trace_handoff_exact(const outgoing_trace_handoff_key_t *key) {
    return bpf_map_lookup_elem(&outgoing_trace_handoff, key);
}

static __always_inline u8 outgoing_trace_handoff_matches(const outgoing_trace_handoff_t *handoff,
                                                         const outgoing_trace_handoff_key_t *key,
                                                         u32 pid,
                                                         u8 req_type,
                                                         const tp_info_pid_t *expected,
                                                         u8 require_current_incarnation) {
    if (!handoff || !key || !handoff->tp.valid || handoff->tp.written > k_outbound_trace_written ||
        handoff->tp.pid != pid || handoff->tp.req_type != req_type ||
        (expected && !outgoing_trace_identity_matches(&handoff->tp, expected))) {
        return 0;
    }
    return !require_current_incarnation ||
           process_incarnation_matches_current_exact(pid, key->token.process_start_time);
}

// Identity matching remains valid for exact cleanup, including terminal
// generations. Consumer authorization is stricter: once any terminal outcome
// is visible, no later snapshot or claimant may propagate that generation.
static __always_inline u8
outgoing_trace_handoff_authorizable(const outgoing_trace_handoff_t *handoff) {
    return handoff && !handoff->retire_requested && !handoff->terminal_at &&
           handoff->terminal_reason == k_outgoing_trace_terminal_none &&
           !(handoff->tp.written == k_outbound_trace_written && handoff->local_consumed);
}

static __always_inline u8 claim_outgoing_trace_handoff_egress(const egress_key_t *egress) {
    const u8 claimed = 1;
    return egress && bpf_map_update_elem(
                         &outgoing_trace_handoff_egress_claims, egress, &claimed, BPF_NOEXIST) == 0;
}

static __always_inline void release_outgoing_trace_handoff_egress(const egress_key_t *egress) {
    if (egress) {
        bpf_map_delete_elem(&outgoing_trace_handoff_egress_claims, egress);
    }
}

static __always_inline u8
claim_outgoing_trace_handoff_key(const outgoing_trace_handoff_key_t *key) {
    const u8 claimed = 1;
    return key &&
           bpf_map_update_elem(&outgoing_trace_handoff_claims, key, &claimed, BPF_NOEXIST) == 0;
}

static __always_inline void
release_outgoing_trace_handoff_key(const outgoing_trace_handoff_key_t *key) {
    if (key) {
        bpf_map_delete_elem(&outgoing_trace_handoff_claims, key);
    }
}

// Exact reverse-reference publication participates in the same action claim
// protocol as consumers and the userspace reaper. The refreshed progress is
// visible before the ref, so a reaper that scanned absence earlier must
// recheck and abandon retirement after this claim is released.
static __always_inline u8
claim_outgoing_trace_handoff_reference(const egress_key_t *egress,
                                       const outgoing_trace_token_t *token,
                                       outgoing_trace_handoff_key_t *claimed_key) {
    if (!egress || !outgoing_trace_token_valid(token) || !claimed_key) {
        return 0;
    }
    const outgoing_trace_handoff_key_t key = outgoing_trace_handoff_key(egress, token);
    if (!claim_outgoing_trace_handoff_key(&key)) {
        return 0;
    }
    outgoing_trace_handoff_t *handoff = lookup_outgoing_trace_handoff_exact(&key);
    if (!outgoing_trace_handoff_matches(handoff, &key, egress->pid, EVENT_HTTP_CLIENT, NULL, 1) ||
        !outgoing_trace_handoff_authorizable(handoff)) {
        release_outgoing_trace_handoff_key(&key);
        return 0;
    }
    handoff->last_progress = bpf_ktime_get_ns();
    *claimed_key = key;
    return 1;
}

// Returns with the current CPU's allocation guard held. The caller must keep
// the guard through the exact authority insertion and release it on every
// exit. Current producers run only in non-NMI tracing/socket contexts; adding
// an NMI-context producer requires a separate proof because a regular hash map
// must not be treated as a general NMI mutex. This avoids atomic-fetch
// instructions unavailable on the oldest supported kernels.
static __noinline __attribute__((unused)) u8
begin_outgoing_trace_token_allocation(outgoing_trace_token_t *token) {
    if (!token) {
        return 0;
    }

    const u64 process_start_time = OBI_CURRENT_PROCESS_START_BOOTTIME_NS();
    if (!process_start_time) {
        return 0;
    }

    const u32 cpu = bpf_get_smp_processor_id();
    const u64 claimed_at = bpf_ktime_get_ns();
    if (bpf_map_update_elem(&outgoing_trace_handoff_cpu_claims, &cpu, &claimed_at, BPF_NOEXIST)) {
        return 0;
    }

    u64 *sequence = bpf_map_lookup_elem(&outgoing_trace_handoff_sequence, &(u32){0});
    u64 *epoch = bpf_map_lookup_elem(&outgoing_trace_handoff_epoch, &(u32){0});
    if (!sequence || !epoch || !*epoch || *sequence == ~0ULL) {
        bpf_map_delete_elem(&outgoing_trace_handoff_cpu_claims, &cpu);
        return 0;
    }

    // U64_MAX is a valid final generation. The next allocation observes the
    // saturated value and permanently fails closed for this lane.
    *sequence += 1;
    *token = (outgoing_trace_token_t){
        .map_epoch = *epoch,
        .sequence = *sequence,
        .process_start_time = process_start_time,
        .cpu = cpu,
    };
    return 1;
}

static __always_inline long
release_outgoing_trace_token_allocation(const outgoing_trace_token_t *token) {
    if (!token) {
        return -1;
    }
    return bpf_map_delete_elem(&outgoing_trace_handoff_cpu_claims, &token->cpu);
}

// Called only while the token's CPU guard is held and the program is still on
// that CPU. A duplicate exact generation indicates broken allocator lifetime;
// poison the lane rather than risk publishing another ambiguous token.
static __always_inline void poison_outgoing_trace_token_lane(const outgoing_trace_token_t *token) {
    if (!token || token->cpu != bpf_get_smp_processor_id()) {
        return;
    }
    u64 *sequence = bpf_map_lookup_elem(&outgoing_trace_handoff_sequence, &(u32){0});
    if (sequence) {
        *sequence = ~0ULL;
    }
}

enum outgoing_trace_reservation_result : u8 {
    k_outgoing_trace_reservation_failed,
    k_outgoing_trace_reservation_fresh,
    k_outgoing_trace_reservation_reused,
};

// Must be called before any wire mutation. The egress claim serializes the
// non-authoritative locator and guarantees that at most one live generation
// owns an egress tuple.
static __noinline __attribute__((unused)) u8 reserve_outgoing_trace_handoff(
    const egress_key_t *egress, const tp_info_pid_t *candidate, outgoing_trace_token_t *token) {
    if (!egress || !candidate || !token || !candidate->valid ||
        candidate->written > k_outbound_trace_written || candidate->pid != egress->pid) {
        return 0;
    }

    outgoing_trace_token_t fresh = {};
    if (!begin_outgoing_trace_token_allocation(&fresh)) {
        return 0;
    }
    // Even a conflict/saturation failure carries an exact missing generation
    // into transport scratch, forcing downstream consumers to fail closed.
    *token = fresh;
    if (!claim_outgoing_trace_handoff_egress(egress)) {
        // If releasing the guard itself fails the CPU lane remains
        // unavailable, and this reservation is never published.
        release_outgoing_trace_token_allocation(&fresh);
        return 0;
    }

    u8 result = k_outgoing_trace_reservation_failed;
    u8 allocation_guard_held = 1;
    u8 fresh_authority_inserted = 0;
    outgoing_trace_token_t current = {};
    outgoing_trace_token_t *located = bpf_map_lookup_elem(&outgoing_trace_handoff_locators, egress);
    if (located) {
        current = *located;
    }

    if (outgoing_trace_token_valid(&current)) {
        const outgoing_trace_handoff_key_t current_key =
            outgoing_trace_handoff_key(egress, &current);
        outgoing_trace_handoff_t *existing = lookup_outgoing_trace_handoff_exact(&current_key);
        if (existing && existing->tp.valid) {
            const u8 stale_incarnation =
                !process_incarnation_matches_current_exact(egress->pid, current.process_start_time);
            const u8 reclaimable =
                !outgoing_trace_handoff_authorizable(existing) ||
                (existing->tp.written == k_outbound_trace_written && existing->local_consumed);

            if (!stale_incarnation && !reclaimable &&
                outgoing_trace_identity_matches(&existing->tp, candidate)) {
                *token = current;
                result = k_outgoing_trace_reservation_reused;
                goto done;
            }

            // A live different request remains authoritative. A stale,
            // deferred, or fully durable generation can be reaped only after
            // acquiring its exact action claim.
            if (!stale_incarnation && !reclaimable) {
                goto done;
            }
            if (!claim_outgoing_trace_handoff_key(&current_key)) {
                goto done;
            }
            existing = lookup_outgoing_trace_handoff_exact(&current_key);
            if (existing &&
                (stale_incarnation || !outgoing_trace_handoff_authorizable(existing) ||
                 (existing->tp.written == k_outbound_trace_written && existing->local_consumed))) {
                delete_outgoing_trace_if_matches(egress, &existing->tp);
                bpf_map_delete_elem(&outgoing_trace_handoff, &current_key);
            }
            release_outgoing_trace_handoff_key(&current_key);
        }
    }

    const outgoing_trace_handoff_key_t fresh_key = outgoing_trace_handoff_key(egress, &fresh);
    const u64 created_at = bpf_ktime_get_ns();
    const outgoing_trace_handoff_t reservation = {
        .tp = *candidate,
        .created_at = created_at,
        .last_progress = created_at,
    };
    const long insert_err =
        bpf_map_update_elem(&outgoing_trace_handoff, &fresh_key, &reservation, BPF_NOEXIST);
    if (insert_err) {
        // bpf_map_update_elem returns -EEXIST (-17) for an exact duplicate.
        if (insert_err == -17) {
            poison_outgoing_trace_token_lane(&fresh);
        }
        goto done;
    }
    fresh_authority_inserted = 1;

    // The generation cannot become discoverable until the allocation guard is
    // successfully released. A stuck guard fails this lane closed.
    if (release_outgoing_trace_token_allocation(&fresh)) {
        bpf_map_delete_elem(&outgoing_trace_handoff, &fresh_key);
        fresh_authority_inserted = 0;
        allocation_guard_held = 0;
        goto done;
    }
    allocation_guard_held = 0;

    if (bpf_map_update_elem(&outgoing_trace_handoff_locators, egress, &fresh, BPF_ANY)) {
        bpf_map_delete_elem(&outgoing_trace_handoff, &fresh_key);
        fresh_authority_inserted = 0;
        goto done;
    }

    *token = fresh;
    result = k_outgoing_trace_reservation_fresh;

done:
    if (allocation_guard_held) {
        if (release_outgoing_trace_token_allocation(&fresh)) {
            // Existing-authority reuse is not granted if this invocation
            // cannot prove it released the allocation lane.
            result = k_outgoing_trace_reservation_failed;
        }
    }
    if (result == k_outgoing_trace_reservation_failed && fresh_authority_inserted) {
        bpf_map_delete_elem(&outgoing_trace_handoff, &fresh_key);
    }
    release_outgoing_trace_handoff_egress(egress);
    return result;
}

// Remove a locator only while holding its egress claim. A locator is a hint,
// never authority, but keeping its lifecycle serialized prevents stale cleanup
// from removing a newer request's hint.
static __always_inline void
clear_outgoing_trace_handoff_locator_claimed(const egress_key_t *egress,
                                             const outgoing_trace_token_t *token) {
    outgoing_trace_token_t *current = bpf_map_lookup_elem(&outgoing_trace_handoff_locators, egress);
    if (outgoing_trace_tokens_match(current, token)) {
        bpf_map_delete_elem(&outgoing_trace_handoff_locators, egress);
    }
}

// The exact action claim and the egress claim must be held. The immutable
// authority key can be deleted directly; a later reservation uses a different
// generation and cannot be affected by a delayed operation on this key.
static __always_inline void
retire_claimed_outgoing_trace_handoff_egress_held(const outgoing_trace_handoff_key_t *key) {
    if (!key) {
        return;
    }

    tp_info_pid_t retired = {};
    outgoing_trace_handoff_t *handoff = lookup_outgoing_trace_handoff_exact(key);
    const u8 has_retired = handoff != NULL;
    if (has_retired) {
        retired = handoff->tp;
    }
    bpf_map_delete_elem(&outgoing_trace_handoff, key);
    clear_outgoing_trace_handoff_locator_claimed(&key->egress, &key->token);

    if (has_retired) {
        delete_outgoing_trace_if_matches(&key->egress, &retired);
    }
}

// The exact action claim must be held.
static __always_inline void
retire_claimed_outgoing_trace_handoff(const outgoing_trace_handoff_key_t *key) {
    if (!key || !claim_outgoing_trace_handoff_egress(&key->egress)) {
        return;
    }

    retire_claimed_outgoing_trace_handoff_egress_held(key);
    release_outgoing_trace_handoff_egress(&key->egress);
}

enum outgoing_trace_claim_option : u64 {
    k_outgoing_trace_claim_req_type_shift = 32,
    k_outgoing_trace_claim_require_unconsumed = 1ULL << 40,
    k_outgoing_trace_claim_require_current_incarnation = 1ULL << 41,
};

static __always_inline u64 outgoing_trace_claim_options(u32 pid,
                                                        u8 req_type,
                                                        u8 require_unconsumed,
                                                        u8 require_current_incarnation) {
    return (u64)pid | ((u64)req_type << k_outgoing_trace_claim_req_type_shift) |
           (require_unconsumed ? k_outgoing_trace_claim_require_unconsumed : 0) |
           (require_current_incarnation ? k_outgoing_trace_claim_require_current_incarnation : 0);
}

static __noinline __attribute__((unused)) u8
claim_outgoing_trace_handoff_impl(const egress_key_t *egress,
                                  const outgoing_trace_token_t *token,
                                  const tp_info_pid_t *expected,
                                  u64 options,
                                  tp_info_pid_t *snapshot) {
    if (!egress || !outgoing_trace_token_valid(token)) {
        return 0;
    }

    const u32 pid = (u32)options;
    const u8 req_type = (u8)(options >> k_outgoing_trace_claim_req_type_shift);
    const outgoing_trace_handoff_key_t key = outgoing_trace_handoff_key(egress, token);
    if (!claim_outgoing_trace_handoff_key(&key)) {
        return 0;
    }

    outgoing_trace_handoff_t *handoff = lookup_outgoing_trace_handoff_exact(&key);
    if (!outgoing_trace_handoff_matches(
            handoff,
            &key,
            pid,
            req_type,
            expected,
            !!(options & k_outgoing_trace_claim_require_current_incarnation)) ||
        !outgoing_trace_handoff_authorizable(handoff) ||
        ((options & k_outgoing_trace_claim_require_unconsumed) && handoff->local_consumed)) {
        release_outgoing_trace_handoff_key(&key);
        return 0;
    }

    if (snapshot) {
        *snapshot = handoff->tp;
    }
    return 1;
}

static __always_inline u8 claim_outgoing_trace_handoff(const egress_key_t *egress,
                                                       const outgoing_trace_token_t *token,
                                                       u32 pid,
                                                       u8 req_type,
                                                       const tp_info_pid_t *expected,
                                                       u8 require_unconsumed,
                                                       u8 require_current_incarnation,
                                                       tp_info_pid_t *snapshot) {
    return claim_outgoing_trace_handoff_impl(
        egress,
        token,
        expected,
        outgoing_trace_claim_options(
            pid, req_type, require_unconsumed, require_current_incarnation),
        snapshot);
}

static __always_inline u8 current_outgoing_trace_handoff_token(const egress_key_t *egress,
                                                               outgoing_trace_token_t *token) {
    const outgoing_trace_token_t *current =
        bpf_map_lookup_elem(&outgoing_trace_handoff_locators, egress);
    if (!current || !outgoing_trace_token_valid(current) || !token) {
        return 0;
    }
    *token = *current;
    return 1;
}

enum outgoing_trace_resolution : u8 {
    k_outgoing_trace_absent,
    k_outgoing_trace_exact,
    k_outgoing_trace_fail_closed,
};

// A snapshot never authorizes mutation. Callers must acquire the exact action
// claim immediately before touching wire bytes or publishing local state.
static __noinline __attribute__((unused)) u8
snapshot_outgoing_trace_handoff_impl(const egress_key_t *egress,
                                     const outgoing_trace_token_t *token,
                                     u64 options,
                                     tp_info_pid_t *snapshot,
                                     u8 *local_consumed) {
    if (!egress || !snapshot || !outgoing_trace_token_valid(token)) {
        return 0;
    }
    const u32 pid = (u32)options;
    const u8 req_type = (u8)(options >> k_outgoing_trace_claim_req_type_shift);
    const outgoing_trace_handoff_key_t key = outgoing_trace_handoff_key(egress, token);
    const outgoing_trace_handoff_t *handoff = lookup_outgoing_trace_handoff_exact(&key);
    if (!outgoing_trace_handoff_matches(
            handoff,
            &key,
            pid,
            req_type,
            NULL,
            !!(options & k_outgoing_trace_claim_require_current_incarnation)) ||
        !outgoing_trace_handoff_authorizable(handoff)) {
        return 0;
    }
    *snapshot = handoff->tp;
    if (local_consumed) {
        *local_consumed = handoff->local_consumed;
    }
    return 1;
}

static __always_inline u8 snapshot_outgoing_trace_handoff(const egress_key_t *egress,
                                                          const outgoing_trace_token_t *token,
                                                          u32 pid,
                                                          u8 req_type,
                                                          u8 require_current_incarnation,
                                                          tp_info_pid_t *snapshot,
                                                          u8 *local_consumed) {
    return snapshot_outgoing_trace_handoff_impl(
        egress,
        token,
        outgoing_trace_claim_options(pid, req_type, 0, require_current_incarnation),
        snapshot,
        local_consumed);
}

static __noinline __attribute__((unused)) u8
resolve_current_outgoing_trace_handoff_impl(const egress_key_t *egress,
                                            u64 options,
                                            outgoing_trace_token_t *token,
                                            tp_info_pid_t *snapshot,
                                            u8 *local_consumed) {
    outgoing_trace_token_t current = {};
    if (!current_outgoing_trace_handoff_token(egress, &current)) {
        return k_outgoing_trace_absent;
    }
    if (!snapshot_outgoing_trace_handoff_impl(
            egress, &current, options, snapshot, local_consumed)) {
        return k_outgoing_trace_fail_closed;
    }
    if (token) {
        *token = current;
    }
    return k_outgoing_trace_exact;
}

static __always_inline u8 resolve_current_outgoing_trace_handoff(const egress_key_t *egress,
                                                                 u32 pid,
                                                                 u8 req_type,
                                                                 u8 require_current_incarnation,
                                                                 outgoing_trace_token_t *token,
                                                                 tp_info_pid_t *snapshot,
                                                                 u8 *local_consumed) {
    return resolve_current_outgoing_trace_handoff_impl(
        egress,
        outgoing_trace_claim_options(pid, req_type, 0, require_current_incarnation),
        token,
        snapshot,
        local_consumed);
}

static __always_inline u8 snapshot_current_outgoing_trace_handoff(const egress_key_t *egress,
                                                                  u32 pid,
                                                                  u8 req_type,
                                                                  u8 require_current_incarnation,
                                                                  outgoing_trace_token_t *token,
                                                                  tp_info_pid_t *snapshot,
                                                                  u8 *local_consumed) {
    return resolve_current_outgoing_trace_handoff(egress,
                                                  pid,
                                                  req_type,
                                                  require_current_incarnation,
                                                  token,
                                                  snapshot,
                                                  local_consumed) == k_outgoing_trace_exact;
}

static __noinline __attribute__((unused)) u8
resolve_and_claim_current_outgoing_trace_handoff_impl(const egress_key_t *egress,
                                                      const tp_info_pid_t *expected,
                                                      u64 options,
                                                      outgoing_trace_token_t *token,
                                                      tp_info_pid_t *snapshot) {
    const outgoing_trace_token_t *located =
        bpf_map_lookup_elem(&outgoing_trace_handoff_locators, egress);
    if (!located) {
        return k_outgoing_trace_absent;
    }
    if (!outgoing_trace_token_valid(located)) {
        return k_outgoing_trace_fail_closed;
    }
    const outgoing_trace_token_t current = *located;
    if (!claim_outgoing_trace_handoff_impl(egress, &current, expected, options, snapshot)) {
        return k_outgoing_trace_fail_closed;
    }
    if (token) {
        *token = current;
    }
    return k_outgoing_trace_exact;
}

static __always_inline u8
resolve_and_claim_current_outgoing_trace_handoff(const egress_key_t *egress,
                                                 u32 pid,
                                                 u8 req_type,
                                                 const tp_info_pid_t *expected,
                                                 u8 require_unconsumed,
                                                 u8 require_current_incarnation,
                                                 outgoing_trace_token_t *token,
                                                 tp_info_pid_t *snapshot) {
    return resolve_and_claim_current_outgoing_trace_handoff_impl(
        egress,
        expected,
        outgoing_trace_claim_options(
            pid, req_type, require_unconsumed, require_current_incarnation),
        token,
        snapshot);
}

static __always_inline u8 claim_current_outgoing_trace_handoff(const egress_key_t *egress,
                                                               u32 pid,
                                                               u8 req_type,
                                                               const tp_info_pid_t *expected,
                                                               u8 require_unconsumed,
                                                               u8 require_current_incarnation,
                                                               outgoing_trace_token_t *token,
                                                               tp_info_pid_t *snapshot) {
    return resolve_and_claim_current_outgoing_trace_handoff(egress,
                                                            pid,
                                                            req_type,
                                                            expected,
                                                            require_unconsumed,
                                                            require_current_incarnation,
                                                            token,
                                                            snapshot) == k_outgoing_trace_exact;
}

static __noinline __attribute__((unused)) void
finish_claimed_outgoing_trace_handoff(const egress_key_t *egress,
                                      const outgoing_trace_token_t *token,
                                      u8 mark_written,
                                      u8 mark_consumed) {
    if (!egress || !outgoing_trace_token_valid(token)) {
        return;
    }
    const outgoing_trace_handoff_key_t key = outgoing_trace_handoff_key(egress, token);
    outgoing_trace_handoff_t *handoff = lookup_outgoing_trace_handoff_exact(&key);
    if (!handoff) {
        release_outgoing_trace_handoff_key(&key);
        return;
    }

    if (mark_written) {
        handoff->tp.written = k_outbound_trace_written;
        handoff->last_progress = bpf_ktime_get_ns();
    }
    if (mark_consumed) {
        handoff->local_consumed = 1;
        handoff->last_progress = bpf_ktime_get_ns();
    }

    // Reclaim capacity as soon as both sides are durable. A deferred cleanup
    // request is also serviced as the claim owner's final action.
    if (handoff->tp.written == k_outbound_trace_written && handoff->local_consumed) {
        handoff->terminal_at = bpf_ktime_get_ns();
        handoff->terminal_reason = k_outgoing_trace_terminal_durable;
    }
    if (handoff->retire_requested ||
        (handoff->tp.written == k_outbound_trace_written && handoff->local_consumed)) {
        retire_claimed_outgoing_trace_handoff(&key);
    }
    release_outgoing_trace_handoff_key(&key);
}

static __always_inline void
release_claimed_outgoing_trace_handoff(const egress_key_t *egress,
                                       const outgoing_trace_token_t *token) {
    finish_claimed_outgoing_trace_handoff(egress, token, 0, 0);
}

static __always_inline void
commit_claimed_outgoing_trace_handoff(const egress_key_t *egress,
                                      const outgoing_trace_token_t *token) {
    finish_claimed_outgoing_trace_handoff(egress, token, 1, 0);
}

static __always_inline void
consume_claimed_outgoing_trace_handoff(const egress_key_t *egress,
                                       const outgoing_trace_token_t *token) {
    finish_claimed_outgoing_trace_handoff(egress, token, 0, 1);
}

// The exact action claim and the egress claim must be held. This variant lets a
// consumer make its durable local publication and exact-authority retirement
// one serialized operation.
static __noinline __attribute__((unused)) void
consume_claimed_outgoing_trace_handoff_egress_held(const egress_key_t *egress,
                                                   const outgoing_trace_token_t *token) {
    if (!egress || !outgoing_trace_token_valid(token)) {
        return;
    }

    const outgoing_trace_handoff_key_t key = outgoing_trace_handoff_key(egress, token);
    outgoing_trace_handoff_t *handoff = lookup_outgoing_trace_handoff_exact(&key);
    if (!handoff) {
        release_outgoing_trace_handoff_key(&key);
        return;
    }

    handoff->local_consumed = 1;
    handoff->last_progress = bpf_ktime_get_ns();
    if (handoff->tp.written == k_outbound_trace_written) {
        handoff->terminal_at = bpf_ktime_get_ns();
        handoff->terminal_reason = k_outgoing_trace_terminal_durable;
    }
    if (handoff->retire_requested ||
        (handoff->tp.written == k_outbound_trace_written && handoff->local_consumed)) {
        retire_claimed_outgoing_trace_handoff_egress_held(&key);
    }
    release_outgoing_trace_handoff_key(&key);
}

static __noinline __attribute__((unused)) void
request_outgoing_trace_handoff_retirement(const egress_key_t *egress,
                                          const outgoing_trace_token_t *token,
                                          const tp_info_pid_t *expected,
                                          u8 pending_only) {
    if (!egress || !outgoing_trace_token_valid(token)) {
        return;
    }
    const outgoing_trace_handoff_key_t key = outgoing_trace_handoff_key(egress, token);

    if (claim_outgoing_trace_handoff_key(&key)) {
        outgoing_trace_handoff_t *handoff = lookup_outgoing_trace_handoff_exact(&key);
        if (outgoing_trace_handoff_matches(
                handoff, &key, egress->pid, EVENT_HTTP_CLIENT, expected, 0) &&
            (!pending_only || handoff->tp.written == k_outbound_trace_pending)) {
            handoff->terminal_at = bpf_ktime_get_ns();
            handoff->terminal_reason = k_outgoing_trace_terminal_owner_cleanup;
            retire_claimed_outgoing_trace_handoff(&key);
        }
        release_outgoing_trace_handoff_key(&key);
        return;
    }

    // A writer/consumer owns the exact claim. Request deferred retirement,
    // then retry once to close the owner-check/loser-store race.
    outgoing_trace_handoff_t *handoff = lookup_outgoing_trace_handoff_exact(&key);
    if (outgoing_trace_handoff_matches(
            handoff, &key, egress->pid, EVENT_HTTP_CLIENT, expected, 0) &&
        (!pending_only || handoff->tp.written == k_outbound_trace_pending)) {
        handoff->retire_requested = 1;
        handoff->terminal_at = bpf_ktime_get_ns();
        handoff->terminal_reason = k_outgoing_trace_terminal_owner_cleanup;
    }

    if (claim_outgoing_trace_handoff_key(&key)) {
        handoff = lookup_outgoing_trace_handoff_exact(&key);
        if (handoff && handoff->retire_requested &&
            outgoing_trace_handoff_matches(
                handoff, &key, egress->pid, EVENT_HTTP_CLIENT, expected, 0) &&
            (!pending_only || handoff->tp.written == k_outbound_trace_pending)) {
            retire_claimed_outgoing_trace_handoff(&key);
        }
        release_outgoing_trace_handoff_key(&key);
    }
}

static __always_inline void cleanup_outgoing_trace_handoff_token(
    const egress_key_t *egress, u32 pid, u8 req_type, const outgoing_trace_token_t *token) {
    if (!egress || pid != egress->pid || req_type != EVENT_HTTP_CLIENT) {
        return;
    }
    request_outgoing_trace_handoff_retirement(egress, token, NULL, 0);
}

static __always_inline void mirror_outgoing_trace_handoff_commit(const egress_key_t *e_key,
                                                                 const tp_info_pid_t *expected) {
    tp_info_pid_t *current = bpf_map_lookup_elem(&outgoing_trace_map, e_key);
    if (current && current->valid && current->written == k_outbound_trace_pending &&
        outgoing_trace_identity_matches(current, expected)) {
        current->written = k_outbound_trace_written;
    }
}

static __always_inline u8 adopt_outgoing_trace_handoff(tp_info_t *tp,
                                                       const tp_info_pid_t *snapshot) {
    if (!tp || !snapshot || !snapshot->valid || snapshot->written > k_outbound_trace_written) {
        return 0;
    }
    *tp = snapshot->tp;
    return 1;
}
