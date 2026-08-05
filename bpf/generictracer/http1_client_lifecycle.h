// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

enum http1_client_handoff_state : u8 {
    k_http1_client_handoff_none,
    k_http1_client_handoff_wire,
    k_http1_client_handoff_pending_initial,
    k_http1_client_handoff_pending_wire,
    k_http1_client_handoff_exact,
    k_http1_client_handoff_fail_closed,
};

enum http1_client_pending_resolution : u8 {
    k_http1_client_pending_wait,
    k_http1_client_pending_exact,
    k_http1_client_pending_fail_closed,
};

static __always_inline u8 http1_client_handoff_is_pending(u8 state) {
    return state == k_http1_client_handoff_pending_initial ||
           state == k_http1_client_handoff_pending_wire;
}

static __always_inline u8 http1_client_handoff_has_wire_candidate(u8 state) {
    return state == k_http1_client_handoff_wire || state == k_http1_client_handoff_pending_wire;
}

static __always_inline u8 http1_client_handoff_suppresses_event(u8 state) {
    return http1_client_handoff_is_pending(state) || state == k_http1_client_handoff_fail_closed;
}

static __always_inline enum http1_client_pending_resolution http1_client_resolve_pending(
    u8 state, u8 exact_claimed, u8 authority_written, u8 wire_matches, u8 terminal) {
    if (!http1_client_handoff_is_pending(state)) {
        return k_http1_client_pending_exact;
    }
    if (exact_claimed && authority_written &&
        (state != k_http1_client_handoff_pending_wire || wire_matches)) {
        return k_http1_client_pending_exact;
    }
    if ((exact_claimed && authority_written && state == k_http1_client_handoff_pending_wire &&
         !wire_matches) ||
        terminal) {
        return k_http1_client_pending_fail_closed;
    }
    return k_http1_client_pending_wait;
}

static __always_inline u8 http1_client_request_generation_matches(u64 expected_start_monotime_ns,
                                                                  u64 current_start_monotime_ns) {
    return expected_start_monotime_ns && expected_start_monotime_ns == current_start_monotime_ns;
}
