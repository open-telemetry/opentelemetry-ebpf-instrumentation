// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/event_defs.h>
#include <common/trace_util.h>

enum {
    k_traceparent_span_id_char_len = SPAN_ID_SIZE_BYTES * 2,
    k_traceparent_flags_char_len = 2,
    k_traceparent_span_flags_wire_len =
        k_traceparent_span_id_char_len + 1 + k_traceparent_flags_char_len,
};

static __always_inline void
write_traceparent_span_flags(unsigned char *wire, const unsigned char *span_id, const u8 flags) {
    encode_hex(wire, span_id, SPAN_ID_SIZE_BYTES);
    encode_traceparent_flags(wire + k_traceparent_span_id_char_len + 1, flags);
}

static __always_inline u8 h2_wire_traceparent_matches_authority(const tp_info_t *authority,
                                                                const unsigned char *wire_trace_id,
                                                                const unsigned char *wire_span_id,
                                                                u8 wire_flags) {
    return wire_traceparent_parts_match(authority, wire_trace_id, wire_span_id, wire_flags);
}

static __always_inline u8 h2_handoff_failure_retires(u8 fresh_reservation) {
    return !!fresh_reservation;
}

static __always_inline void
initialize_created_client_trace(tp_info_pid_t *tp_p, u32 pid, u64 timestamp) {
    tp_p->tp.ts = timestamp;
    tp_p->tp.flags = k_flag_sampled;
    reset_sampling_decision(&tp_p->tp);
    tp_p->valid = 1;
    tp_p->pid = pid;
    tp_p->req_type = EVENT_HTTP_CLIENT;
}

enum http1_injection_scan_action : u8 {
    k_http1_injection_scan_continue = 0,
    k_http1_injection_scan_abort,
    k_http1_injection_scan_create,
    k_http1_injection_scan_finalize,
};

static __always_inline u8 http1_injection_observe_traceparent(u8 *state, u8 valid) {
    if (!state) {
        return 0;
    }
    if (*state != k_http1_traceparent_scan_absent || !valid) {
        *state = k_http1_traceparent_scan_present;
        return 0;
    }
    *state = k_http1_traceparent_scan_found;
    return 1;
}

static __always_inline enum http1_injection_scan_action
http1_injection_scan_action(u8 state, u8 end_of_headers, u8 exhausted) {
    if (state == k_http1_traceparent_scan_present || state == k_http1_traceparent_scan_unknown) {
        return k_http1_injection_scan_abort;
    }
    if (!end_of_headers) {
        return exhausted ? k_http1_injection_scan_abort : k_http1_injection_scan_continue;
    }
    if (state == k_http1_traceparent_scan_found) {
        return k_http1_injection_scan_finalize;
    }
    if (state == k_http1_traceparent_scan_absent) {
        return k_http1_injection_scan_create;
    }
    return k_http1_injection_scan_abort;
}
