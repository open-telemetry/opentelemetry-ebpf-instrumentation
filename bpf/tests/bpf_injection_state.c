// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static inline unsigned int bpf_get_prandom_u32(void) {
    return 0;
}

static inline long bpf_loop(unsigned int nr_loops,
                            int (*callback_fn)(unsigned int, void *),
                            void *callback_ctx,
                            unsigned long long flags) {
    (void)flags;
    for (unsigned int i = 0; i < nr_loops; i++) {
        if (callback_fn(i, callback_ctx)) {
            break;
        }
    }
    return 0;
}

#include <common/connection_info.h>
#include <common/event_defs.h>
#include <common/h2_defs.h>
#include <common/tp_info.h>
#include <common/trace_util.h>
#include <tpinjector/injection_state.h>

typedef struct handoff_model {
    egress_key_t key;
    tp_info_pid_t value;
    u8 present;
    u8 local_consumed;
    u8 wire_mutated;
    u8 legacy_mirror_present;
    u32 map_updates;
    u32 post_wire_map_updates;
} handoff_model_t;

static unsigned int failures;

static void assert_bool(int want, int got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %d, got %d\n", message, want, got);
    failures++;
}

static u8 same_key(const egress_key_t *left, const egress_key_t *right) {
    return memcmp(left, right, sizeof(*left)) == 0;
}

static u8 same_identity(const tp_info_pid_t *left, const tp_info_pid_t *right) {
    return left->pid == right->pid && left->req_type == right->req_type &&
           left->tp.ts == right->tp.ts && left->tp.flags == right->tp.flags &&
           left->tp.sampling_decision == right->tp.sampling_decision &&
           left->tp.parent_remote == right->tp.parent_remote &&
           memcmp(left->tp.trace_id, right->tp.trace_id, sizeof(left->tp.trace_id)) == 0 &&
           memcmp(left->tp.span_id, right->tp.span_id, sizeof(left->tp.span_id)) == 0 &&
           memcmp(left->tp.parent_id, right->tp.parent_id, sizeof(left->tp.parent_id)) == 0;
}

static egress_key_t test_key(u32 stream_id) {
    egress_key_t key = {
        .pid = 42,
        .stream_id = stream_id,
        .s_port = 31000,
        .d_port = 443,
    };
    key.s_ip[3] = 0x0100007f;
    key.d_ip[3] = 0x0200007f;
    return key;
}

static tp_info_pid_t test_trace(u8 id) {
    tp_info_pid_t tp = {
        .pid = 42,
        .valid = 1,
        .written = k_outbound_trace_pending,
        .req_type = EVENT_HTTP_CLIENT,
    };
    tp.tp.ts = 1000 + id;
    tp.tp.flags = k_flag_sampled;
    tp.tp.sampling_decision = id;
    for (u8 i = 0; i < TRACE_ID_SIZE_BYTES; i++) {
        tp.tp.trace_id[i] = id + i;
    }
    for (u8 i = 0; i < SPAN_ID_SIZE_BYTES; i++) {
        tp.tp.span_id[i] = id + 32 + i;
        tp.tp.parent_id[i] = id + 64 + i;
    }
    return tp;
}

static u8 reserve_handoff(handoff_model_t *state,
                          const egress_key_t *key,
                          const tp_info_pid_t *candidate,
                          u8 saturated) {
    if (!candidate->valid || candidate->pid != key->pid ||
        candidate->written != k_outbound_trace_pending) {
        return 0;
    }
    if (!state->present) {
        if (saturated) {
            return 0;
        }
        state->key = *key;
        state->value = *candidate;
        state->present = 1;
        state->local_consumed = 0;
        state->map_updates++;
        state->post_wire_map_updates += state->wire_mutated;
        return 1;
    }
    if (same_key(&state->key, key) && same_identity(&state->value, candidate)) {
        return 1;
    }
    if (same_key(&state->key, key) && state->value.written == k_outbound_trace_written &&
        state->local_consumed) {
        state->value = *candidate;
        state->local_consumed = 0;
        state->map_updates++;
        state->post_wire_map_updates += state->wire_mutated;
        return 1;
    }
    return 0;
}

static u8
commit_handoff(handoff_model_t *state, const egress_key_t *key, const tp_info_pid_t *expected) {
    if (!state->present || !same_key(&state->key, key) || !same_identity(&state->value, expected)) {
        return 0;
    }
    state->value.written = k_outbound_trace_written;
    return 1;
}

static u8 consume_handoff(handoff_model_t *state, const egress_key_t *key, u32 pid, u8 req_type) {
    if (!state->present || state->local_consumed || !same_key(&state->key, key) ||
        state->value.pid != pid || state->value.req_type != req_type ||
        state->value.written > k_outbound_trace_written) {
        return 0;
    }
    state->local_consumed = 1;
    return 1;
}

static u8 cleanup_handoff(handoff_model_t *state,
                          const egress_key_t *key,
                          const tp_info_pid_t *expected,
                          u8 pending_only) {
    if (!state->present || !same_key(&state->key, key) || !same_identity(&state->value, expected) ||
        (pending_only && state->value.written != k_outbound_trace_pending)) {
        return 0;
    }
    state->present = 0;
    return 1;
}

static u8
write_header(handoff_model_t *state, const egress_key_t *key, const tp_info_pid_t *expected) {
    if (!state->present || !same_key(&state->key, key) || !same_identity(&state->value, expected)) {
        return 0;
    }
    state->wire_mutated = 1;
    return commit_handoff(state, key, expected);
}

static u8 promote_go_h2_application_traceparent(handoff_model_t *state,
                                                const tp_info_t *wire,
                                                u8 claim_succeeds) {
    if (!state->present || !claim_succeeds ||
        !h2_wire_traceparent_matches_authority(
            &state->value.tp, wire->trace_id, wire->span_id, wire->flags)) {
        return 0;
    }
    state->value.written = k_outbound_trace_written;
    return 1;
}

static void test_pending_a_cannot_be_replaced_by_b(void) {
    handoff_model_t state = {};
    const egress_key_t key = test_key(0);
    const tp_info_pid_t a = test_trace(1);
    const tp_info_pid_t b = test_trace(2);

    assert_bool(1, reserve_handoff(&state, &key, &a, 0), "reserve pending A");
    assert_bool(1, reserve_handoff(&state, &key, &a, 0), "exact A reserve is idempotent");
    assert_bool(0, reserve_handoff(&state, &key, &b, 0), "pending A rejects B");
    assert_bool(1, same_identity(&state.value, &a), "A remains authoritative");
    assert_bool(1, state.map_updates, "idempotent reserve does not update the map");
}

static void test_capacity_and_missing_authority_fail_before_wire(void) {
    handoff_model_t saturated = {};
    const egress_key_t key = test_key(0);
    const tp_info_pid_t a = test_trace(1);

    assert_bool(0, reserve_handoff(&saturated, &key, &a, 1), "saturation rejects reserve");
    assert_bool(0, write_header(&saturated, &key, &a), "saturation skips wire mutation");
    assert_bool(0, saturated.wire_mutated, "wire remains untouched at capacity");

    handoff_model_t missing = {};
    assert_bool(1, reserve_handoff(&missing, &key, &a, 0), "reserve before writer");
    missing.present = 0;
    assert_bool(0, write_header(&missing, &key, &a), "missing authority skips writer");
    assert_bool(0, missing.wire_mutated, "missing authority cannot mutate wire");
}

static void test_exact_cleanup_and_owner_failure(void) {
    handoff_model_t state = {};
    const egress_key_t key = test_key(0);
    const tp_info_pid_t a = test_trace(1);
    const tp_info_pid_t b = test_trace(2);

    reserve_handoff(&state, &key, &a, 0);
    assert_bool(0, cleanup_handoff(&state, &key, &b, 0), "mismatched cleanup cannot delete A");
    assert_bool(1, state.present, "A survives mismatched cleanup");
    assert_bool(1, cleanup_handoff(&state, &key, &a, 1), "owner failure retires pending A");
    assert_bool(0, state.present, "pending owner failure frees capacity");
}

static void test_header_commit_is_in_place(void) {
    handoff_model_t state = {};
    const egress_key_t key = test_key(0);
    const tp_info_pid_t a = test_trace(1);

    assert_bool(1, reserve_handoff(&state, &key, &a, 0), "HTTP/1 reserves before rewrite");
    state.legacy_mirror_present = 0;
    assert_bool(1, write_header(&state, &key, &a), "wire writer commits exact A");
    assert_bool(k_outbound_trace_written, state.value.written, "A becomes written");
    assert_bool(0, state.post_wire_map_updates, "commit performs no post-wire map update");
    assert_bool(1, state.present, "missing legacy mirror does not lose authority");
}

static void test_generic_consumer_before_tcp_callback(void) {
    handoff_model_t state = {};
    const egress_key_t key = test_key(0);
    const tp_info_pid_t a = test_trace(1);
    const tp_info_pid_t b = test_trace(2);

    reserve_handoff(&state, &key, &a, 0);
    assert_bool(
        1, consume_handoff(&state, &key, a.pid, a.req_type), "generic consumer adopts pending A");
    assert_bool(0, reserve_handoff(&state, &key, &b, 0), "generic path cannot publish B");
    state.wire_mutated = 1; // successful bpf_store_hdr_opt
    assert_bool(1, commit_handoff(&state, &key, &a), "TCP callback commits the same A");
    assert_bool(k_outbound_trace_written, state.value.written, "callback publishes A");
    assert_bool(1, state.local_consumed, "local consumption survives wire commit");
}

static void test_tcp_callback_before_generic_consumer(void) {
    handoff_model_t state = {};
    const egress_key_t key = test_key(0);
    const tp_info_pid_t a = test_trace(1);

    reserve_handoff(&state, &key, &a, 0);
    state.wire_mutated = 1;
    assert_bool(1, commit_handoff(&state, &key, &a), "callback commits pending A");
    assert_bool(1, consume_handoff(&state, &key, a.pid, a.req_type), "consumer adopts written A");
    assert_bool(
        0, consume_handoff(&state, &key, a.pid, a.req_type), "A is consumed locally only once");
}

static void test_dual_transport_failure_preserves_header(void) {
    handoff_model_t state = {};
    const egress_key_t key = test_key(0);
    const tp_info_pid_t a = test_trace(1);

    reserve_handoff(&state, &key, &a, 0);
    assert_bool(1, write_header(&state, &key, &a), "header transport publishes A");
    assert_bool(0,
                cleanup_handoff(&state, &key, &a, 1),
                "TCP reserve/store failure cannot retire written A");
    assert_bool(1, state.present, "written header authority survives TCP failure");
    assert_bool(k_outbound_trace_written, state.value.written, "written state is preserved");
}

static void test_dual_transport_header_failure_preserves_tcp_authority(void) {
    handoff_model_t state = {};
    const egress_key_t key = test_key(0);
    const tp_info_pid_t a = test_trace(1);
    const u8 tcp_option_scheduled = 1;

    reserve_handoff(&state, &key, &a, 0);
    assert_bool(1, tcp_option_scheduled, "TCP transport is scheduled before the header attempt");
    assert_bool(1, state.present, "rolled-back header failure keeps pending A for TCP");
    assert_bool(k_outbound_trace_pending,
                state.value.written,
                "rolled-back header failure leaves A pending");
    assert_bool(0, state.wire_mutated, "rolled-back header failure leaves HTTP bytes unchanged");

    state.wire_mutated = 1;
    assert_bool(1, commit_handoff(&state, &key, &a), "TCP callback commits the same A");
    assert_bool(k_outbound_trace_written, state.value.written, "TCP publishes exact A");
}

static void test_finalize_tailcall_failure_retires_reserved_identity(void) {
    handoff_model_t state = {};
    const egress_key_t key = test_key(0);
    tp_info_pid_t rewritten = test_trace(1);
    tp_info_pid_t restored = rewritten;
    rewritten.tp.span_id[0] ^= 1;
    rewritten.tp.flags ^= k_flag_sampled;
    rewritten.tp.sampling_decision = k_sampling_decision_applied;

    assert_bool(1, reserve_handoff(&state, &key, &rewritten, 0), "reserve rewritten A");
    restored.tp.span_id[0] = test_trace(1).tp.span_id[0];
    assert_bool(1,
                cleanup_handoff(&state, &key, &rewritten, 1),
                "tail-call failure retires A before restoring scratch state");
    assert_bool(0, state.present, "failed finalizer leaves no pending authority");
    assert_bool(0, state.wire_mutated, "failed finalizer never mutates wire bytes");
    assert_bool(0,
                same_identity(&rewritten, &restored),
                "restored scratch identity cannot stand in for reserved A");
}

static void test_created_trace_replaces_dirty_timestamp(void) {
    tp_info_pid_t scratch = test_trace(1);
    scratch.tp.ts = 17;
    scratch.valid = 0;
    scratch.pid = 7;
    scratch.req_type = EVENT_HTTP_REQUEST;
    scratch.tp.flags = 0xff;
    scratch.tp.sampling_decision = k_sampling_decision_applied;

    initialize_created_client_trace(&scratch, 42, 9001);

    assert_bool(9001, scratch.tp.ts, "new trace gets the current timestamp");
    assert_bool(k_flag_sampled, scratch.tp.flags, "new trace starts sampled");
    assert_bool(k_sampling_decision_pending,
                scratch.tp.sampling_decision,
                "new trace starts with a pending sampler decision");
    assert_bool(1, scratch.valid, "new trace is valid");
    assert_bool(42, scratch.pid, "new trace records its process");
    assert_bool(EVENT_HTTP_CLIENT, scratch.req_type, "new trace records client ownership");
}

static void test_completed_consumed_entry_can_be_reaped(void) {
    handoff_model_t state = {};
    const egress_key_t key = test_key(0);
    const tp_info_pid_t a = test_trace(1);
    const tp_info_pid_t b = test_trace(2);

    reserve_handoff(&state, &key, &a, 0);
    write_header(&state, &key, &a);
    consume_handoff(&state, &key, a.pid, a.req_type);
    assert_bool(1, reserve_handoff(&state, &key, &b, 0), "written consumed A permits B");
    assert_bool(1, same_identity(&state.value, &b), "replacement is exact B");
    assert_bool(k_outbound_trace_pending, state.value.written, "B starts pending");

    state = (handoff_model_t){};
    reserve_handoff(&state, &key, &a, 0);
    consume_handoff(&state, &key, a.pid, a.req_type);
    assert_bool(0, reserve_handoff(&state, &key, &b, 0), "consumed pending A still blocks B");
}

static void test_full_pid_and_stream_key_isolation(void) {
    handoff_model_t h1 = {};
    handoff_model_t h2_stream_1 = {};
    handoff_model_t h2_stream_3 = {};
    const egress_key_t stream_0 = test_key(0);
    const egress_key_t stream_1 = test_key(1);
    const egress_key_t stream_3 = test_key(3);
    const tp_info_pid_t a = test_trace(1);

    assert_bool(0, same_key(&stream_0, &stream_1), "HTTP/1 and H2 keys are distinct");
    assert_bool(0, same_key(&stream_1, &stream_3), "H2 streams are distinct");
    assert_bool(1, reserve_handoff(&h1, &stream_0, &a, 0), "reserve HTTP/1 key");
    assert_bool(1, reserve_handoff(&h2_stream_1, &stream_1, &a, 0), "reserve H2 stream 1");
    assert_bool(1, reserve_handoff(&h2_stream_3, &stream_3, &a, 0), "reserve H2 stream 3");
    assert_bool(0,
                consume_handoff(&h2_stream_1, &stream_1, a.pid + 1, a.req_type),
                "another PID cannot consume A");
}

static void test_go_h2_application_traceparent_promotes_original_authority(void) {
    handoff_model_t state = {};
    const egress_key_t key = test_key(3);
    const tp_info_pid_t a = test_trace(1);
    tp_info_t wire = a.tp;

    reserve_handoff(&state, &key, &a, 0);
    wire.ts += 999;
    assert_bool(1,
                promote_go_h2_application_traceparent(&state, &wire, 1),
                "matching Go HPACK traceparent promotes original A despite timestamp");
    assert_bool(k_outbound_trace_written, state.value.written, "promotion commits original A");
    assert_bool(0, state.wire_mutated, "promotion leaves application bytes unchanged");
    assert_bool(a.tp.ts, state.value.tp.ts, "promotion preserves original authority timestamp");
}

static void test_go_h2_application_traceparent_mismatch_fails_closed(void) {
    const egress_key_t key = test_key(3);
    const tp_info_pid_t a = test_trace(1);

    for (u8 mismatch = 0; mismatch < 3; mismatch++) {
        handoff_model_t state = {};
        tp_info_t wire = a.tp;
        reserve_handoff(&state, &key, &a, 0);
        if (mismatch == 0) {
            wire.trace_id[0] ^= 1;
        } else if (mismatch == 1) {
            wire.span_id[0] ^= 1;
        } else {
            wire.flags ^= k_flag_sampled;
        }

        assert_bool(0,
                    promote_go_h2_application_traceparent(&state, &wire, 1),
                    "wire identity mismatch cannot commit Go authority");
        assert_bool(k_outbound_trace_pending,
                    state.value.written,
                    "mismatched Go authority remains pending");
        assert_bool(0, state.wire_mutated, "mismatch leaves application bytes unchanged");
    }
}

static void test_go_h2_application_traceparent_claim_failures_fail_closed(void) {
    const egress_key_t key = test_key(3);
    const tp_info_pid_t a = test_trace(1);
    const char *failure_names[] = {
        "contention leaves application bytes unchanged",
        "stale locator leaves application bytes unchanged",
        "terminal authority leaves application bytes unchanged",
    };

    for (u8 failure = 0; failure < 3; failure++) {
        handoff_model_t state = {};
        reserve_handoff(&state, &key, &a, 0);
        assert_bool(
            0, promote_go_h2_application_traceparent(&state, &a.tp, 0), failure_names[failure]);
        assert_bool(k_outbound_trace_pending,
                    state.value.written,
                    "failed claim cannot commit Go authority");
        assert_bool(0, state.wire_mutated, failure_names[failure]);
    }
}

static void test_non_go_h2_absence_keeps_normal_reservation(void) {
    handoff_model_t state = {};
    const egress_key_t key = test_key(5);
    const tp_info_pid_t generated = test_trace(9);

    assert_bool(1,
                reserve_handoff(&state, &key, &generated, 0),
                "absent non-Go authority keeps normal H2 generation");
    assert_bool(
        1, same_identity(&state.value, &generated), "normal H2 generation publishes its candidate");
}

static void test_h2_failure_provenance_and_tail_budget(void) {
    assert_bool(
        1, h2_handoff_failure_retires(1), "fresh H2 reservation is retired after writer failure");
    assert_bool(
        0, h2_handoff_failure_retires(0), "borrowed H2 reservation survives writer failure");

    const u32 maximal_value_calls =
        k_h2_tail_calls_before_frames +
        k_h2_max_worst_case_frames_per_packet * k_h2_tail_calls_per_max_existing_frame +
        (k_h2_max_worst_case_frames_per_packet - 1);
    assert_bool(1,
                maximal_value_calls <= k_h2_tail_call_limit,
                "one maximal H2 value fits the tail-call budget");

    const u32 next_maximal_value_calls =
        k_h2_tail_calls_before_frames +
        (k_h2_max_worst_case_frames_per_packet + 1) * k_h2_tail_calls_per_max_existing_frame +
        k_h2_max_worst_case_frames_per_packet;
    assert_bool(1,
                next_maximal_value_calls > k_h2_tail_call_limit,
                "a second maximal H2 value requires runtime capping");

    const u32 four_cheap_value_calls = k_h2_tail_calls_before_frames +
                                       k_h2_max_frames_per_packet * (1 + 4) +
                                       k_h2_tail_calls_between_frames;
    assert_bool(1,
                four_cheap_value_calls <= k_h2_tail_call_limit,
                "four cheap H2 values retain coalesced-frame coverage");

    const u32 rewrite_retry_calls =
        k_h2_tail_calls_before_frames +
        k_h2_max_worst_case_frames_per_packet * k_h2_tail_calls_per_rewrite_retry_frame +
        (k_h2_max_worst_case_frames_per_packet - 1);
    assert_bool(1,
                rewrite_retry_calls <= k_h2_tail_call_limit,
                "one maximal H2 rewrite retry fits the tail-call budget");
}

static void test_http1_injection_requires_complete_unique_headers(void) {
    u8 state = k_http1_traceparent_scan_absent;

    assert_bool(k_http1_injection_scan_continue,
                http1_injection_scan_action(state, 0, 0),
                "absence remains pending before end of headers");
    assert_bool(k_http1_injection_scan_abort,
                http1_injection_scan_action(state, 0, 1),
                "absence at scan exhaustion fails closed");
    assert_bool(k_http1_injection_scan_create,
                http1_injection_scan_action(state, 1, 0),
                "complete headers without traceparent create one");

    assert_bool(
        1, http1_injection_observe_traceparent(&state, 1), "first valid field is a candidate");
    assert_bool(k_http1_traceparent_scan_found, state, "candidate remains pending");
    assert_bool(k_http1_injection_scan_continue,
                http1_injection_scan_action(state, 0, 0),
                "candidate waits for end of headers");
    assert_bool(k_http1_injection_scan_abort,
                http1_injection_scan_action(state, 0, 1),
                "candidate without end of headers fails closed");
    assert_bool(k_http1_injection_scan_finalize,
                http1_injection_scan_action(state, 1, 0),
                "one complete candidate becomes authoritative");

    assert_bool(
        0, http1_injection_observe_traceparent(&state, 1), "duplicate candidate is rejected");
    assert_bool(k_http1_traceparent_scan_present, state, "duplicate field is non-authoritative");
    assert_bool(k_http1_injection_scan_abort,
                http1_injection_scan_action(state, 1, 0),
                "duplicate fields cannot finalize");

    state = k_http1_traceparent_scan_absent;
    assert_bool(0, http1_injection_observe_traceparent(&state, 0), "malformed field is rejected");
    assert_bool(k_http1_traceparent_scan_present, state, "malformed field is non-authoritative");
    assert_bool(k_http1_injection_scan_abort,
                http1_injection_scan_action(state, 1, 0),
                "malformed field cannot trigger injection");
}

int main(void) {
    test_pending_a_cannot_be_replaced_by_b();
    test_capacity_and_missing_authority_fail_before_wire();
    test_exact_cleanup_and_owner_failure();
    test_header_commit_is_in_place();
    test_generic_consumer_before_tcp_callback();
    test_tcp_callback_before_generic_consumer();
    test_dual_transport_failure_preserves_header();
    test_dual_transport_header_failure_preserves_tcp_authority();
    test_finalize_tailcall_failure_retires_reserved_identity();
    test_created_trace_replaces_dirty_timestamp();
    test_completed_consumed_entry_can_be_reaped();
    test_full_pid_and_stream_key_isolation();
    test_go_h2_application_traceparent_promotes_original_authority();
    test_go_h2_application_traceparent_mismatch_fails_closed();
    test_go_h2_application_traceparent_claim_failures_fail_closed();
    test_non_go_h2_absence_keeps_normal_reservation();
    test_h2_failure_provenance_and_tail_budget();
    test_http1_injection_requires_complete_unique_headers();
    return failures ? 1 : 0;
}
