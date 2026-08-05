// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include <generictracer/http1_client_lifecycle.h>

enum trace_identity {
    trace_absent,
    trace_normal,
    trace_wire,
    trace_exact,
};

typedef struct http1_lifecycle_model {
    enum trace_identity ongoing;
    enum trace_identity support;
    enum trace_identity emitted;
    u8 handoff_state;
    u8 start_complete;
    u8 retirement_requested;
    u8 writer_released;
} http1_lifecycle_model_t;

static unsigned int failures;

static void assert_bool(int want, int got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %d, got %d\n", message, want, got);
    failures++;
}

static void assert_trace(enum trace_identity want, enum trace_identity got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %d, got %d\n", message, want, got);
    failures++;
}

static void start_normal(http1_lifecycle_model_t *model, u8 publication_available) {
    model->ongoing = trace_normal;
    model->handoff_state = k_http1_client_handoff_none;
    model->start_complete = 1;
    if (publication_available) {
        model->support = trace_normal;
    }
}

static void
start_exact(http1_lifecycle_model_t *model, u8 exact_claimed, u8 publication_available) {
    model->start_complete = 1;
    if (exact_claimed) {
        model->ongoing = trace_exact;
        model->handoff_state = k_http1_client_handoff_exact;
        if (publication_available) {
            model->support = trace_exact;
        }
        return;
    }
    model->handoff_state = k_http1_client_handoff_pending_initial;
}

static void capture_split(http1_lifecycle_model_t *model,
                          u8 exact_present,
                          u8 exact_claimed,
                          u8 wire_matches,
                          u8 publication_available) {
    model->support = trace_absent;
    model->ongoing = trace_wire;
    model->handoff_state =
        exact_present ? k_http1_client_handoff_pending_wire : k_http1_client_handoff_wire;
    if (!exact_present) {
        if (publication_available) {
            model->support = trace_wire;
        }
        return;
    }

    const enum http1_client_pending_resolution resolution = http1_client_resolve_pending(
        model->handoff_state, exact_claimed, exact_claimed, wire_matches, 0);
    if (resolution == k_http1_client_pending_exact) {
        model->ongoing = trace_exact;
        model->handoff_state = k_http1_client_handoff_exact;
        if (publication_available) {
            model->support = trace_exact;
        }
    } else if (resolution == k_http1_client_pending_fail_closed) {
        model->handoff_state = k_http1_client_handoff_fail_closed;
        model->retirement_requested = 1;
    }
}

static void
complete(http1_lifecycle_model_t *model, u8 exact_claimed, u8 authority_written, u8 wire_matches) {
    if (http1_client_handoff_is_pending(model->handoff_state)) {
        const enum http1_client_pending_resolution resolution = http1_client_resolve_pending(
            model->handoff_state, exact_claimed, authority_written, wire_matches, 1);
        if (resolution == k_http1_client_pending_exact) {
            model->ongoing = trace_exact;
            model->handoff_state = k_http1_client_handoff_exact;
        } else {
            model->handoff_state = k_http1_client_handoff_fail_closed;
            model->retirement_requested = 1;
        }
    }

    if (!http1_client_handoff_suppresses_event(model->handoff_state)) {
        model->emitted = model->ongoing;
    }
    model->support = trace_absent;
    model->ongoing = trace_absent;
}

static void release_writer(http1_lifecycle_model_t *model) {
    model->writer_released = 1;
    if (model->retirement_requested) {
        model->support = trace_absent;
    }
}

static void test_initial_publication_contention_retains_complete_start(void) {
    http1_lifecycle_model_t model = {};

    start_normal(&model, 0);
    assert_bool(1, model.start_complete, "publication contention retains a complete request start");
    assert_trace(trace_normal, model.ongoing, "normal request remains authoritative locally");

    complete(&model, 0, 0, 0);
    assert_trace(trace_normal, model.emitted, "retained normal request emits at terminal response");
}

static void test_deferred_initial_exact_resolution(void) {
    http1_lifecycle_model_t model = {};

    start_exact(&model, 0, 0);
    assert_bool(1,
                http1_client_handoff_is_pending(model.handoff_state),
                "writer-held exact generation remains retryable");
    complete(&model, 1, 1, 1);

    assert_trace(trace_exact, model.emitted, "terminal retry emits the exact generation once");
    assert_trace(trace_absent, model.ongoing, "terminal retry cleans ongoing state");
}

static void test_terminal_writer_contention_fails_closed(void) {
    http1_lifecycle_model_t model = {};

    start_exact(&model, 0, 0);
    complete(&model, 0, 0, 0);
    release_writer(&model);

    assert_trace(trace_absent, model.emitted, "unproven exact generation never emits fallback B");
    assert_bool(1, model.retirement_requested, "terminal contention requests exact retirement");
    assert_bool(1, model.writer_released, "writer release needs no later HTTP callback");
    assert_trace(trace_absent, model.support, "terminal contention leaves no support publication");
}

static void test_split_wire_survives_publication_contention(void) {
    http1_lifecycle_model_t model = {
        .ongoing = trace_normal,
        .support = trace_normal,
        .start_complete = 1,
    };

    capture_split(&model, 0, 0, 0, 0);
    assert_trace(trace_absent, model.support, "split capture removes provisional B support");
    assert_trace(trace_wire, model.ongoing, "wire candidate is durable without shared support");
    complete(&model, 0, 0, 0);
    assert_trace(trace_wire, model.emitted, "wire candidate emits despite publication contention");
}

static void test_split_exact_contention_later_validates(void) {
    http1_lifecycle_model_t model = {
        .ongoing = trace_normal,
        .support = trace_normal,
        .start_complete = 1,
    };

    capture_split(&model, 1, 0, 0, 0);
    complete(&model, 1, 1, 1);
    assert_trace(trace_exact, model.emitted, "terminal validation upgrades split A to exact");
}

static void test_split_exact_mismatch_suppresses(void) {
    http1_lifecycle_model_t model = {
        .ongoing = trace_normal,
        .support = trace_normal,
        .start_complete = 1,
    };

    capture_split(&model, 1, 1, 0, 1);
    complete(&model, 0, 0, 0);
    assert_trace(trace_absent, model.emitted, "wire/exact mismatch suppresses the event");
    assert_bool(1, model.retirement_requested, "wire/exact mismatch retires authority");
    assert_trace(trace_absent, model.support, "wire/exact mismatch cleans support");
}

static void test_tuple_reuse_generation_guard(void) {
    assert_bool(1,
                http1_client_request_generation_matches(100, 100),
                "same request generation permits cleanup");
    assert_bool(0,
                http1_client_request_generation_matches(100, 200),
                "stale terminal cannot clean tuple-reused request");
    assert_bool(0,
                http1_client_request_generation_matches(0, 0),
                "placeholder state is never a cleanup generation");
}

int main(void) {
    test_initial_publication_contention_retains_complete_start();
    test_deferred_initial_exact_resolution();
    test_terminal_writer_contention_fails_closed();
    test_split_wire_survives_publication_contention();
    test_split_exact_contention_later_validates();
    test_split_exact_mismatch_suppresses();
    test_tuple_reuse_generation_guard();
    return failures ? 1 : 0;
}
