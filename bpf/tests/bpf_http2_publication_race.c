// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

#include <generictracer/http2_client_lifecycle.h>

_Static_assert(k_http2_client_lifecycle_map_type == BPF_MAP_TYPE_LRU_HASH,
               "HTTP/2 lifecycle state must remain bounded");
_Static_assert(sizeof(http2_client_lifecycle_key_t) % sizeof(u64) == 0,
               "HTTP/2 lifecycle key must remain naturally aligned");

enum event_state {
    event_absent,
    event_normal,
    event_exact,
};

typedef struct publication_model {
    enum event_state ongoing;
    enum event_state upgrade;
    enum event_state support;
    enum event_state emitted;
    u8 terminal;
    u8 completed;
    u8 retirement_requested;
    u8 writer_released;
    u8 server_started;
    u8 completion_count;
} publication_model_t;

static unsigned int failures;

static void assert_state(enum event_state want, enum event_state got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %d, got %d\n", message, want, got);
    failures++;
}

static void assert_bool(int want, int got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %d, got %d\n", message, want, got);
    failures++;
}

static void publish_with_completion_handshake(publication_model_t *model,
                                              enum event_state publication,
                                              u8 completion_between_checks) {
    if (model->completed) {
        return;
    }
    model->support = publication;
    if (completion_between_checks) {
        model->completed = 1;
    }
    if (model->completed && model->support == publication) {
        model->support = event_absent;
    }
}

static void start_normal(publication_model_t *model, u8 publication_claim_available) {
    if (model->ongoing == event_absent) {
        model->ongoing = event_normal;
    }
    if (publication_claim_available) {
        publish_with_completion_handshake(model, event_normal, 0);
    }
}

static void start_server(publication_model_t *model, u8 client_publication_claimed) {
    assert_bool(
        0, http2_uses_client_publication_lane(EVENT_HTTP_REQUEST), "server avoids client lane");
    (void)client_publication_claimed;
    model->server_started = 1;
}

static void start_exact_upgrade(publication_model_t *model,
                                u8 publication_claim_available,
                                u8 completion_between_publish_checks) {
    if (model->completed) {
        model->retirement_requested = 1;
        return;
    }
    model->upgrade = event_exact;
    if (publication_claim_available) {
        publish_with_completion_handshake(model, event_exact, completion_between_publish_checks);
    }
}

static void complete_client(publication_model_t *model,
                            u8 go_client,
                            u8 exact_locator_present,
                            u8 protocol_upgrade_before_reread) {
    if (model->ongoing == event_absent) {
        return;
    }
    model->terminal = 1;
    const u8 had_exact = model->ongoing == event_exact || model->upgrade == event_exact;
    const enum http2_client_completion_resolution resolution =
        http2_client_completion_resolution(had_exact, exact_locator_present);
    if (resolution == k_http2_client_completion_fail_closed) {
        model->retirement_requested = 1;
    }
    if (model->completed) {
        return;
    }

    model->completed = 1;
    model->completion_count++;
    if (protocol_upgrade_before_reread) {
        model->upgrade = event_exact;
    }

    const u8 has_exact = model->ongoing == event_exact || model->upgrade == event_exact;
    if (has_exact) {
        model->emitted = event_exact;
    } else if (!go_client && resolution == k_http2_client_completion_normal) {
        model->emitted = event_normal;
    }

    model->support = event_absent;
    model->ongoing = event_absent;
    model->upgrade = event_absent;
    model->terminal = 0;
}

static void release_transport_writer(publication_model_t *model) {
    model->writer_released = 1;
    if (model->retirement_requested) {
        model->support = event_absent;
    }
}

static void assert_transient_state_clean(const publication_model_t *model, const char *message) {
    if (model->ongoing == event_absent && model->upgrade == event_absent &&
        model->support == event_absent && !model->terminal) {
        return;
    }
    fprintf(stderr,
            "%s: ongoing=%d upgrade=%d support=%d terminal=%d\n",
            message,
            model->ongoing,
            model->upgrade,
            model->support,
            model->terminal);
    failures++;
}

static void test_server_never_contends_with_client_publication(void) {
    publication_model_t model = {};

    assert_bool(
        1, http2_uses_client_publication_lane(EVENT_HTTP_CLIENT), "client uses publication lane");
    start_server(&model, 1);

    assert_bool(1, model.server_started, "same-process server start is not dropped");
}

static void test_contended_client_start_retains_event_state(void) {
    publication_model_t model = {};

    start_normal(&model, 0);
    assert_state(event_normal, model.ongoing, "contended publication retains client start");
    assert_state(
        event_absent, model.support, "contended publication does not publish partial state");

    complete_client(&model, 0, 0, 0);
    assert_state(event_normal, model.emitted, "retained non-Go client emits at terminal frame");
    assert_transient_state_clean(&model, "terminal frame cleans retained client state");
}

static void test_exact_upgrade_wins_over_normal_start(void) {
    publication_model_t model = {};

    start_normal(&model, 1);
    start_exact_upgrade(&model, 1, 0);
    complete_client(&model, 1, 1, 0);

    assert_state(event_exact, model.emitted, "terminal reread selects immutable exact upgrade");
    assert_bool(1, model.completion_count, "exact request completes once");
    assert_transient_state_clean(&model, "exact completion cleans transient maps");
}

static void test_contended_connection_lane_cannot_drop_end(void) {
    publication_model_t model = {};
    const u8 another_stream_holds_client_publication_lane = 1;

    start_normal(&model, 1);
    start_exact_upgrade(&model, 1, 0);
    (void)another_stream_holds_client_publication_lane;
    complete_client(&model, 1, 1, 0);

    assert_state(event_exact, model.emitted, "end does not depend on the connection lane");
    assert_bool(1, model.completion_count, "unique end is consumed exactly once");
    assert_transient_state_clean(&model, "contended connection lane cannot leak end state");
}

static void test_end_during_protocol_upgrade_emits_exact_once(void) {
    publication_model_t model = {};

    start_normal(&model, 1);
    complete_client(&model, 1, 1, 1);
    complete_client(&model, 1, 1, 0);

    assert_bool(1, model.retirement_requested, "contended authority receives retirement request");
    assert_state(
        event_exact, model.emitted, "upgrade published before reread remains authoritative");
    assert_bool(1, model.completion_count, "completion tombstone rejects duplicate end");
    assert_transient_state_clean(&model, "racing exact completion cleans transient maps");
}

static void test_tpinjector_writer_contention_is_terminal(void) {
    publication_model_t model = {};

    start_normal(&model, 1);
    complete_client(&model, 1, 1, 0);
    release_transport_writer(&model);

    assert_bool(1, model.retirement_requested, "end requests writer-owned exact retirement");
    assert_bool(1, model.writer_released, "transport writer can release without H2 callback");
    assert_bool(1, model.completed, "end installs a durable completion tombstone");
    assert_state(event_absent, model.emitted, "unproven exact authority fails closed");
    assert_transient_state_clean(&model,
                                 "writer-only contention leaves no terminal or ongoing state");
}

static void test_late_publish_after_end_is_removed(void) {
    publication_model_t model = {
        .completed = 1,
    };

    publish_with_completion_handshake(&model, event_normal, 0);
    assert_state(event_absent, model.support, "precheck blocks post-end normal publication");

    model.completed = 0;
    publish_with_completion_handshake(&model, event_exact, 1);
    assert_state(event_absent, model.support, "postcheck removes publication racing with end");
}

static void test_end_before_late_exact_start_cannot_resurrect(void) {
    publication_model_t model = {};

    start_normal(&model, 1);
    complete_client(&model, 1, 0, 0);
    start_exact_upgrade(&model, 1, 0);

    assert_bool(1, model.completed, "completion tombstone survives terminal cleanup");
    assert_bool(1, model.retirement_requested, "late exact start retires its generation");
    assert_transient_state_clean(&model, "late exact start cannot recreate support or upgrade");
}

static void test_lifecycle_key_distinguishes_tuple_reuse(void) {
    http2_conn_stream_t stream = {
        .stream_id = 7,
    };
    const http2_client_lifecycle_key_t first = http2_client_lifecycle_key(&stream, 100);
    const http2_client_lifecycle_key_t second = http2_client_lifecycle_key(&stream, 200);

    assert_bool(1,
                memcmp(&first, &second, sizeof(first)) != 0,
                "start timestamp distinguishes a reused tuple and stream id");
}

int main(void) {
    test_server_never_contends_with_client_publication();
    test_contended_client_start_retains_event_state();
    test_exact_upgrade_wins_over_normal_start();
    test_contended_connection_lane_cannot_drop_end();
    test_end_during_protocol_upgrade_emits_exact_once();
    test_tpinjector_writer_contention_is_terminal();
    test_late_publish_after_end_is_removed();
    test_end_before_late_exact_start_cannot_resurrect();
    test_lifecycle_key_distinguishes_tuple_reuse();
    return failures ? 1 : 0;
}
