// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

static inline unsigned int bpf_get_prandom_u32(void) {
    return 0;
}

static inline unsigned int bpf_get_smp_processor_id(void) {
    return 0;
}

static unsigned long long test_now = 1000;
static inline unsigned long long bpf_ktime_get_ns(void) {
    return ++test_now;
}

static unsigned long long test_process_start = 777;
static inline unsigned long long test_process_start_time(void) {
    return test_process_start;
}

static inline unsigned long long test_pid_tgid(void) {
    return 42ULL << 32;
}

#define OBI_CURRENT_PROCESS_START_TIME_NS() test_process_start_time()
#define OBI_CURRENT_PROCESS_START_BOOTTIME_NS() test_process_start_time()
#define bpf_get_current_pid_tgid test_pid_tgid

static inline long bpf_loop(unsigned int nr_loops,
                            int (*callback_fn)(unsigned int, void *),
                            void *callback_ctx,
                            unsigned long long flags) {
    (void)nr_loops;
    (void)callback_fn;
    (void)callback_ctx;
    (void)flags;
    return 0;
}

static void *test_map_lookup(void *map, const void *key);
static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags);
static long test_map_delete(void *map, const void *key);

#define BPF_ANY 0
#define BPF_NOEXIST 1
#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete

#include <gotracer/maps/hpack.h>

#undef bpf_map_delete_elem
#undef bpf_map_update_elem
#undef bpf_map_lookup_elem
#undef BPF_NOEXIST
#undef BPF_ANY

static unsigned int failures;
static go_hpack_block_t stored_block;
static go_exact_process_addr_key_t stored_key;
static u8 stored_present;
static u8 fail_update;
static unsigned int delete_calls;
static outgoing_trace_handoff_key_t handoff_key;
static outgoing_trace_handoff_t handoff_value;
static u8 handoff_present;
static u8 fail_handoff_update;
static egress_key_t locator_key;
static outgoing_trace_token_t locator_value;
static u8 locator_present;
static outgoing_trace_handoff_key_t exact_claim_key;
static u8 exact_claim_present;
static egress_key_t egress_claim_key;
static u8 egress_claim_present;
static u32 cpu_claim_key;
static u8 cpu_claim_present;
static u64 handoff_sequence;
static u64 handoff_epoch = 99;
static egress_key_t legacy_key;
static tp_info_pid_t legacy_value;
static u8 legacy_present;
static go_outgoing_trace_handoff_owner_t handoff_ref_key;
static go_outgoing_trace_handoff_ref_t handoff_ref_value;
static u8 handoff_ref_present;
static u8 fail_handoff_ref_update;
static go_outgoing_trace_handoff_owner_t owner_claim_key;
static u8 owner_claim_present;

static void *test_map_lookup(void *map, const void *key) {
    if (map == &go_hpack_traceparents && stored_present &&
        memcmp(key, &stored_key, sizeof(stored_key)) == 0) {
        return &stored_block;
    }
    if (map == &outgoing_trace_handoff && handoff_present &&
        memcmp(key, &handoff_key, sizeof(handoff_key)) == 0) {
        return &handoff_value;
    }
    if (map == &outgoing_trace_handoff_locators && locator_present &&
        memcmp(key, &locator_key, sizeof(locator_key)) == 0) {
        return &locator_value;
    }
    if (map == &outgoing_trace_handoff_sequence) {
        return &handoff_sequence;
    }
    if (map == &outgoing_trace_handoff_epoch) {
        return &handoff_epoch;
    }
    if (map == &outgoing_trace_map && legacy_present &&
        memcmp(key, &legacy_key, sizeof(legacy_key)) == 0) {
        return &legacy_value;
    }
    if (map == &go_outgoing_trace_handoffs && handoff_ref_present &&
        memcmp(key, &handoff_ref_key, sizeof(handoff_ref_key)) == 0) {
        return &handoff_ref_value;
    }
    return 0;
}

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    if (map == &go_hpack_traceparents) {
        if (fail_update) {
            return -1;
        }
        stored_key = *(const go_exact_process_addr_key_t *)key;
        stored_block = *(const go_hpack_block_t *)value;
        stored_present = 1;
        return 0;
    }
    if (map == &outgoing_trace_handoff) {
        if (fail_handoff_update || (flags == 1 && handoff_present)) {
            return -1;
        }
        handoff_key = *(const outgoing_trace_handoff_key_t *)key;
        handoff_value = *(const outgoing_trace_handoff_t *)value;
        handoff_present = 1;
        return 0;
    }
    if (map == &outgoing_trace_handoff_locators) {
        if (flags == 1 && locator_present) {
            return -1;
        }
        locator_key = *(const egress_key_t *)key;
        locator_value = *(const outgoing_trace_token_t *)value;
        locator_present = 1;
        return 0;
    }
    if (map == &outgoing_trace_handoff_claims) {
        if (exact_claim_present) {
            return -1;
        }
        exact_claim_key = *(const outgoing_trace_handoff_key_t *)key;
        exact_claim_present = 1;
        return 0;
    }
    if (map == &outgoing_trace_handoff_egress_claims) {
        if (egress_claim_present) {
            return -1;
        }
        egress_claim_key = *(const egress_key_t *)key;
        egress_claim_present = 1;
        return 0;
    }
    if (map == &outgoing_trace_handoff_cpu_claims) {
        if (cpu_claim_present) {
            return -1;
        }
        cpu_claim_key = *(const u32 *)key;
        cpu_claim_present = 1;
        return 0;
    }
    if (map == &outgoing_trace_map) {
        if (flags == 1 && legacy_present) {
            return -1;
        }
        legacy_key = *(const egress_key_t *)key;
        legacy_value = *(const tp_info_pid_t *)value;
        legacy_present = 1;
        return 0;
    }
    if (map == &go_outgoing_trace_handoffs) {
        if (fail_handoff_ref_update ||
            (flags == 1 && handoff_ref_present &&
             memcmp(key, &handoff_ref_key, sizeof(handoff_ref_key)) == 0)) {
            return -1;
        }
        handoff_ref_key = *(const go_outgoing_trace_handoff_owner_t *)key;
        handoff_ref_value = *(const go_outgoing_trace_handoff_ref_t *)value;
        handoff_ref_present = 1;
        return 0;
    }
    if (map == &go_outgoing_trace_handoff_owner_claims) {
        if (owner_claim_present && memcmp(key, &owner_claim_key, sizeof(owner_claim_key)) == 0) {
            return -1;
        }
        owner_claim_key = *(const go_outgoing_trace_handoff_owner_t *)key;
        owner_claim_present = 1;
        return 0;
    }
    return -1;
}

static long test_map_delete(void *map, const void *key) {
    if (map == &go_hpack_traceparents) {
        if (stored_present && memcmp(key, &stored_key, sizeof(stored_key)) == 0) {
            stored_present = 0;
        }
        delete_calls++;
        return 0;
    }
    if (map == &outgoing_trace_handoff && handoff_present &&
        memcmp(key, &handoff_key, sizeof(handoff_key)) == 0) {
        handoff_present = 0;
        return 0;
    }
    if (map == &outgoing_trace_handoff_locators && locator_present &&
        memcmp(key, &locator_key, sizeof(locator_key)) == 0) {
        locator_present = 0;
        return 0;
    }
    if (map == &outgoing_trace_handoff_claims && exact_claim_present &&
        memcmp(key, &exact_claim_key, sizeof(exact_claim_key)) == 0) {
        exact_claim_present = 0;
        return 0;
    }
    if (map == &outgoing_trace_handoff_egress_claims && egress_claim_present &&
        memcmp(key, &egress_claim_key, sizeof(egress_claim_key)) == 0) {
        egress_claim_present = 0;
        return 0;
    }
    if (map == &outgoing_trace_handoff_cpu_claims && cpu_claim_present &&
        memcmp(key, &cpu_claim_key, sizeof(cpu_claim_key)) == 0) {
        cpu_claim_present = 0;
        return 0;
    }
    if (map == &outgoing_trace_map && legacy_present &&
        memcmp(key, &legacy_key, sizeof(legacy_key)) == 0) {
        legacy_present = 0;
        return 0;
    }
    if (map == &go_outgoing_trace_handoffs && handoff_ref_present &&
        memcmp(key, &handoff_ref_key, sizeof(handoff_ref_key)) == 0) {
        handoff_ref_present = 0;
        return 0;
    }
    if (map == &go_outgoing_trace_handoff_owner_claims && owner_claim_present &&
        memcmp(key, &owner_claim_key, sizeof(owner_claim_key)) == 0) {
        owner_claim_present = 0;
        return 0;
    }
    return -1;
}

static void reset_transport_maps(void) {
    handoff_present = 0;
    fail_handoff_update = 0;
    locator_present = 0;
    exact_claim_present = 0;
    egress_claim_present = 0;
    cpu_claim_present = 0;
    handoff_sequence = 0;
    handoff_epoch = 99;
    legacy_present = 0;
    handoff_ref_present = 0;
    fail_handoff_ref_update = 0;
    owner_claim_present = 0;
    test_process_start = 777;
}

static tp_info_t test_trace(u8 id) {
    tp_info_t tp = {
        .ts = 1000 + id,
        .flags = k_flag_sampled,
        .sampling_decision = id,
    };
    for (u8 i = 0; i < TRACE_ID_SIZE_BYTES; i++) {
        tp.trace_id[i] = id + i;
    }
    for (u8 i = 0; i < SPAN_ID_SIZE_BYTES; i++) {
        tp.span_id[i] = id + 32 + i;
        tp.parent_id[i] = id + 64 + i;
    }
    return tp;
}

static connection_info_t test_connection(void) {
    connection_info_t conn = {
        .s_port = 31000,
        .d_port = 443,
    };
    conn.s_ip[3] = 0x0100007f;
    conn.d_ip[3] = 0x0200007f;
    return conn;
}

static u8 publish_test_hpack_traceparent(const connection_info_t *conn,
                                         u32 stream_id,
                                         const tp_info_t *tp,
                                         u32 pid,
                                         const go_addr_key_t *request) {
    outgoing_trace_token_t token = {};
    return publish_go_hpack_traceparent(conn, stream_id, tp, pid, request, &token);
}

static void assert_bool(int want, int got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %d, got %d\n", message, want, got);
    failures++;
}

static void assert_trace(const tp_info_t *want, const tp_info_t *got, const char *message) {
    if (memcmp(want, got, sizeof(*want)) == 0) {
        return;
    }
    fprintf(stderr,
            "%s: trace identities differ (want id=%u flags=%u, got id=%u flags=%u)\n",
            message,
            want->trace_id[0],
            want->flags,
            got->trace_id[0],
            got->flags);
    failures++;
}

static void assert_transport_empty(const char *message) {
    if (!handoff_present && !legacy_present && !handoff_ref_present) {
        return;
    }
    fprintf(stderr, "%s: transport maps were not empty\n", message);
    failures++;
}

static void test_hpack_publish_reserves_exact_handoff(void) {
    reset_transport_maps();
    const connection_info_t conn = test_connection();
    const go_addr_key_t request = {.pid = 42, .addr = 0x1234};
    const tp_info_t a = test_trace(1);

    assert_bool(
        1, publish_test_hpack_traceparent(&conn, 3, &a, 42, &request), "publish reserves H2 A");
    assert_bool(1, handoff_present, "non-evicting handoff is present");
    assert_bool(1, legacy_present, "legacy mirror is present");
    assert_bool(1, handoff_ref_present, "Go cleanup reference is present");
    assert_bool(k_outbound_trace_pending, handoff_value.tp.written, "A starts pending");
    assert_bool(3, handoff_key.egress.stream_id, "handoff keeps full stream ID");
    assert_trace(&a, &handoff_value.tp.tp, "handoff keeps exact trace A");
}

static void test_hpack_publish_rejects_conflicting_b(void) {
    reset_transport_maps();
    const connection_info_t conn = test_connection();
    const go_addr_key_t request = {.pid = 42, .addr = 0x1234};
    const tp_info_t a = test_trace(1);
    const tp_info_t b = test_trace(2);

    assert_bool(1, publish_test_hpack_traceparent(&conn, 3, &a, 42, &request), "publish initial A");
    assert_bool(
        0, publish_test_hpack_traceparent(&conn, 3, &b, 42, &request), "pending A rejects B");
    assert_trace(&a, &handoff_value.tp.tp, "conflict leaves A authoritative");
    assert_trace(&a, &legacy_value.tp, "conflict leaves legacy A intact");
}

static void test_hpack_saturation_and_registration_failure_fail_closed(void) {
    reset_transport_maps();
    const connection_info_t conn = test_connection();
    const go_addr_key_t request = {.pid = 42, .addr = 0x1234};
    const tp_info_t a = test_trace(1);

    fail_handoff_update = 1;
    assert_bool(0,
                publish_test_hpack_traceparent(&conn, 3, &a, 42, &request),
                "handoff saturation rejects publication");
    assert_transport_empty("saturation performs no secondary publication");

    reset_transport_maps();
    fail_handoff_ref_update = 1;
    assert_bool(0,
                publish_test_hpack_traceparent(&conn, 3, &a, 42, &request),
                "cleanup-index saturation rejects publication");
    assert_transport_empty("failed cleanup registration retires pending A");
}

static void test_hpack_cleanup_is_token_exact(void) {
    reset_transport_maps();
    const connection_info_t conn = test_connection();
    const go_addr_key_t request = {.pid = 42, .addr = 0x1234};
    const tp_info_t a = test_trace(1);
    const tp_info_t b = test_trace(2);

    assert_bool(
        1, publish_test_hpack_traceparent(&conn, 3, &a, 42, &request), "publish A before cleanup");
    cleanup_go_outgoing_trace_handoff(&request);
    assert_bool(0, handoff_present, "request completion retires exact A");
    assert_bool(0, locator_present, "request completion retires A locator");
    assert_bool(0, handoff_ref_present, "request completion retires A owner reference");
    assert_bool(0, legacy_present, "request completion retires matching legacy A");

    reset_transport_maps();
    assert_bool(1,
                publish_test_hpack_traceparent(&conn, 3, &a, 42, &request),
                "publish A before delayed cleanup");
    // Model an immutable replacement generation: B has its own exact token
    // and locator while the delayed request owner still references A's token.
    handoff_key.token.sequence++;
    locator_value = handoff_key.token;
    handoff_value.tp.tp = b;
    handoff_value.tp.written = k_outbound_trace_written;
    legacy_value.tp = b;
    cleanup_go_outgoing_trace_handoff(&request);
    assert_bool(1, handoff_present, "A token cannot delete replacement B");
    assert_bool(1, legacy_present, "A token cannot delete legacy B");
    assert_bool(0, handoff_ref_present, "completed request reference is retired");
}

static void test_injector_reuse_preserves_go_authority(void) {
    reset_transport_maps();
    const connection_info_t conn = test_connection();
    const go_addr_key_t request = {.pid = 42, .addr = 0x1234};
    const tp_info_t a = test_trace(1);

    assert_bool(
        1, publish_test_hpack_traceparent(&conn, 3, &a, 42, &request), "Go publishes pending A");
    const egress_key_t egress = handoff_key.egress;
    const outgoing_trace_token_t owner_token = handoff_key.token;
    const tp_info_pid_t candidate = handoff_value.tp;

    outgoing_trace_token_t injector_token = {};
    const u8 reservation = reserve_outgoing_trace_handoff(&egress, &candidate, &injector_token);
    assert_bool(
        k_outgoing_trace_reservation_reused, reservation, "injector reuses matching Go authority");
    assert_bool(1,
                outgoing_trace_tokens_match(&owner_token, &injector_token),
                "injector receives the original exact token");

    if (reservation == k_outgoing_trace_reservation_fresh) {
        request_outgoing_trace_handoff_retirement(&egress, &injector_token, &candidate, 1);
    }
    assert_bool(1, handoff_present, "injector failure preserves borrowed Go authority");
    assert_bool(1, locator_present, "injector failure preserves borrowed locator");

    cleanup_go_outgoing_trace_handoff(&request);
    assert_bool(0, handoff_present, "request owner retires borrowed authority");
    assert_bool(0, locator_present, "request owner retires borrowed locator");
}

static void test_durable_handoff_retirement_releases_legacy_capacity(void) {
    reset_transport_maps();
    const connection_info_t conn = test_connection();
    const go_addr_key_t request_a = {.pid = 42, .addr = 0x1234};
    const go_addr_key_t request_b = {.pid = 42, .addr = 0x5678};
    const tp_info_t a = test_trace(1);
    const tp_info_t b = test_trace(2);

    assert_bool(
        1, publish_test_hpack_traceparent(&conn, 3, &a, 42, &request_a), "publish durable A");
    const egress_key_t egress = handoff_key.egress;
    const outgoing_trace_token_t token = handoff_key.token;
    assert_bool(
        1,
        claim_outgoing_trace_handoff(&egress, &token, 42, EVENT_HTTP_CLIENT, NULL, 1, 1, NULL),
        "writer claims A");
    commit_claimed_outgoing_trace_handoff(&egress, &token);
    assert_bool(
        1,
        claim_outgoing_trace_handoff(&egress, &token, 42, EVENT_HTTP_CLIENT, NULL, 1, 1, NULL),
        "consumer claims written A");
    consume_claimed_outgoing_trace_handoff(&egress, &token);

    assert_bool(0, handoff_present, "durable A retires exact authority");
    assert_bool(0, locator_present, "durable A retires its locator");
    assert_bool(0, legacy_present, "durable A retires its matching legacy mirror");
    assert_bool(1,
                publish_test_hpack_traceparent(&conn, 3, &b, 42, &request_b),
                "same egress can publish B after durable A");
    assert_trace(&b, &legacy_value.tp, "replacement legacy mirror carries B");
}

static void test_consume_with_egress_claim_retires_atomically(void) {
    reset_transport_maps();
    const connection_info_t conn = test_connection();
    const go_addr_key_t request = {.pid = 42, .addr = 0x1234};
    const tp_info_t a = test_trace(1);

    assert_bool(1, publish_test_hpack_traceparent(&conn, 3, &a, 42, &request), "publish written A");
    const egress_key_t egress = handoff_key.egress;
    const outgoing_trace_token_t token = handoff_key.token;
    assert_bool(
        1,
        claim_outgoing_trace_handoff(&egress, &token, 42, EVENT_HTTP_CLIENT, NULL, 1, 1, NULL),
        "writer claims written A");
    commit_claimed_outgoing_trace_handoff(&egress, &token);

    assert_bool(1, claim_outgoing_trace_handoff_egress(&egress), "consumer claims egress lane");
    assert_bool(
        1,
        claim_outgoing_trace_handoff(&egress, &token, 42, EVENT_HTTP_CLIENT, NULL, 1, 1, NULL),
        "consumer claims exact written A");
    consume_claimed_outgoing_trace_handoff_egress_held(&egress, &token);

    assert_bool(0, handoff_present, "preclaimed consume retires exact A");
    assert_bool(0, locator_present, "preclaimed consume retires A locator");
    assert_bool(0, legacy_present, "preclaimed consume retires matching legacy A");
    assert_bool(0, exact_claim_present, "preclaimed consume releases the exact claim");
    assert_bool(1, egress_claim_present, "preclaimed consume retains the caller's egress claim");
    release_outgoing_trace_handoff_egress(&egress);
    assert_bool(0, egress_claim_present, "caller releases the egress claim last");
}

static void test_pending_consume_with_egress_claim_defers_retirement(void) {
    reset_transport_maps();
    const connection_info_t conn = test_connection();
    const go_addr_key_t request = {.pid = 42, .addr = 0x1234};
    const tp_info_t a = test_trace(1);

    assert_bool(1, publish_test_hpack_traceparent(&conn, 3, &a, 42, &request), "publish pending A");
    const egress_key_t egress = handoff_key.egress;
    const outgoing_trace_token_t token = handoff_key.token;
    assert_bool(1, claim_outgoing_trace_handoff_egress(&egress), "consumer claims pending lane");
    assert_bool(
        1,
        claim_outgoing_trace_handoff(&egress, &token, 42, EVENT_HTTP_CLIENT, NULL, 1, 1, NULL),
        "consumer claims exact pending A");
    consume_claimed_outgoing_trace_handoff_egress_held(&egress, &token);

    assert_bool(1, handoff_present, "pending A remains until the writer commits");
    assert_bool(1, handoff_value.local_consumed, "pending A records local consumption");
    assert_bool(1, locator_present, "pending A retains its locator");
    assert_bool(1, legacy_present, "pending A retains its legacy mirror");
    assert_bool(0, exact_claim_present, "pending consume releases the exact claim");
    assert_bool(1, egress_claim_present, "pending consume retains the caller's egress claim");
    release_outgoing_trace_handoff_egress(&egress);

    assert_bool(
        1,
        claim_outgoing_trace_handoff(&egress, &token, 42, EVENT_HTTP_CLIENT, NULL, 0, 1, NULL),
        "writer reclaims pending A");
    commit_claimed_outgoing_trace_handoff(&egress, &token);
    assert_bool(0, handoff_present, "writer commit retires consumed A");
    assert_bool(0, locator_present, "writer commit retires the consumed locator");
    assert_bool(0, legacy_present, "writer commit retires the consumed legacy mirror");
}

static void test_allocator_reclaim_retires_matching_legacy_mirror(void) {
    reset_transport_maps();
    const connection_info_t conn = test_connection();
    const go_addr_key_t request = {.pid = 42, .addr = 0x1234};
    const tp_info_t a = test_trace(1);
    const tp_info_t b = test_trace(2);

    assert_bool(
        1, publish_test_hpack_traceparent(&conn, 3, &a, 42, &request), "publish reclaimable A");
    handoff_value.tp.written = k_outbound_trace_written;
    handoff_value.local_consumed = 1;
    const egress_key_t egress = handoff_key.egress;

    const tp_info_pid_t candidate = {
        .tp = b,
        .pid = 42,
        .valid = 1,
        .written = k_outbound_trace_pending,
        .req_type = EVENT_HTTP_CLIENT,
    };
    outgoing_trace_token_t token = {};
    assert_bool(1,
                reserve_outgoing_trace_handoff(&egress, &candidate, &token),
                "allocator replaces durable A with B");
    assert_bool(0, legacy_present, "allocator reclaim retires matching legacy A");
    assert_trace(&b, &handoff_value.tp.tp, "fresh authority carries B");
}

static void test_hpack_owner_key_recovers_after_pid_reuse(void) {
    reset_transport_maps();
    const connection_info_t conn = test_connection();
    const go_addr_key_t request = {.pid = 42, .addr = 0x1234};
    const tp_info_t a = test_trace(1);
    const tp_info_t b = test_trace(2);

    assert_bool(1,
                publish_test_hpack_traceparent(&conn, 3, &a, 42, &request),
                "old process publishes an exact owner reference");

    // Model process death leaving only its bounded LRU owner reference. The
    // same PID and Go address in a new exact incarnation must not be blocked by
    // the old BPF_NOEXIST key.
    handoff_present = 0;
    locator_present = 0;
    legacy_present = 0;
    exact_claim_present = 0;
    egress_claim_present = 0;
    cpu_claim_present = 0;
    owner_claim_present = 0;
    test_process_start = 778;

    assert_bool(1,
                publish_test_hpack_traceparent(&conn, 3, &b, 42, &request),
                "new process incarnation reuses finite owner capacity");
    assert_bool(
        778, handoff_ref_key.process_start_time, "owner reference key carries exact process start");
    assert_bool(778,
                handoff_ref_value.token.process_start_time,
                "replacement reference carries new exact token");
}

static go_hpack_block_t request_without_traceparent(void) {
    const unsigned char method[] = ":method";
    go_hpack_block_t block = {};
    go_hpack_observe_pseudo_header(&block, method, sizeof(method) - 1);
    return block;
}

static go_hpack_block_t request_with_traceparent(void) {
    const unsigned char method[] = ":method";
    const unsigned char name[] = "traceparent";
    const unsigned char value[] = "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01";
    go_hpack_block_t block = {};
    go_hpack_observe_pseudo_header(&block, method, sizeof(method) - 1);
    go_hpack_capture_traceparent(&block, name, sizeof(name) - 1, value, sizeof(value) - 1);
    return block;
}

static void test_successful_observation_proves_absence(void) {
    const go_addr_key_t key = {.pid = 42, .addr = 0x1234};
    const go_hpack_block_t block = request_without_traceparent();
    go_hpack_block_t observed = {};

    stored_present = 0;
    fail_update = 0;
    assert_bool(0, replace_go_hpack_traceparent(&key, &block), "store request observation");
    const u8 classification = read_go_hpack_traceparent(&key, &observed);
    assert_bool(k_go_hpack_traceparent_absent, classification, "stored request proves absence");
    assert_bool(1,
                go_hpack_can_inject_traceparent(classification),
                "proven absence permits shared direct-injection path");
}

static void test_update_failure_is_unknown(void) {
    const go_addr_key_t key = {.pid = 42, .addr = 0x1234};
    const go_hpack_block_t stale_absence = request_without_traceparent();
    const go_hpack_block_t observed_traceparent = request_with_traceparent();
    go_hpack_block_t observed = {};

    stored_block = stale_absence;
    stored_key = go_exact_process_addr_key(42, test_process_start, key.addr);
    stored_present = 1;
    fail_update = 1;
    delete_calls = 0;
    assert_bool(-1,
                replace_go_hpack_traceparent(&key, &observed_traceparent),
                "force traceparent observation update failure");
    assert_bool(1, delete_calls, "replace clears stale state before update");
    const u8 classification = read_go_hpack_traceparent(&key, &observed);
    assert_bool(k_go_hpack_traceparent_unknown,
                classification,
                "failed traceparent update cannot retain stale proven absence");
    assert_bool(0,
                go_hpack_can_inject_traceparent(classification),
                "net/http2 direct injection is suppressed after update failure");
    assert_bool(0,
                go_hpack_can_inject_traceparent(classification),
                "gRPC direct injection is suppressed after update failure");
}

static void test_eviction_is_unknown(void) {
    const go_addr_key_t key = {.pid = 42, .addr = 0x1234};
    const go_hpack_block_t block = request_without_traceparent();
    go_hpack_block_t observed = {};

    fail_update = 0;
    assert_bool(0, replace_go_hpack_traceparent(&key, &block), "store state before eviction");
    stored_present = 0;
    const u8 classification = read_go_hpack_traceparent(&key, &observed);
    assert_bool(k_go_hpack_traceparent_unknown, classification, "evicted observation is unknown");
    assert_bool(0,
                go_hpack_can_inject_traceparent(classification),
                "net/http2 direct injection is suppressed after eviction");
    assert_bool(0,
                go_hpack_can_inject_traceparent(classification),
                "gRPC direct injection is suppressed after eviction");
}

static void test_hpack_state_is_exact_process_scoped(void) {
    const go_addr_key_t reused = {.pid = 42, .addr = 0x4321};
    const go_hpack_block_t old = request_with_traceparent();
    go_hpack_block_t observed = {};

    stored_present = 0;
    fail_update = 0;
    test_process_start = 777;
    assert_bool(
        0, replace_go_hpack_traceparent(&reused, &old), "old process stores HPACK observation");

    test_process_start = 778;
    assert_bool(k_go_hpack_traceparent_unknown,
                read_go_hpack_traceparent(&reused, &observed),
                "PID and goroutine reuse cannot read old HPACK state");
    clear_go_hpack_traceparent(&reused);
    assert_bool(1, stored_present, "new process cleanup cannot address the old exact key");
}

int main(void) {
    test_hpack_publish_reserves_exact_handoff();
    test_hpack_publish_rejects_conflicting_b();
    test_hpack_saturation_and_registration_failure_fail_closed();
    test_hpack_cleanup_is_token_exact();
    test_injector_reuse_preserves_go_authority();
    test_durable_handoff_retirement_releases_legacy_capacity();
    test_consume_with_egress_claim_retires_atomically();
    test_pending_consume_with_egress_claim_defers_retirement();
    test_allocator_reclaim_retires_matching_legacy_mirror();
    test_hpack_owner_key_recovers_after_pid_reuse();
    test_successful_observation_proves_absence();
    test_update_failure_is_unknown();
    test_eviction_is_unknown();
    test_hpack_state_is_exact_process_scoped();
    return failures ? 1 : 0;
}
