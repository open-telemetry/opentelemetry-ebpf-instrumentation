// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wint-conversion"
#pragma clang diagnostic ignored "-Wint-to-pointer-cast"
#pragma clang diagnostic ignored "-Wunused-variable"

#undef BPF_CORE_READ
#define BPF_CORE_READ(src, ...) ((void)(src), 0)

struct pt_regs {
    unsigned long bx;
    unsigned long sp;
};

#define GO_PARAM2(ctx) ((void *)(ctx)->bx)
#define PT_REGS_SP(ctx) ((ctx)->sp)

static inline unsigned int bpf_get_prandom_u32(void) {
    return 0;
}

static inline unsigned long long bpf_ktime_get_ns(void) {
    return 0;
}

static inline unsigned int bpf_get_smp_processor_id(void) {
    return 0;
}

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
static long test_map_update(void *map, const void *key, const void *val, unsigned long long flags);
static long test_map_delete(void *map, const void *key);
static unsigned long long test_current_pid_tgid(void);
static unsigned long long test_process_start_time(void);

#define BPF_ANY 0
#define BPF_NOEXIST 1
#define LIBBPF_PIN_BY_NAME 1
#define bpf_memcpy memcpy
#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete
#define bpf_get_current_pid_tgid test_current_pid_tgid
#define OBI_CURRENT_PROCESS_START_TIME_NS test_process_start_time

#include "../common/trace_lifecycle.h"

#undef OBI_CURRENT_PROCESS_START_TIME_NS
#undef bpf_get_current_pid_tgid
#undef bpf_map_delete_elem
#undef bpf_map_update_elem
#undef bpf_map_lookup_elem
#undef BPF_NOEXIST
#undef BPF_ANY
#undef bpf_memcpy
#undef LIBBPF_PIN_BY_NAME
#undef PT_REGS_SP
#undef GO_PARAM2
#undef BPF_CORE_READ

#pragma clang diagnostic pop

static unsigned int failures;
static connection_info_part_t captured_aux_key;
static tp_info_pid_t captured_aux_value;
static trace_map_key_t captured_trace_key;
static tp_info_pid_t captured_trace_value;
static egress_key_t captured_outgoing_key;
static tp_info_pid_t captured_outgoing_value;
static u64 captured_obi_key;
static obi_ctx_info_t captured_obi_value;
static u64 captured_flags_key;
static u8 captured_flags;
static unsigned int aux_updates;
static unsigned int trace_updates;
static unsigned int outgoing_updates;
static unsigned int obi_updates;
static unsigned int flags_updates;
static u64 deleted_obi_key;
static u64 deleted_flags_key;
static unsigned int obi_deletes;
static unsigned int flags_deletes;
static unsigned int outgoing_deletes;
static unsigned int trace_deletes;
static unsigned int claim_deletes;

typedef enum publication_map {
    publication_map_none,
    publication_map_outgoing,
    publication_map_trace,
    publication_map_obi,
    publication_map_flags,
} publication_map_t;

enum {
    test_bpf_noexist = 1,
};

static egress_key_t stored_outgoing_key;
static tp_info_pid_t stored_outgoing;
static trace_map_key_t stored_trace_key;
static tp_info_pid_t stored_trace;
static u64 stored_obi_key;
static obi_ctx_info_t stored_obi;
static u64 stored_flags_key;
static u8 stored_flags;
static egress_key_t stored_claim_key;
static u8 stored_claim;
static u8 outgoing_present;
static u8 trace_present;
static u8 obi_present;
static u8 flags_present;
static u8 claim_present;
static publication_map_t fail_next_update;
static publication_map_t publication_update_order[4];
static unsigned int publication_update_count;

static void assert_bool(int want, int got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %d, got %d\n", message, want, got);
    failures++;
}

static void assert_bytes(const void *want, const void *got, size_t len, const char *message) {
    if (memcmp(want, got, len) == 0) {
        return;
    }
    fprintf(stderr, "%s: byte sequences differ\n", message);
    failures++;
}

static void assert_u64(u64 want, u64 got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr,
            "%s: want %llu, got %llu\n",
            message,
            (unsigned long long)want,
            (unsigned long long)got);
    failures++;
}

static void assert_map_order(publication_map_t want, publication_map_t got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want map %d, got map %d\n", message, want, got);
    failures++;
}

static void reset_captures(void) {
    memset(&captured_aux_key, 0, sizeof(captured_aux_key));
    memset(&captured_aux_value, 0, sizeof(captured_aux_value));
    memset(&captured_trace_key, 0, sizeof(captured_trace_key));
    memset(&captured_trace_value, 0, sizeof(captured_trace_value));
    memset(&captured_outgoing_key, 0, sizeof(captured_outgoing_key));
    memset(&captured_outgoing_value, 0, sizeof(captured_outgoing_value));
    memset(&captured_obi_value, 0, sizeof(captured_obi_value));
    captured_obi_key = 0;
    captured_flags_key = 0;
    captured_flags = 0;
    aux_updates = 0;
    trace_updates = 0;
    outgoing_updates = 0;
    obi_updates = 0;
    flags_updates = 0;
    deleted_obi_key = 0;
    deleted_flags_key = 0;
    obi_deletes = 0;
    flags_deletes = 0;
    outgoing_deletes = 0;
    trace_deletes = 0;
    claim_deletes = 0;
    memset(&stored_outgoing_key, 0, sizeof(stored_outgoing_key));
    memset(&stored_outgoing, 0, sizeof(stored_outgoing));
    memset(&stored_trace_key, 0, sizeof(stored_trace_key));
    memset(&stored_trace, 0, sizeof(stored_trace));
    stored_obi_key = 0;
    memset(&stored_obi, 0, sizeof(stored_obi));
    stored_flags_key = 0;
    stored_flags = 0;
    memset(&stored_claim_key, 0, sizeof(stored_claim_key));
    stored_claim = 0;
    outgoing_present = 0;
    trace_present = 0;
    obi_present = 0;
    flags_present = 0;
    claim_present = 0;
    fail_next_update = publication_map_none;
    memset(publication_update_order, 0, sizeof(publication_update_order));
    publication_update_count = 0;
}

static void *test_map_lookup(void *map, const void *key) {
    if (map == (void *)&outgoing_trace_map && outgoing_present &&
        memcmp(key, &stored_outgoing_key, sizeof(stored_outgoing_key)) == 0) {
        return &stored_outgoing;
    }
    if (map == (void *)&trace_map && trace_present &&
        memcmp(key, &stored_trace_key, sizeof(stored_trace_key)) == 0) {
        return &stored_trace;
    }
    if (map == (void *)&traces_ctx_v1 && obi_present && *(const u64 *)key == stored_obi_key) {
        return &stored_obi;
    }
    if (map == (void *)&traces_ctx_flags && flags_present &&
        *(const u64 *)key == stored_flags_key) {
        return &stored_flags;
    }
    if (map == (void *)&outgoing_trace_handoff_egress_claims && claim_present &&
        memcmp(key, &stored_claim_key, sizeof(stored_claim_key)) == 0) {
        return &stored_claim;
    }
    return NULL;
}

static long test_map_update(void *map, const void *key, const void *val, unsigned long long flags) {
    publication_map_t publication_map = publication_map_none;
    if (map == (void *)&outgoing_trace_map) {
        publication_map = publication_map_outgoing;
    } else if (map == (void *)&trace_map) {
        publication_map = publication_map_trace;
    } else if (map == (void *)&traces_ctx_v1) {
        publication_map = publication_map_obi;
    } else if (map == (void *)&traces_ctx_flags) {
        publication_map = publication_map_flags;
    }
    if (publication_map != publication_map_none &&
        publication_update_count <
            sizeof(publication_update_order) / sizeof(publication_update_order[0])) {
        publication_update_order[publication_update_count++] = publication_map;
    }
    if (publication_map != publication_map_none && fail_next_update == publication_map) {
        fail_next_update = publication_map_none;
        return -1;
    }

    if (map == (void *)&server_traces_aux) {
        captured_aux_key = *(const connection_info_part_t *)key;
        captured_aux_value = *(const tp_info_pid_t *)val;
        aux_updates++;
    } else if (map == (void *)&trace_map) {
        stored_trace_key = *(const trace_map_key_t *)key;
        stored_trace = *(const tp_info_pid_t *)val;
        trace_present = 1;
        captured_trace_key = *(const trace_map_key_t *)key;
        captured_trace_value = *(const tp_info_pid_t *)val;
        trace_updates++;
    } else if (map == (void *)&outgoing_trace_map) {
        if (flags == test_bpf_noexist && outgoing_present &&
            memcmp(key, &stored_outgoing_key, sizeof(stored_outgoing_key)) == 0) {
            return -1;
        }
        stored_outgoing_key = *(const egress_key_t *)key;
        stored_outgoing = *(const tp_info_pid_t *)val;
        outgoing_present = 1;
        captured_outgoing_key = *(const egress_key_t *)key;
        captured_outgoing_value = *(const tp_info_pid_t *)val;
        outgoing_updates++;
    } else if (map == (void *)&traces_ctx_v1) {
        stored_obi_key = *(const u64 *)key;
        stored_obi = *(const obi_ctx_info_t *)val;
        obi_present = 1;
        captured_obi_key = *(const u64 *)key;
        captured_obi_value = *(const obi_ctx_info_t *)val;
        obi_updates++;
    } else if (map == (void *)&traces_ctx_flags) {
        stored_flags_key = *(const u64 *)key;
        stored_flags = *(const u8 *)val;
        flags_present = 1;
        captured_flags_key = *(const u64 *)key;
        captured_flags = *(const u8 *)val;
        flags_updates++;
    } else if (map == (void *)&outgoing_trace_handoff_egress_claims) {
        if (flags == test_bpf_noexist && claim_present &&
            memcmp(key, &stored_claim_key, sizeof(stored_claim_key)) == 0) {
            return -1;
        }
        stored_claim_key = *(const egress_key_t *)key;
        stored_claim = *(const u8 *)val;
        claim_present = 1;
    }

    return 0;
}

static long test_map_delete(void *map, const void *key) {
    if (map == (void *)&outgoing_trace_map) {
        if (outgoing_present &&
            memcmp(key, &stored_outgoing_key, sizeof(stored_outgoing_key)) == 0) {
            outgoing_present = 0;
        }
        outgoing_deletes++;
    } else if (map == (void *)&trace_map) {
        if (trace_present && memcmp(key, &stored_trace_key, sizeof(stored_trace_key)) == 0) {
            trace_present = 0;
        }
        trace_deletes++;
    } else if (map == (void *)&traces_ctx_v1) {
        if (obi_present && *(const u64 *)key == stored_obi_key) {
            obi_present = 0;
        }
        deleted_obi_key = *(const u64 *)key;
        obi_deletes++;
    } else if (map == (void *)&traces_ctx_flags) {
        if (flags_present && *(const u64 *)key == stored_flags_key) {
            flags_present = 0;
        }
        deleted_flags_key = *(const u64 *)key;
        flags_deletes++;
    } else if (map == (void *)&outgoing_trace_handoff_egress_claims) {
        if (claim_present && memcmp(key, &stored_claim_key, sizeof(stored_claim_key)) == 0) {
            claim_present = 0;
        }
        claim_deletes++;
    }
    return 0;
}

static unsigned long long test_current_pid_tgid(void) {
    return 0x999900000001ULL;
}

static unsigned long long test_process_start_time(void) {
    return 1;
}

static connection_info_t test_connection(void) {
    connection_info_t conn = {
        .s_port = 42000,
        .d_port = 8080,
    };
    conn.s_addr[IP_V6_ADDR_LEN - 1] = 1;
    conn.d_addr[IP_V6_ADDR_LEN - 1] = 2;
    return conn;
}

static tp_info_pid_t test_publication(void) {
    tp_info_pid_t publication = {
        .pid = 42,
        .valid = 1,
        .req_type = EVENT_HTTP_REQUEST,
    };
    publication.tp.flags = k_flag_sampled | k_flag_random;
    for (u8 i = 0; i < TRACE_ID_SIZE_BYTES; i++) {
        publication.tp.trace_id[i] = i + 1;
    }
    for (u8 i = 0; i < SPAN_ID_SIZE_BYTES; i++) {
        publication.tp.span_id[i] = i + 17;
    }
    return publication;
}

static void test_refresh_uses_original_publication_identity(void) {
    const connection_info_t conn = test_connection();
    const connection_info_part_t original_aux_key = {
        .addr = {7},
        .port = 54321,
        .pid = 42,
        .type = FD_SERVER,
    };
    const tp_info_pid_t publication = test_publication();
    const u64 original_owner = 0x2a00000007ULL;

    reset_captures();
    refresh_server_trace_publications(
        &conn, &original_aux_key, &publication, 42, original_owner, k_lw_thread_none, 0);

    trace_map_key_t expected_trace_key = {};
    trace_key_from_conn(&expected_trace_key, &conn, TRACE_TYPE_SERVER);

    assert_bool(1, aux_updates, "refresh updates the auxiliary server publication");
    assert_bytes(&original_aux_key,
                 &captured_aux_key,
                 sizeof(original_aux_key),
                 "refresh keeps the original auxiliary key");
    assert_bytes(&publication,
                 &captured_aux_value,
                 sizeof(publication),
                 "refresh publishes the new auxiliary trace");
    assert_bool(1, trace_updates, "refresh updates the connection publication");
    assert_bytes(&expected_trace_key,
                 &captured_trace_key,
                 sizeof(expected_trace_key),
                 "refresh keeps the original connection key");
    assert_bytes(&publication,
                 &captured_trace_value,
                 sizeof(publication),
                 "refresh publishes the new connection trace");
    assert_bool(1, obi_updates, "refresh updates the profiler context");
    assert_u64(original_owner, captured_obi_key, "refresh uses the original profiler owner");
    assert_bytes(publication.tp.trace_id,
                 captured_obi_value.trace_id,
                 sizeof(captured_obi_value.trace_id),
                 "refresh publishes the profiler trace ID");
    assert_bytes(publication.tp.span_id,
                 captured_obi_value.span_id,
                 sizeof(captured_obi_value.span_id),
                 "refresh publishes the profiler span ID");
    assert_bool(1, flags_updates, "refresh updates the profiler flags");
    assert_u64(original_owner, captured_flags_key, "refresh flags use the original profiler owner");
    assert_bool(publication.tp.flags, captured_flags, "refresh publishes the new trace flags");
}

static void test_virtual_thread_refresh_skips_profiler_context(void) {
    const connection_info_t conn = test_connection();
    const connection_info_part_t aux_key = {
        .port = 54321,
        .pid = 42,
        .type = FD_SERVER,
    };
    const tp_info_pid_t publication = test_publication();

    reset_captures();
    refresh_server_trace_publications(
        &conn, &aux_key, &publication, 42, 0x2a00000007ULL, k_lw_thread_none, 1);

    assert_bool(1, aux_updates, "virtual-thread refresh updates auxiliary state");
    assert_bool(1, trace_updates, "virtual-thread refresh updates connection state");
    assert_bool(0, obi_updates, "virtual-thread refresh skips the profiler context");
    assert_bool(0, flags_updates, "virtual-thread refresh skips profiler flags");
}

static void test_client_refresh_updates_initial_publications(void) {
    const connection_info_t conn = test_connection();
    tp_info_pid_t publication = test_publication();
    publication.req_type = EVENT_HTTP_CLIENT;
    const u64 original_owner = 0x2a00000007ULL;

    reset_captures();
    assert_bool(0,
                refresh_client_trace_publications(&conn, &publication, 42, 9, 0, original_owner, 0),
                "client refresh succeeds");

    const egress_key_t expected_egress = make_egress_key(&conn, 42, 9);
    assert_bool(1, outgoing_updates, "client refresh updates outgoing metadata");
    assert_bytes(&expected_egress,
                 &captured_outgoing_key,
                 sizeof(expected_egress),
                 "client refresh keeps the stream egress key");
    assert_bytes(publication.tp.trace_id,
                 captured_outgoing_value.tp.trace_id,
                 sizeof(publication.tp.trace_id),
                 "client refresh publishes the outgoing trace");
    assert_bool(1, captured_outgoing_value.valid, "plain client metadata stays valid");
    assert_bool(1, trace_updates, "client refresh updates the connection publication");
    assert_bytes(publication.tp.trace_id,
                 captured_trace_value.tp.trace_id,
                 sizeof(publication.tp.trace_id),
                 "client refresh publishes the connection trace");
    assert_bool(1, obi_updates, "plain client refresh updates the profiler context");
    assert_u64(original_owner, captured_obi_key, "client refresh uses the original profiler owner");
}

static void test_ssl_client_refresh_skips_profiler_context(void) {
    const connection_info_t conn = test_connection();
    tp_info_pid_t publication = test_publication();
    publication.req_type = EVENT_HTTP_CLIENT;

    reset_captures();
    assert_bool(
        0,
        refresh_client_trace_publications(&conn, &publication, 42, 9, 1, 0x2a00000007ULL, 0),
        "SSL client refresh succeeds");

    assert_bool(1, outgoing_updates, "SSL client refresh updates outgoing metadata");
    assert_bool(0, captured_outgoing_value.valid, "SSL outgoing metadata stays invalid");
    assert_bool(1, trace_updates, "SSL client refresh updates connection state");
    assert_bool(0, obi_updates, "SSL client refresh skips the profiler context");
    assert_bool(0, flags_updates, "SSL client refresh skips profiler flags");
}

static client_trace_publication_target_t test_publication_target(void) {
    return (client_trace_publication_target_t){
        .owner_pid_tgid = 0x2a00000007ULL,
        .host_pid = 42,
        .stream_id = 9,
    };
}

static tp_info_pid_t test_previous_publication(void) {
    tp_info_pid_t previous = test_publication();
    previous.pid = 7;
    previous.tp.trace_id[0] = 0xa1;
    previous.tp.span_id[0] = 0xb2;
    previous.tp.flags = k_flag_sampled;
    return previous;
}

static void seed_previous_publications(const connection_info_t *conn,
                                       const client_trace_publication_target_t *target,
                                       const tp_info_pid_t *previous) {
    stored_outgoing_key = make_egress_key(conn, target->host_pid, target->stream_id);
    client_trace_publication_values(
        previous, target->host_pid, target->ssl, &stored_outgoing, &stored_obi);
    outgoing_present = 1;

    trace_key_from_conn(&stored_trace_key, conn, TRACE_TYPE_CLIENT);
    stored_trace = *previous;
    trace_present = 1;

    stored_obi_key = target->owner_pid_tgid;
    obi_present = 1;
    stored_flags_key = target->owner_pid_tgid;
    stored_flags = previous->tp.flags;
    flags_present = 1;
}

static void assert_previous_publications(const connection_info_t *conn,
                                         const client_trace_publication_target_t *target,
                                         const tp_info_pid_t *previous) {
    const egress_key_t expected_egress = make_egress_key(conn, target->host_pid, target->stream_id);
    trace_map_key_t expected_trace_key = {};
    trace_key_from_conn(&expected_trace_key, conn, TRACE_TYPE_CLIENT);
    tp_info_pid_t expected_outgoing = {};
    obi_ctx_info_t expected_obi = {};
    client_trace_publication_values(
        previous, target->host_pid, target->ssl, &expected_outgoing, &expected_obi);

    assert_bool(1, outgoing_present, "rollback restores prior outgoing presence");
    assert_bytes(&expected_egress,
                 &stored_outgoing_key,
                 sizeof(expected_egress),
                 "rollback restores the prior outgoing key");
    assert_bytes(&expected_outgoing,
                 &stored_outgoing,
                 sizeof(expected_outgoing),
                 "rollback restores the prior outgoing value");
    assert_bool(1, trace_present, "rollback restores prior trace presence");
    assert_bytes(&expected_trace_key,
                 &stored_trace_key,
                 sizeof(expected_trace_key),
                 "rollback restores the prior trace key");
    assert_bytes(
        previous, &stored_trace, sizeof(*previous), "rollback restores the prior trace value");
    assert_bool(1, obi_present, "rollback restores prior owner context presence");
    assert_u64(
        target->owner_pid_tgid, stored_obi_key, "rollback restores the prior owner context key");
    assert_bytes(
        &expected_obi, &stored_obi, sizeof(expected_obi), "rollback restores prior owner context");
    assert_bool(1, flags_present, "rollback restores prior flags presence");
    assert_u64(target->owner_pid_tgid, stored_flags_key, "rollback restores the prior flags key");
    assert_bool(previous->tp.flags, stored_flags, "rollback restores the prior flags");
}

static void assert_no_publications(void) {
    assert_bool(0, outgoing_present, "rollback deletes newly inserted outgoing state");
    assert_bool(0, trace_present, "rollback deletes newly inserted trace state");
    assert_bool(0, obi_present, "rollback deletes newly inserted owner context");
    assert_bool(0, flags_present, "rollback deletes newly inserted flags");
}

static void
assert_connection_claim_released(const client_trace_publication_transaction_t *transaction) {
    assert_bool(0, claim_present, "finish releases the connection egress claim");
    assert_bool(1, claim_deletes, "finish deletes the connection egress claim");
    assert_bool(0,
                transaction->connection_claim_acquired,
                "finish clears the acquired connection claim marker");
}

static void test_client_publication_success_order(void) {
    const connection_info_t conn = test_connection();
    tp_info_pid_t publication = test_publication();
    publication.req_type = EVENT_HTTP_CLIENT;
    const client_trace_publication_target_t target = test_publication_target();
    client_trace_publication_transaction_t transaction = {};

    reset_captures();
    assert_bool(0,
                begin_client_trace_publications(&conn, &publication, &target, &transaction),
                "transaction begin succeeds");

    assert_bool(4, publication_update_count, "transaction updates all publication maps");
    assert_map_order(publication_map_outgoing,
                     publication_update_order[0],
                     "transaction updates outgoing state first");
    assert_map_order(publication_map_trace,
                     publication_update_order[1],
                     "transaction updates trace state second");
    assert_map_order(publication_map_obi,
                     publication_update_order[2],
                     "transaction updates owner context third");
    assert_map_order(
        publication_map_flags, publication_update_order[3], "transaction updates flags fourth");
    assert_bool(1, claim_present, "transaction holds the connection egress claim");
    assert_bool(1,
                transaction.connection_claim_acquired,
                "transaction records the acquired connection claim");

    finish_client_trace_publications(&conn, &target, &transaction);
    assert_connection_claim_released(&transaction);
}

static void test_client_publication_update_failures_roll_back(void) {
    const publication_map_t failed_maps[] = {
        publication_map_outgoing,
        publication_map_trace,
        publication_map_obi,
        publication_map_flags,
    };
    const connection_info_t conn = test_connection();
    tp_info_pid_t publication = test_publication();
    publication.req_type = EVENT_HTTP_CLIENT;
    const tp_info_pid_t previous = test_previous_publication();
    const client_trace_publication_target_t target = test_publication_target();

    for (unsigned int prior_present = 0; prior_present <= 1; prior_present++) {
        for (unsigned int failed_index = 0;
             failed_index < sizeof(failed_maps) / sizeof(failed_maps[0]);
             failed_index++) {
            client_trace_publication_transaction_t transaction = {};

            reset_captures();
            if (prior_present) {
                seed_previous_publications(&conn, &target, &previous);
            }
            fail_next_update = failed_maps[failed_index];

            assert_bool(-1,
                        begin_client_trace_publications(&conn, &publication, &target, &transaction),
                        "injected forward update failure aborts transaction begin");
            assert_bool(publication_map_none,
                        fail_next_update,
                        "transaction reaches the injected forward update");
            assert_bool((int)failed_index + 1,
                        publication_update_count,
                        "transaction stops at the failed forward update");
            assert_bool(1, claim_present, "failed transaction still holds its connection claim");

            rollback_client_trace_publications(&conn, &publication, &target, &transaction);
            if (prior_present) {
                assert_previous_publications(&conn, &target, &previous);
            } else {
                assert_no_publications();
            }

            finish_client_trace_publications(&conn, &target, &transaction);
            assert_connection_claim_released(&transaction);
        }
    }
}

static void test_event_publication_failure_rolls_back(void) {
    const connection_info_t conn = test_connection();
    tp_info_pid_t publication = test_publication();
    publication.req_type = EVENT_HTTP_CLIENT;
    const tp_info_pid_t previous = test_previous_publication();
    const client_trace_publication_target_t target = test_publication_target();

    for (unsigned int prior_present = 0; prior_present <= 1; prior_present++) {
        client_trace_publication_transaction_t transaction = {};

        reset_captures();
        if (prior_present) {
            seed_previous_publications(&conn, &target, &previous);
        }
        assert_bool(0,
                    begin_client_trace_publications(&conn, &publication, &target, &transaction),
                    "publication transaction succeeds before event submission");

        const int event_publication_result = -1;
        assert_bool(-1, event_publication_result, "event publication failure is simulated");
        rollback_client_trace_publications(&conn, &publication, &target, &transaction);
        if (prior_present) {
            assert_previous_publications(&conn, &target, &previous);
        } else {
            assert_no_publications();
            assert_bool(1, outgoing_deletes, "event failure deletes new outgoing state");
            assert_bool(1, trace_deletes, "event failure deletes new trace state");
            assert_bool(1, obi_deletes, "event failure deletes new owner context");
            assert_bool(1, flags_deletes, "event failure deletes new flags");
        }
        finish_client_trace_publications(&conn, &target, &transaction);
        assert_connection_claim_released(&transaction);
    }
}

static void test_outgoing_noexist_conflict_preserves_existing_value(void) {
    const connection_info_t conn = test_connection();
    tp_info_pid_t publication = test_publication();
    publication.req_type = EVENT_HTTP_CLIENT;
    const tp_info_pid_t previous = test_previous_publication();
    client_trace_publication_target_t target = test_publication_target();
    client_trace_publication_transaction_t transaction = {};
    target.outgoing_noexist = 1;

    reset_captures();
    stored_outgoing_key = make_egress_key(&conn, target.host_pid, target.stream_id);
    client_trace_publication_values(
        &previous, target.host_pid, target.ssl, &stored_outgoing, &stored_obi);
    const tp_info_pid_t expected_outgoing = stored_outgoing;
    outgoing_present = 1;

    assert_bool(-1,
                begin_client_trace_publications(&conn, &publication, &target, &transaction),
                "BPF_NOEXIST conflict aborts transaction begin");
    assert_bool(1, transaction.outgoing_present, "transaction records the conflicting value");
    assert_bool(0,
                transaction.outgoing_updated,
                "BPF_NOEXIST conflict does not mark outgoing state updated");

    rollback_client_trace_publications(&conn, &publication, &target, &transaction);
    assert_bool(1, outgoing_present, "rollback preserves the conflicting outgoing value");
    assert_bytes(&expected_outgoing,
                 &stored_outgoing,
                 sizeof(expected_outgoing),
                 "rollback leaves the conflicting outgoing value unchanged");
    assert_bool(0, outgoing_deletes, "rollback does not delete the conflicting outgoing value");
    finish_client_trace_publications(&conn, &target, &transaction);
    assert_connection_claim_released(&transaction);
}

static void seed_owner_context(u64 owner_pid_tgid, const tp_info_t *trace) {
    stored_obi_key = owner_pid_tgid;
    memcpy(stored_obi.trace_id, trace->trace_id, sizeof(stored_obi.trace_id));
    memcpy(stored_obi.span_id, trace->span_id, sizeof(stored_obi.span_id));
    obi_present = 1;
    stored_flags_key = owner_pid_tgid;
    stored_flags = trace->flags;
    flags_present = 1;
}

static void test_cleanup_uses_original_publication_identity(void) {
    pid_connection_info_t pid_conn = {
        .conn = test_connection(),
        .pid = 42,
    };
    trace_key_t trace_key = {
        .p_key =
            {
                .tid = 7,
                .pid = 42,
                .ns = 11,
            },
    };
    const u64 original_owner = 0x2a00000007ULL;
    const tp_info_pid_t publication = test_publication();

    reset_captures();
    seed_owner_context(original_owner, &publication.tp);
    delete_server_trace_for_owner(&pid_conn, &trace_key, original_owner, &publication.tp);

    assert_bool(1, obi_deletes, "cleanup deletes the profiler context");
    assert_u64(original_owner, deleted_obi_key, "cleanup deletes the original profiler owner");
    assert_bool(1, flags_deletes, "cleanup deletes the profiler flags");
    assert_u64(original_owner, deleted_flags_key, "cleanup flags use the original profiler owner");
    assert_bool(0,
                deleted_obi_key == test_current_pid_tgid(),
                "cleanup does not delete the continuation owner");
}

static void test_server_cleanup_preserves_newer_same_thread_context(void) {
    pid_connection_info_t pid_conn = {
        .conn = test_connection(),
        .pid = 42,
    };
    trace_key_t trace_key = {
        .p_key =
            {
                .tid = 7,
                .pid = 42,
                .ns = 11,
            },
    };
    const u64 owner = 0x2a00000007ULL;
    const tp_info_pid_t completed = test_publication();

    for (u8 changed_field = 0; changed_field < 3; changed_field++) {
        tp_info_pid_t newer = test_publication();
        if (changed_field == 0) {
            newer.tp.trace_id[0] ^= 0xff;
        } else if (changed_field == 1) {
            newer.tp.span_id[0] ^= 0xff;
        } else {
            newer.tp.flags ^= k_flag_sampled;
        }

        reset_captures();
        seed_owner_context(owner, &newer.tp);
        const obi_ctx_info_t expected_obi = stored_obi;
        const u8 expected_flags = stored_flags;

        delete_server_trace_for_owner(&pid_conn, &trace_key, owner, &completed.tp);

        assert_bool(0, obi_deletes, "older cleanup preserves a newer profiler context");
        assert_bool(0, flags_deletes, "older cleanup preserves newer profiler flags");
        assert_bool(1, obi_present, "newer profiler context remains present");
        assert_bool(1, flags_present, "newer profiler flags remain present");
        assert_bytes(&expected_obi,
                     &stored_obi,
                     sizeof(expected_obi),
                     "newer profiler context remains unchanged");
        assert_bool(expected_flags, stored_flags, "newer profiler flags remain unchanged");
    }
}

static void test_virtual_thread_cleanup_skips_profiler_context(void) {
    pid_connection_info_t pid_conn = {
        .conn = test_connection(),
        .pid = 42,
    };
    trace_key_t trace_key = {
        .p_key =
            {
                .tid = JAVA_VT_TID_FLAG | 7,
                .pid = 42,
                .ns = 11,
            },
    };
    const tp_info_pid_t publication = test_publication();

    reset_captures();
    delete_server_trace_for_owner(&pid_conn, &trace_key, 0x2a00000007ULL, &publication.tp);

    assert_bool(0, obi_deletes, "virtual-thread cleanup skips the profiler context");
    assert_bool(0, flags_deletes, "virtual-thread cleanup skips profiler flags");
}

int main(void) {
    test_refresh_uses_original_publication_identity();
    test_virtual_thread_refresh_skips_profiler_context();
    test_client_refresh_updates_initial_publications();
    test_ssl_client_refresh_skips_profiler_context();
    test_client_publication_success_order();
    test_client_publication_update_failures_roll_back();
    test_event_publication_failure_rolls_back();
    test_outgoing_noexist_conflict_preserves_existing_value();
    test_cleanup_uses_original_publication_identity();
    test_server_cleanup_preserves_newer_same_thread_context();
    test_virtual_thread_cleanup_skips_profiler_context();
    return failures ? 1 : 0;
}
