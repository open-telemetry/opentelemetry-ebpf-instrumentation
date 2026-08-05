// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

static uint64_t test_process_start = 777;

static inline unsigned long long test_pid_tgid(void) {
    return 42ULL << 32;
}

static inline unsigned long long test_process_start_time(void) {
    return test_process_start;
}

static inline unsigned int bpf_get_smp_processor_id(void) {
    return 0;
}

static inline unsigned int bpf_get_prandom_u32(void) {
    return 0;
}

static inline unsigned long long bpf_ktime_get_ns(void) {
    return 1000;
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

#define OBI_CURRENT_PROCESS_START_TIME_NS() test_process_start_time()
#define OBI_CURRENT_PROCESS_START_BOOTTIME_NS() test_process_start_time()
#define bpf_get_current_pid_tgid test_pid_tgid

static void *test_map_lookup(void *map, const void *key);
static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags);
static long test_map_delete(void *map, const void *key);

#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2
#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete

#include <gotracer/maps/grpc.h>

#undef bpf_map_delete_elem
#undef bpf_map_update_elem
#undef bpf_map_lookup_elem

enum {
    k_test_slots = 8,
};

typedef struct canonical_slot {
    grpc_client_request_id_t key;
    grpc_client_func_invocation_t value;
    u8 present;
} canonical_slot_t;

typedef struct ref_slot {
    grpc_client_handoff_slot_key_t key;
    go_outgoing_trace_handoff_ref_t value;
    u8 present;
} ref_slot_t;

typedef struct authority_slot {
    outgoing_trace_handoff_key_t key;
    outgoing_trace_handoff_t value;
    u8 present;
} authority_slot_t;

static canonical_slot_t canonicals[k_test_slots];
static ref_slot_t refs[k_test_slots];
static authority_slot_t authorities[k_test_slots];

static grpc_client_request_id_t handoff_state_key;
static u8 handoff_state;
static u8 handoff_state_present;
static grpc_client_request_id_t request_claim_key;
static u8 request_claim_present;
static go_addr_key_t stream_claim_key;
static u8 stream_claim_present;
static go_addr_key_t stream_key;
static grpc_client_request_id_t stream_value;
static u8 stream_present;
static go_addr_key_t creator_key;
static grpc_client_func_invocation_t creator_value;
static u8 creator_present;
static go_addr_key_t creator_claim_key;
static u8 creator_claim_present;
static outgoing_trace_handoff_key_t authority_claim_key;
static u8 authority_claim_present;
static egress_key_t egress_claim_key;
static u8 egress_claim_present;
static egress_key_t locator_key;
static outgoing_trace_token_t locator_value;
static u8 locator_present;
static u8 defer_terminal_on_ref_insert;
static u8 verify_registration_handshake_on_ref_insert;
static u8 registration_held_authority_claim;
static u8 registration_refreshed_progress;
static u8 registration_blocked_reaper_claim;
static u8 failures;

static u8 request_ids_equal(const grpc_client_request_id_t *left,
                            const grpc_client_request_id_t *right) {
    return memcmp(left, right, sizeof(*left)) == 0;
}

static canonical_slot_t *find_canonical(const grpc_client_request_id_t *key) {
    for (u8 i = 0; i < k_test_slots; i++) {
        if (canonicals[i].present && request_ids_equal(&canonicals[i].key, key)) {
            return &canonicals[i];
        }
    }
    return NULL;
}

static ref_slot_t *find_ref(const grpc_client_handoff_slot_key_t *key) {
    for (u8 i = 0; i < k_test_slots; i++) {
        if (refs[i].present && memcmp(&refs[i].key, key, sizeof(*key)) == 0) {
            return &refs[i];
        }
    }
    return NULL;
}

static authority_slot_t *find_authority(const outgoing_trace_handoff_key_t *key) {
    for (u8 i = 0; i < k_test_slots; i++) {
        if (authorities[i].present && memcmp(&authorities[i].key, key, sizeof(*key)) == 0) {
            return &authorities[i];
        }
    }
    return NULL;
}

static void *test_map_lookup(void *map, const void *key) {
    if (map == &grpc_client_request_states) {
        canonical_slot_t *slot = find_canonical(key);
        return slot ? &slot->value : NULL;
    }
    if (map == &grpc_client_request_handoff_states && handoff_state_present &&
        request_ids_equal(key, &handoff_state_key)) {
        return &handoff_state;
    }
    if (map == &grpc_client_request_handoffs) {
        ref_slot_t *slot = find_ref(key);
        return slot ? &slot->value : NULL;
    }
    if (map == &grpc_client_stream_requests && stream_present &&
        memcmp(key, &stream_key, sizeof(stream_key)) == 0) {
        return &stream_value;
    }
    if (map == &ongoing_grpc_client_requests && creator_present &&
        memcmp(key, &creator_key, sizeof(creator_key)) == 0) {
        return &creator_value;
    }
    if (map == &outgoing_trace_handoff) {
        authority_slot_t *slot = find_authority(key);
        return slot ? &slot->value : NULL;
    }
    if (map == &outgoing_trace_handoff_locators && locator_present &&
        memcmp(key, &locator_key, sizeof(locator_key)) == 0) {
        return &locator_value;
    }
    return NULL;
}

static long put_ref(const grpc_client_handoff_slot_key_t *key,
                    const go_outgoing_trace_handoff_ref_t *value,
                    unsigned long long flags) {
    ref_slot_t *slot = find_ref(key);
    if (slot && flags == BPF_NOEXIST) {
        return -1;
    }
    if (!slot) {
        for (u8 i = 0; i < k_test_slots; i++) {
            if (!refs[i].present) {
                slot = &refs[i];
                slot->present = 1;
                slot->key = *key;
                break;
            }
        }
    }
    if (!slot) {
        return -1;
    }
    slot->value = *value;
    if (verify_registration_handshake_on_ref_insert) {
        const outgoing_trace_handoff_key_t exact =
            outgoing_trace_handoff_key(&value->egress, &value->token);
        authority_slot_t *authority = find_authority(&exact);
        registration_held_authority_claim =
            authority_claim_present && memcmp(&authority_claim_key, &exact, sizeof(exact)) == 0;
        registration_refreshed_progress =
            authority && authority->value.last_progress == bpf_ktime_get_ns();
        registration_blocked_reaper_claim = !claim_outgoing_trace_handoff_key(&exact);
        if (!registration_blocked_reaper_claim) {
            release_outgoing_trace_handoff_key(&exact);
        }
    }
    if (defer_terminal_on_ref_insert) {
        defer_terminal_on_ref_insert = 0;
        defer_grpc_client_request_terminal(&key->request_id, 1);
    }
    return 0;
}

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    if (map == &grpc_client_request_handoff_claims) {
        if (request_claim_present) {
            return -1;
        }
        request_claim_key = *(const grpc_client_request_id_t *)key;
        request_claim_present = 1;
        return 0;
    }
    if (map == &grpc_client_stream_request_claims) {
        if (stream_claim_present) {
            return -1;
        }
        stream_claim_key = *(const go_addr_key_t *)key;
        stream_claim_present = 1;
        return 0;
    }
    if (map == &grpc_client_creator_request_claims) {
        if (creator_claim_present) {
            return -1;
        }
        creator_claim_key = *(const go_addr_key_t *)key;
        creator_claim_present = 1;
        return 0;
    }
    if (map == &grpc_client_request_handoff_states) {
        if (flags == BPF_NOEXIST && handoff_state_present) {
            return -1;
        }
        if (flags == BPF_EXIST && !handoff_state_present) {
            return -1;
        }
        handoff_state_key = *(const grpc_client_request_id_t *)key;
        handoff_state = *(const u8 *)value;
        handoff_state_present = 1;
        return 0;
    }
    if (map == &grpc_client_request_handoffs) {
        return put_ref(key, value, flags);
    }
    if (map == &grpc_client_stream_requests) {
        if (flags == BPF_NOEXIST && stream_present) {
            return -1;
        }
        stream_key = *(const go_addr_key_t *)key;
        stream_value = *(const grpc_client_request_id_t *)value;
        stream_present = 1;
        return 0;
    }
    if (map == &ongoing_grpc_client_requests) {
        creator_key = *(const go_addr_key_t *)key;
        creator_value = *(const grpc_client_func_invocation_t *)value;
        creator_present = 1;
        return 0;
    }
    if (map == &outgoing_trace_handoff_claims) {
        if (authority_claim_present) {
            return -1;
        }
        authority_claim_key = *(const outgoing_trace_handoff_key_t *)key;
        authority_claim_present = 1;
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
    return -1;
}

static long test_map_delete(void *map, const void *key) {
    if (map == &grpc_client_request_handoff_claims && request_claim_present &&
        request_ids_equal(key, &request_claim_key)) {
        request_claim_present = 0;
        return 0;
    }
    if (map == &grpc_client_stream_request_claims && stream_claim_present &&
        memcmp(key, &stream_claim_key, sizeof(stream_claim_key)) == 0) {
        stream_claim_present = 0;
        return 0;
    }
    if (map == &grpc_client_creator_request_claims && creator_claim_present &&
        memcmp(key, &creator_claim_key, sizeof(creator_claim_key)) == 0) {
        creator_claim_present = 0;
        return 0;
    }
    if (map == &grpc_client_request_handoff_states && handoff_state_present &&
        request_ids_equal(key, &handoff_state_key)) {
        handoff_state_present = 0;
        return 0;
    }
    if (map == &grpc_client_request_handoffs) {
        ref_slot_t *slot = find_ref(key);
        if (slot) {
            slot->present = 0;
            return 0;
        }
    }
    if (map == &grpc_client_stream_requests && stream_present &&
        memcmp(key, &stream_key, sizeof(stream_key)) == 0) {
        stream_present = 0;
        return 0;
    }
    if (map == &ongoing_grpc_client_requests && creator_present &&
        memcmp(key, &creator_key, sizeof(creator_key)) == 0) {
        creator_present = 0;
        return 0;
    }
    if (map == &grpc_client_request_states) {
        canonical_slot_t *slot = find_canonical(key);
        if (slot) {
            slot->present = 0;
            return 0;
        }
    }
    if (map == &outgoing_trace_handoff_claims && authority_claim_present &&
        memcmp(key, &authority_claim_key, sizeof(authority_claim_key)) == 0) {
        authority_claim_present = 0;
        return 0;
    }
    if (map == &outgoing_trace_handoff_egress_claims && egress_claim_present &&
        memcmp(key, &egress_claim_key, sizeof(egress_claim_key)) == 0) {
        egress_claim_present = 0;
        return 0;
    }
    if (map == &outgoing_trace_handoff) {
        authority_slot_t *slot = find_authority(key);
        if (slot) {
            slot->present = 0;
            return 0;
        }
    }
    if (map == &outgoing_trace_handoff_locators && locator_present &&
        memcmp(key, &locator_key, sizeof(locator_key)) == 0) {
        locator_present = 0;
        return 0;
    }
    return -1;
}

static grpc_client_request_id_t test_request(u64 start, u64 sequence) {
    return (grpc_client_request_id_t){
        .creator = {.pid = 42, .addr = 0x1234 + sequence},
        .process_start_time = start,
        .sequence = sequence,
        .cpu = 1,
    };
}

static go_outgoing_trace_handoff_ref_t test_ref(u64 sequence) {
    return (go_outgoing_trace_handoff_ref_t){
        .egress = {.pid = 42, .stream_id = (u32)sequence},
        .token =
            {
                .map_epoch = 1,
                .sequence = sequence,
                .process_start_time = test_process_start,
                .cpu = 1,
            },
    };
}

static canonical_slot_t *add_canonical(grpc_client_request_id_t id, go_addr_key_t stable_stream) {
    canonical_slot_t *slot = NULL;
    for (u8 i = 0; i < k_test_slots; i++) {
        if (!canonicals[i].present) {
            slot = &canonicals[i];
            break;
        }
    }
    if (!slot) {
        return NULL;
    }
    *slot = (canonical_slot_t){
        .key = id,
        .value =
            {
                .request_id = id,
                .stream_key = stable_stream,
                .has_stream = 1,
            },
        .present = 1,
    };
    return slot;
}

static canonical_slot_t *add_request(grpc_client_request_id_t id, go_addr_key_t stable_stream) {
    canonical_slot_t *slot = add_canonical(id, stable_stream);
    if (!slot) {
        return NULL;
    }
    creator_key = id.creator;
    creator_value = slot->value;
    creator_present = 1;
    stream_key = stable_stream;
    stream_value = id;
    stream_present = 1;
    return slot;
}

static void add_authority(go_outgoing_trace_handoff_ref_t ref) {
    for (u8 i = 0; i < k_test_slots; i++) {
        if (!authorities[i].present) {
            authorities[i].present = 1;
            authorities[i].key = outgoing_trace_handoff_key(&ref.egress, &ref.token);
            authorities[i].value.tp = (tp_info_pid_t){
                .pid = 42,
                .valid = 1,
                .req_type = EVENT_HTTP_CLIENT,
            };
            locator_key = ref.egress;
            locator_value = ref.token;
            locator_present = 1;
            return;
        }
    }
}

static void reset_state(void) {
    memset(canonicals, 0, sizeof(canonicals));
    memset(refs, 0, sizeof(refs));
    memset(authorities, 0, sizeof(authorities));
    handoff_state_present = 0;
    request_claim_present = 0;
    stream_claim_present = 0;
    stream_present = 0;
    creator_present = 0;
    creator_claim_present = 0;
    authority_claim_present = 0;
    egress_claim_present = 0;
    locator_present = 0;
    defer_terminal_on_ref_insert = 0;
    verify_registration_handshake_on_ref_insert = 0;
    registration_held_authority_claim = 0;
    registration_refreshed_progress = 0;
    registration_blocked_reaper_claim = 0;
    test_process_start = 777;
}

static void assert_true(u8 value, const char *message) {
    if (value) {
        return;
    }
    fprintf(stderr, "%s\n", message);
    failures++;
}

static u8 refs_present(void) {
    for (u8 i = 0; i < k_test_slots; i++) {
        if (refs[i].present) {
            return 1;
        }
    }
    return 0;
}

static u8 authority_present(void) {
    for (u8 i = 0; i < k_test_slots; i++) {
        if (authorities[i].present) {
            return 1;
        }
    }
    return 0;
}

enum terminal_phase {
    terminal_before_registration,
    terminal_during_registration,
    terminal_after_registration,
};

static void run_terminal_race(enum terminal_phase phase) {
    reset_state();
    const grpc_client_request_id_t id = test_request(test_process_start, 1);
    const go_addr_key_t stable_stream = {.pid = 42, .addr = 0xbeef};
    canonical_slot_t *canonical = add_request(id, stable_stream);
    const go_outgoing_trace_handoff_ref_t ref = test_ref(1);
    add_authority(ref);

    if (phase == terminal_before_registration) {
        defer_grpc_client_request_terminal(&id, 1);
    }
    assert_true(claim_grpc_client_request_handoffs(&id), "publisher acquires exact request claim");
    if (phase == terminal_during_registration) {
        defer_terminal_on_ref_insert = 1;
    }
    const u8 registration =
        register_claimed_grpc_client_request_handoff(&id, &ref.egress, &ref.token);
    if (phase == terminal_after_registration) {
        assert_true(canonical && !canonical->value.terminal,
                    "publisher final check can precede terminal store");
        defer_grpc_client_request_terminal(&id, 1);
        release_grpc_client_request_handoffs(&id);
        assert_true(claim_grpc_client_request_handoffs(&id),
                    "post-release observation reacquires deferred terminal");
    }

    assert_true(canonical && canonical->value.terminal,
                "terminal outcome is retained in canonical state");
    assert_true(mark_grpc_client_request_terminal_emitted(&id),
                "exact claim owner emits the terminal span once");
    assert_true(!mark_grpc_client_request_terminal_emitted(&id),
                "terminal span cannot be emitted twice");
    cleanup_claimed_grpc_client_request(&id);
    if (registration != k_grpc_client_handoff_registered) {
        request_outgoing_trace_handoff_retirement(&ref.egress, &ref.token, NULL, 0);
    }
    release_grpc_client_request_handoffs(&id);

    assert_true(!find_canonical(&id), "canonical state is retired");
    assert_true(!creator_present, "creator locator is retired");
    assert_true(!stream_present, "stream locator is retired");
    assert_true(!refs_present(), "reverse references are retired");
    assert_true(!handoff_state_present, "handoff state is retired");
    assert_true(!authority_present(), "exact authority is retired");
    assert_true(!locator_present, "authority locator is retired");
    assert_true(!request_claim_present, "request claim is released");
    assert_true(!stream_claim_present, "stream claim is released");
}

static void test_stream_cleanup_never_deletes_new_generation(void) {
    reset_state();
    const grpc_client_request_id_t old_id = test_request(test_process_start, 1);
    const grpc_client_request_id_t new_id = test_request(test_process_start, 2);
    const go_addr_key_t reused_stream = {.pid = 42, .addr = 0xcafe};
    add_request(old_id, reused_stream);
    stream_value = new_id;

    assert_true(claim_grpc_client_request_handoffs(&old_id),
                "old request cleanup acquires its exact claim");
    cleanup_claimed_grpc_client_request(&old_id);
    release_grpc_client_request_handoffs(&old_id);

    assert_true(stream_present && request_ids_equal(&stream_value, &new_id),
                "delayed cleanup preserves the replacement stream generation");
}

static void test_stream_collision_reclaims_only_dead_incarnation(void) {
    reset_state();
    const grpc_client_request_id_t old_id = test_request(666, 1);
    const grpc_client_request_id_t new_id = test_request(test_process_start, 2);
    const go_addr_key_t reused_stream = {.pid = 42, .addr = 0xd00d};
    stream_key = reused_stream;
    stream_value = old_id;
    stream_present = 1;

    assert_true(reserve_grpc_client_stream_request(&reused_stream, &new_id),
                "dead-incarnation locator is reclaimed");
    assert_true(stream_present && request_ids_equal(&stream_value, &new_id),
                "reclaimed locator carries only the new exact generation");

    canonical_slot_t *live = add_request(new_id, reused_stream);
    const grpc_client_request_id_t contender = test_request(test_process_start, 3);
    assert_true(live && !reserve_grpc_client_stream_request(&reused_stream, &contender),
                "current live locator is never overwritten");
    assert_true(request_ids_equal(&stream_value, &new_id),
                "live collision preserves the incumbent generation");
}

static void test_creator_cleanup_never_deletes_new_generation(void) {
    reset_state();
    const grpc_client_request_id_t old_id = test_request(test_process_start, 1);
    grpc_client_request_id_t new_id = test_request(test_process_start, 2);
    new_id.creator = old_id.creator;
    const go_addr_key_t stable_stream = {.pid = 42, .addr = 0xabcd};
    add_request(old_id, stable_stream);
    grpc_client_func_invocation_t replacement = {
        .request_id = new_id,
        .request_key = new_id.creator,
    };

    assert_true(publish_grpc_client_creator_request(&new_id.creator, &replacement),
                "new creator generation publishes under its locator claim");
    assert_true(delete_grpc_client_creator_request_exact(&old_id.creator, &old_id) == 0,
                "delayed old cleanup does not match the replacement");
    assert_true(creator_present &&
                    grpc_client_request_ids_match(&creator_value.request_id, &new_id),
                "delayed old cleanup preserves the replacement generation");
    assert_true(!creator_claim_present, "creator locator claim is released");
}

static void test_creator_publication_claim_failure_drops_canonical(void) {
    reset_state();
    const grpc_client_request_id_t old_id = test_request(test_process_start, 1);
    grpc_client_request_id_t new_id = test_request(test_process_start, 2);
    new_id.creator = old_id.creator;
    const go_addr_key_t stable_stream = {.pid = 42, .addr = 0xbcde};
    add_request(old_id, stable_stream);
    canonical_slot_t *fresh = add_canonical(new_id, stable_stream);
    assert_true(fresh != NULL, "fresh canonical exists before publication");
    grpc_client_func_invocation_t replacement =
        fresh ? fresh->value : (grpc_client_func_invocation_t){};

    creator_claim_key = old_id.creator;
    creator_claim_present = 1;
    assert_true(!publish_grpc_client_creator_request(&new_id.creator, &replacement),
                "creator claim contention fails publication closed");
    assert_true(!find_canonical(&new_id), "failed publication removes its orphan canonical");
    assert_true(creator_present &&
                    grpc_client_request_ids_match(&creator_value.request_id, &old_id),
                "failed replacement preserves the incumbent locator");
    assert_true(creator_claim_present, "failed contender never releases the incumbent claim");
}

static void test_terminal_authority_cannot_be_reauthorized(void) {
    reset_state();
    const go_outgoing_trace_handoff_ref_t ref = test_ref(9);
    add_authority(ref);
    const outgoing_trace_handoff_key_t exact = outgoing_trace_handoff_key(&ref.egress, &ref.token);
    authority_claim_key = exact;
    authority_claim_present = 1;

    // Model the claim owner having completed its final retirement check. The
    // cleanup loser stores the terminal outcome and loses its one retry while
    // that owner still holds the exact claim.
    request_outgoing_trace_handoff_retirement(&ref.egress, &ref.token, NULL, 0);
    authority_slot_t *slot = find_authority(&exact);
    assert_true(slot && slot->value.retire_requested && slot->value.terminal_at &&
                    slot->value.terminal_reason == k_outgoing_trace_terminal_owner_cleanup,
                "retirement loser leaves an explicit terminal outcome");
    assert_true(authority_claim_present, "retirement retry loses to the original claim owner");

    authority_claim_present = 0;
    tp_info_pid_t snapshot = {};
    assert_true(
        !claim_outgoing_trace_handoff(
            &ref.egress, &ref.token, ref.egress.pid, EVENT_HTTP_CLIENT, NULL, 0, 1, &snapshot),
        "later exact claim rejects terminal authority");
    assert_true(!snapshot_outgoing_trace_handoff(
                    &ref.egress, &ref.token, ref.egress.pid, EVENT_HTTP_CLIENT, 1, &snapshot, NULL),
                "later snapshot rejects terminal authority");
    outgoing_trace_token_t resolved = {};
    assert_true(
        resolve_and_claim_current_outgoing_trace_handoff(
            &ref.egress, ref.egress.pid, EVENT_HTTP_CLIENT, NULL, 0, 1, &resolved, &snapshot) ==
            k_outgoing_trace_fail_closed,
        "terminal current locator resolves fail closed");
    assert_true(!authority_claim_present, "rejected consumer releases its exact claim");

    request_outgoing_trace_handoff_retirement(&ref.egress, &ref.token, NULL, 0);
    assert_true(!find_authority(&exact), "exact cleanup may still retire terminal authority");
}

static u8 resolve_test_ref(const go_outgoing_trace_handoff_ref_t *ref) {
    outgoing_trace_token_t resolved = {};
    tp_info_pid_t snapshot = {};
    return resolve_and_claim_current_outgoing_trace_handoff(
        &ref->egress, ref->egress.pid, EVENT_HTTP_CLIENT, NULL, 1, 1, &resolved, &snapshot);
}

static void test_current_resolution_is_tri_state(void) {
    go_outgoing_trace_handoff_ref_t ref = test_ref(10);

    reset_state();
    assert_true(resolve_test_ref(&ref) == k_outgoing_trace_absent,
                "missing locator is the only absent outcome");

    reset_state();
    add_authority(ref);
    assert_true(resolve_test_ref(&ref) == k_outgoing_trace_exact,
                "live exact authority is claimable");
    release_claimed_outgoing_trace_handoff(&ref.egress, &ref.token);

    reset_state();
    locator_key = ref.egress;
    locator_value = ref.token;
    locator_present = 1;
    assert_true(resolve_test_ref(&ref) == k_outgoing_trace_fail_closed,
                "locator with missing authority fails closed");

    reset_state();
    ref.token.process_start_time = test_process_start - 1;
    add_authority(ref);
    assert_true(resolve_test_ref(&ref) == k_outgoing_trace_fail_closed,
                "stale-incarnation authority fails closed");

    reset_state();
    ref = test_ref(11);
    add_authority(ref);
    authority_claim_key = outgoing_trace_handoff_key(&ref.egress, &ref.token);
    authority_claim_present = 1;
    assert_true(resolve_test_ref(&ref) == k_outgoing_trace_fail_closed,
                "claim contention fails closed");

    reset_state();
    ref = test_ref(12);
    add_authority(ref);
    authority_slot_t *slot = find_authority(&(outgoing_trace_handoff_key_t){
        .egress = ref.egress,
        .token = ref.token,
    });
    assert_true(slot != NULL, "consumed test authority exists");
    if (slot) {
        slot->value.local_consumed = 1;
    }
    assert_true(resolve_test_ref(&ref) == k_outgoing_trace_fail_closed,
                "already-consumed authority fails closed");

    reset_state();
    ref = test_ref(13);
    add_authority(ref);
    slot = find_authority(&(outgoing_trace_handoff_key_t){
        .egress = ref.egress,
        .token = ref.token,
    });
    assert_true(slot != NULL, "terminal test authority exists");
    if (slot) {
        slot->value.terminal_at = 1;
        slot->value.terminal_reason = k_outgoing_trace_terminal_owner_cleanup;
    }
    assert_true(resolve_test_ref(&ref) == k_outgoing_trace_fail_closed,
                "terminal authority fails closed");
}

static void test_reference_registration_refreshes_before_publish(void) {
    reset_state();
    const grpc_client_request_id_t id = test_request(test_process_start, 21);
    add_request(id, (go_addr_key_t){.pid = 42, .addr = 0xdada});
    const go_outgoing_trace_handoff_ref_t ref = test_ref(21);
    add_authority(ref);
    const outgoing_trace_handoff_key_t exact = outgoing_trace_handoff_key(&ref.egress, &ref.token);
    authority_slot_t *slot = find_authority(&exact);
    assert_true(slot != NULL, "registration authority exists");
    if (slot) {
        slot->value.last_progress = 1;
    }

    assert_true(claim_grpc_client_request_handoffs(&id), "publisher owns canonical request");
    verify_registration_handshake_on_ref_insert = 1;
    assert_true(register_claimed_grpc_client_request_handoff(&id, &ref.egress, &ref.token) ==
                    k_grpc_client_handoff_registered,
                "reference registration succeeds");
    assert_true(registration_held_authority_claim,
                "reference publishes while holding exact authority claim");
    assert_true(registration_refreshed_progress,
                "authority progress refresh precedes reference publication");
    assert_true(registration_blocked_reaper_claim,
                "concurrent reaper claim loses during publication");
    assert_true(!authority_claim_present, "registration releases exact authority claim");
    slot = find_authority(&exact);
    assert_true(slot && slot->value.last_progress == bpf_ktime_get_ns(),
                "post-release reaper recheck observes fresh progress");
    release_grpc_client_request_handoffs(&id);
}

static void test_reference_registration_failures_publish_nothing(void) {
    reset_state();
    const grpc_client_request_id_t id = test_request(test_process_start, 22);
    add_request(id, (go_addr_key_t){.pid = 42, .addr = 0xebeb});
    const go_outgoing_trace_handoff_ref_t ref = test_ref(22);
    add_authority(ref);
    const outgoing_trace_handoff_key_t exact = outgoing_trace_handoff_key(&ref.egress, &ref.token);

    assert_true(claim_grpc_client_request_handoffs(&id),
                "publisher owns request for authority contention");
    authority_claim_key = exact;
    authority_claim_present = 1;
    assert_true(register_claimed_grpc_client_request_handoff(&id, &ref.egress, &ref.token) ==
                    k_grpc_client_handoff_registration_failed,
                "authority claim contention fails registration");
    assert_true(!refs_present(), "authority claim failure publishes no live reference");
    authority_claim_present = 0;

    authority_slot_t *slot = find_authority(&exact);
    assert_true(slot != NULL, "terminal registration authority exists");
    if (slot) {
        slot->value.retire_requested = 1;
        slot->value.terminal_at = 1;
        slot->value.terminal_reason = k_outgoing_trace_terminal_owner_cleanup;
    }
    assert_true(register_claimed_grpc_client_request_handoff(&id, &ref.egress, &ref.token) ==
                    k_grpc_client_handoff_registration_failed,
                "terminal authority fails registration");
    assert_true(!refs_present(), "terminal authority publishes no live reference");
    release_grpc_client_request_handoffs(&id);
}

int main(void) {
    run_terminal_race(terminal_before_registration);
    run_terminal_race(terminal_during_registration);
    run_terminal_race(terminal_after_registration);
    test_stream_cleanup_never_deletes_new_generation();
    test_stream_collision_reclaims_only_dead_incarnation();
    test_creator_cleanup_never_deletes_new_generation();
    test_creator_publication_claim_failure_drops_canonical();
    test_terminal_authority_cannot_be_reauthorized();
    test_current_resolution_is_tri_state();
    test_reference_registration_refreshes_before_publish();
    test_reference_registration_failures_publish_nothing();
    return failures ? 1 : 0;
}
