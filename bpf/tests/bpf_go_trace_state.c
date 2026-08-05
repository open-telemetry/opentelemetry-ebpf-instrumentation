// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wint-conversion"
#pragma clang diagnostic ignored "-Wint-to-pointer-cast"

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
#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete
#define bpf_get_current_pid_tgid test_current_pid_tgid
#define OBI_CURRENT_PROCESS_START_TIME_NS test_process_start_time

#include <gotracer/go_common.h>

#undef OBI_CURRENT_PROCESS_START_TIME_NS
#undef bpf_get_current_pid_tgid
#undef bpf_map_delete_elem
#undef bpf_map_update_elem
#undef bpf_map_lookup_elem
#undef BPF_NOEXIST
#undef BPF_ANY
#undef PT_REGS_SP
#undef GO_PARAM2
#undef BPF_CORE_READ

#pragma clang diagnostic pop

enum {
    test_bpf_any = 0,
    test_bpf_noexist = 1,
    test_bpf_exist = 2,
    test_owner_capacity = k_go_owner_restore_depth + 4,
};

static unsigned int failures;
static const u32 test_pid = 123;
static const u64 test_generation = 7;
static const u64 test_start_time = 120000000ULL;

static go_process_generation_t process_generation;
static go_trace_state_t trace_state;
static go_trace_state_t trace_state_scratch;
static go_trace_owner_link_scratch_t owner_link_scratch;
static go_trace_resolve_scratch_t resolve_scratch;
static go_process_addr_key_t trace_state_key;
static go_trace_lease_key_t trace_lease_key;
static go_process_addr_key_t owner_link_keys[test_owner_capacity];
static go_trace_owner_link_t owner_link_values[test_owner_capacity];
static go_process_addr_key_t active_span_keys[test_owner_capacity];
static otel_span_t active_span_values[test_owner_capacity];
static go_process_addr_key_t owner_claim_key;
static go_process_addr_key_t reset_key;

static u8 process_generation_present;
static u8 trace_state_present;
static u8 trace_lease_present;
static u8 owner_link_present[test_owner_capacity];
static u8 active_span_present[test_owner_capacity];
static u8 owner_claim_present;
static u8 reset_present;

static u8 owner_claim_update_failure;
static u8 owner_claim_delete_failure;
static u8 owner_claim_delete_reset_hook;
static u8 reset_update_failure;
static u8 trace_state_exist_update_failure;
static u8 owner_link_update_failure;
static u8 claim_update_reset_hook;
static u8 active_span_reset_hook;
static u8 owner_link_delete_publish_hook;
static u8 generation_tp_reuse_hook;
static u8 generation_owner_key_reuse_hook;

static go_addr_key_t claim_hook_goroutine;
static go_addr_key_t active_hook_goroutine;
static go_addr_key_t publish_hook_goroutine;
static tp_info_t publish_hook_tp;
static u64 publish_hook_span;
static long claim_hook_result;
static long publish_hook_result;
static tp_info_t pop_source_tp;
static tp_info_t pop_reused_tp;
static go_addr_key_t generation_source_owner_key;
static go_addr_key_t generation_reused_owner_key;

static unsigned int trace_state_delete_calls;
static unsigned int owner_claim_delete_calls;
static unsigned int reset_delete_calls;
static unsigned int owner_link_delete_calls;
static unsigned int lease_delete_calls;
static unsigned int readiness_delete_calls;

static u8 process_keys_match(const go_process_addr_key_t *left,
                             const go_process_addr_key_t *right) {
    return left->pid == right->pid && left->generation == right->generation &&
           left->addr == right->addr;
}

static int find_owner_link(const go_process_addr_key_t *key) {
    for (int i = 0; i < test_owner_capacity; i++) {
        if (owner_link_present[i] && process_keys_match(key, &owner_link_keys[i])) {
            return i;
        }
    }
    return -1;
}

static int owner_link_slot(const go_process_addr_key_t *key) {
    const int existing = find_owner_link(key);
    if (existing >= 0) {
        return existing;
    }
    for (int i = 0; i < test_owner_capacity; i++) {
        if (!owner_link_present[i]) {
            return i;
        }
    }
    return -1;
}

static int find_active_span(const go_process_addr_key_t *key) {
    for (int i = 0; i < test_owner_capacity; i++) {
        if (active_span_present[i] && process_keys_match(key, &active_span_keys[i])) {
            return i;
        }
    }
    return -1;
}

static void *test_map_lookup(void *map, const void *key) {
    if (map == &go_process_generations) {
        if (generation_tp_reuse_hook) {
            generation_tp_reuse_hook = 0;
            pop_source_tp = pop_reused_tp;
        }
        if (generation_owner_key_reuse_hook) {
            generation_owner_key_reuse_hook = 0;
            generation_source_owner_key = generation_reused_owner_key;
        }
        return process_generation_present && *(const u32 *)key == test_pid ? &process_generation
                                                                           : 0;
    }
    if (map == &go_trace_map) {
        return trace_state_present && process_keys_match(key, &trace_state_key) ? &trace_state : 0;
    }
    if (map == &go_trace_state_storage) {
        return *(const u32 *)key == 0 ? &trace_state_scratch : 0;
    }
    if (map == &go_trace_owner_link_scratch_storage) {
        return *(const u32 *)key == 0 ? &owner_link_scratch : 0;
    }
    if (map == &go_trace_resolve_scratch_storage) {
        return *(const u32 *)key == 0 ? &resolve_scratch : 0;
    }
    if (map == &go_trace_leases) {
        return trace_lease_present && memcmp(key, &trace_lease_key, sizeof(trace_lease_key)) == 0
                   ? &trace_lease_present
                   : 0;
    }
    if (map == &go_trace_owner_claims) {
        return owner_claim_present && process_keys_match(key, &owner_claim_key)
                   ? &owner_claim_present
                   : 0;
    }
    if (map == &go_trace_state_resets) {
        return reset_present && process_keys_match(key, &reset_key) ? &reset_present : 0;
    }
    if (map == &go_trace_owner_links) {
        const int index = find_owner_link(key);
        return index >= 0 ? &owner_link_values[index] : 0;
    }
    if (map == &active_spans) {
        if (active_span_reset_hook) {
            active_span_reset_hook = 0;
            claim_hook_result = delete_go_trace_state(&active_hook_goroutine);
        }
        const int index = find_active_span(key);
        return index >= 0 ? &active_span_values[index] : 0;
    }
    return 0;
}

static long test_map_update(void *map, const void *key, const void *val, unsigned long long flags) {
    if (map == &go_trace_leases) {
        trace_lease_key = *(const go_trace_lease_key_t *)key;
        trace_lease_present = *(const u8 *)val;
        return 0;
    }
    if (map == &go_trace_map && process_keys_match(key, &trace_state_key)) {
        if ((flags != test_bpf_noexist && flags != test_bpf_exist) ||
            (flags == test_bpf_exist && trace_state_exist_update_failure) ||
            (flags == test_bpf_noexist && trace_state_present) ||
            (flags == test_bpf_exist && !trace_state_present)) {
            return -1;
        }
        trace_state = *(const go_trace_state_t *)val;
        trace_state_present = 1;
        return 0;
    }
    if (map == &go_trace_owner_claims) {
        if (owner_claim_update_failure || flags != test_bpf_noexist || owner_claim_present) {
            return -1;
        }
        owner_claim_key = *(const go_process_addr_key_t *)key;
        owner_claim_present = *(const u8 *)val;
        if (claim_update_reset_hook) {
            claim_update_reset_hook = 0;
            claim_hook_result = delete_go_trace_state(&claim_hook_goroutine);
        }
        return 0;
    }
    if (map == &go_trace_state_resets) {
        if (reset_update_failure) {
            return -1;
        }
        reset_key = *(const go_process_addr_key_t *)key;
        reset_present = *(const u8 *)val;
        return 0;
    }
    if (map == &go_trace_owner_links) {
        if (owner_link_update_failure) {
            return -1;
        }
        const int index = owner_link_slot(key);
        if (index < 0) {
            return -1;
        }
        owner_link_keys[index] = *(const go_process_addr_key_t *)key;
        owner_link_values[index] = *(const go_trace_owner_link_t *)val;
        owner_link_present[index] = 1;
        return 0;
    }
    return -1;
}

static long test_map_delete(void *map, const void *key) {
    if (map == &go_trace_map) {
        trace_state_delete_calls++;
        if (trace_state_present && process_keys_match(key, &trace_state_key)) {
            trace_state_present = 0;
            return 0;
        }
        return -1;
    }
    if (map == &go_trace_leases) {
        lease_delete_calls++;
        if (trace_lease_present && memcmp(key, &trace_lease_key, sizeof(trace_lease_key)) == 0) {
            trace_lease_present = 0;
            return 0;
        }
        return -1;
    }
    if (map == &go_trace_owner_claims) {
        owner_claim_delete_calls++;
        if (owner_claim_delete_failure) {
            return -1;
        }
        if (owner_claim_present && process_keys_match(key, &owner_claim_key)) {
            owner_claim_present = 0;
            if (owner_claim_delete_reset_hook) {
                owner_claim_delete_reset_hook = 0;
                reset_key = *(const go_process_addr_key_t *)key;
                reset_present = 1;
            }
            return 0;
        }
        return -1;
    }
    if (map == &go_trace_state_resets) {
        reset_delete_calls++;
        if (reset_present && process_keys_match(key, &reset_key)) {
            reset_present = 0;
            return 0;
        }
        return -1;
    }
    if (map == &go_trace_owner_links) {
        const int index = find_owner_link(key);
        if (index < 0) {
            return -1;
        }
        owner_link_delete_calls++;
        if (owner_link_delete_publish_hook) {
            owner_link_delete_publish_hook = 0;
            publish_hook_result = publish_go_trace_owner(
                &publish_hook_goroutine, &publish_hook_tp, publish_hook_span);
        }
        owner_link_present[index] = 0;
        return 0;
    }
    if (map == &go_auto_sdk_ready) {
        readiness_delete_calls++;
    }
    return -1;
}

static unsigned long long test_current_pid_tgid(void) {
    return (unsigned long long)test_pid << 32;
}

static unsigned long long test_process_start_time(void) {
    return test_start_time;
}

static void assert_bool(int want, int got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %d, got %d\n", message, want, got);
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

static void assert_bytes(const void *want, const void *got, size_t len, const char *message) {
    if (memcmp(want, got, len) == 0) {
        return;
    }
    fprintf(stderr, "%s: byte sequences differ\n", message);
    failures++;
}

static tp_info_t test_traceparent(u8 seed) {
    tp_info_t tp = {};
    for (u8 i = 0; i < TRACE_ID_SIZE_BYTES; i++) {
        tp.trace_id[i] = seed + i;
    }
    for (u8 i = 0; i < SPAN_ID_SIZE_BYTES; i++) {
        tp.span_id[i] = seed + TRACE_ID_SIZE_BYTES + i;
    }
    return tp;
}

static go_trace_owner_t test_owner(const tp_info_t *tp, u64 span_addr) {
    go_trace_owner_t owner = {};
    go_trace_owner_from_tp(&owner, tp, span_addr);
    return owner;
}

static go_process_addr_key_t test_process_key(u64 addr) {
    return (go_process_addr_key_t){
        .pid = test_pid,
        .generation = test_generation,
        .addr = addr,
    };
}

static void reset_test(const go_addr_key_t *goroutine_key) {
    process_generation = (go_process_generation_t){
        .generation = test_generation,
        .start_time = test_start_time,
    };
    process_generation_present = 1;
    trace_state_key = test_process_key(goroutine_key->addr);

    memset(&trace_state, 0, sizeof(trace_state));
    memset(&trace_state_scratch, 0, sizeof(trace_state_scratch));
    memset(&owner_link_scratch, 0, sizeof(owner_link_scratch));
    memset(&resolve_scratch, 0, sizeof(resolve_scratch));
    memset(&trace_lease_key, 0, sizeof(trace_lease_key));
    memset(owner_link_keys, 0, sizeof(owner_link_keys));
    memset(owner_link_values, 0, sizeof(owner_link_values));
    memset(owner_link_present, 0, sizeof(owner_link_present));
    memset(active_span_keys, 0, sizeof(active_span_keys));
    memset(active_span_values, 0, sizeof(active_span_values));
    memset(active_span_present, 0, sizeof(active_span_present));
    memset(&owner_claim_key, 0, sizeof(owner_claim_key));
    memset(&reset_key, 0, sizeof(reset_key));

    trace_state_present = 0;
    trace_lease_present = 0;
    owner_claim_present = 0;
    reset_present = 0;
    owner_claim_update_failure = 0;
    owner_claim_delete_failure = 0;
    owner_claim_delete_reset_hook = 0;
    reset_update_failure = 0;
    trace_state_exist_update_failure = 0;
    owner_link_update_failure = 0;
    claim_update_reset_hook = 0;
    active_span_reset_hook = 0;
    owner_link_delete_publish_hook = 0;
    generation_tp_reuse_hook = 0;
    generation_owner_key_reuse_hook = 0;

    memset(&claim_hook_goroutine, 0, sizeof(claim_hook_goroutine));
    memset(&active_hook_goroutine, 0, sizeof(active_hook_goroutine));
    memset(&publish_hook_goroutine, 0, sizeof(publish_hook_goroutine));
    memset(&publish_hook_tp, 0, sizeof(publish_hook_tp));
    publish_hook_span = 0;
    claim_hook_result = -99;
    publish_hook_result = -99;
    memset(&pop_source_tp, 0, sizeof(pop_source_tp));
    memset(&pop_reused_tp, 0, sizeof(pop_reused_tp));
    memset(&generation_source_owner_key, 0, sizeof(generation_source_owner_key));
    memset(&generation_reused_owner_key, 0, sizeof(generation_reused_owner_key));

    trace_state_delete_calls = 0;
    owner_claim_delete_calls = 0;
    reset_delete_calls = 0;
    owner_link_delete_calls = 0;
    lease_delete_calls = 0;
    readiness_delete_calls = 0;
}

static void setup_generic(const tp_info_t *tp) {
    trace_state.generic_tp = *tp;
    trace_state.has_generic = 1;
    trace_state_present = 1;
    go_trace_lease_key_from_tp(&trace_lease_key, test_pid, test_generation, tp);
    trace_lease_present = 1;
}

static void
add_owner_link(const go_trace_owner_t *owner, const go_trace_owner_t *previous, u8 has_previous) {
    const go_process_addr_key_t key = test_process_key(owner->span_addr);
    const int index = owner_link_slot(&key);
    if (index < 0) {
        failures++;
        return;
    }
    owner_link_keys[index] = key;
    owner_link_values[index] = (go_trace_owner_link_t){
        .goroutine = trace_state_key,
        .owner = *owner,
        .has_previous = has_previous,
    };
    if (has_previous) {
        owner_link_values[index].previous = *previous;
    }
    owner_link_present[index] = 1;
}

static void setup_current_owner(const tp_info_t *tp, u64 span_addr) {
    const go_trace_owner_t owner = test_owner(tp, span_addr);
    trace_state.owner = owner;
    trace_state.has_owner = 1;
    trace_state_present = 1;
    add_owner_link(&owner, 0, 0);
}

static void set_active_owner(const tp_info_t *tp, u64 span_addr, u8 present) {
    const go_process_addr_key_t key = test_process_key(span_addr);
    int index = find_active_span(&key);
    if (index < 0) {
        for (int i = 0; i < test_owner_capacity; i++) {
            if (!active_span_present[i]) {
                index = i;
                break;
            }
        }
    }
    if (index < 0) {
        failures++;
        return;
    }
    active_span_keys[index] = key;
    active_span_values[index].tp = *tp;
    active_span_present[index] = present;
}

static u8 owner_link_is_present(u64 span_addr) {
    const go_process_addr_key_t key = test_process_key(span_addr);
    return find_owner_link(&key) >= 0;
}

static s8 resolve_test_go_trace(go_trace_parent_t *resolved, const go_addr_key_t *goroutine_key) {
    memset(&resolve_scratch, 0, sizeof(resolve_scratch));
    go_process_addr_key_from_generation(&resolve_scratch.state_key, goroutine_key, test_generation);
    return resolve_current_go_trace(resolved, &resolve_scratch);
}

static void setup_owner_chain(tp_info_t *traceparents, u64 *span_addrs, int count) {
    go_trace_owner_t previous = {};
    for (int i = 0; i < count; i++) {
        const go_trace_owner_t owner = test_owner(&traceparents[i], span_addrs[i]);
        add_owner_link(&owner, &previous, i != 0);
        previous = owner;
    }
    trace_state.owner = previous;
    trace_state.has_owner = 1;
    trace_state_present = 1;
}

static void test_poison_and_revoke_go_trace(void) {
    const go_addr_key_t goroutine_key = {
        .pid = test_pid,
        .addr = 0x5678,
    };
    const tp_info_t stale_tp = test_traceparent(1);
    const tp_info_t owner_tp = test_traceparent(41);
    reset_test(&goroutine_key);
    setup_generic(&stale_tp);
    setup_current_owner(&owner_tp, 0x1234);
    const go_trace_owner_t owner = trace_state.owner;

    assert_bool(0, poison_and_revoke_go_trace(&goroutine_key), "revoke current goroutine trace");
    assert_bool(1, trace_state.poisoned, "revoke poisons goroutine state");
    assert_bool(0, trace_state.has_generic, "revoke clears generic state");
    assert_bool(0, trace_lease_present, "revoke removes generic lease");
    assert_bool(1, lease_delete_calls, "revoke deletes one generic lease");
    assert_bool(0, readiness_delete_calls, "revoke keeps process readiness");
    assert_bool(1, trace_state.has_owner, "revoke keeps owner state");
    assert_bytes(&owner, &trace_state.owner, sizeof(owner), "revoke preserves owner");
    assert_bool(0, owner_claim_present, "revoke releases owner claim");

    go_trace_parent_t resolved = {};
    assert_bool(k_go_trace_parent_error,
                resolve_test_go_trace(&resolved, &goroutine_key),
                "poisoned state cannot resolve");

    const tp_info_t recovered_tp = test_traceparent(97);
    assert_bool(0, push_go_trace(&goroutine_key, &recovered_tp), "push recovers goroutine state");
    assert_bool(0, trace_state.poisoned, "push clears poison");
    assert_bool(1, trace_state.has_generic, "push publishes generic state");
    assert_bool(1, trace_lease_present, "push publishes generic lease");
    assert_bool(1, trace_state.has_owner, "push retains owner state");
    assert_bytes(&owner, &trace_state.owner, sizeof(owner), "push preserves owner");

    assert_bool(k_go_trace_parent_found,
                resolve_test_go_trace(&resolved, &goroutine_key),
                "recovered state resolves");
    assert_bytes(recovered_tp.trace_id,
                 resolved.tp.trace_id,
                 sizeof(recovered_tp.trace_id),
                 "recovered state uses new trace ID");
    assert_bytes(recovered_tp.span_id,
                 resolved.tp.span_id,
                 sizeof(recovered_tp.span_id),
                 "recovered state uses new span ID");
}

static void test_new_state_clears_reused_scratch(void) {
    const go_addr_key_t goroutine_key = {
        .pid = test_pid,
        .addr = 0x6000,
    };
    const tp_info_t fresh_tp = test_traceparent(2);
    reset_test(&goroutine_key);
    trace_state_scratch.has_owner = 1;
    trace_state_scratch.poisoned = 1;
    trace_state_scratch.owner.span_addr = 0xdead;

    assert_bool(0, push_go_trace(&goroutine_key, &fresh_tp), "create trace from reused scratch");
    assert_bool(1, trace_state_present, "new trace state is created");
    assert_bool(1, trace_state.has_generic, "new trace has generic parent");
    assert_bool(0, trace_state.has_owner, "new trace does not resurrect owner");
    assert_bool(0, trace_state.poisoned, "new trace does not resurrect poison");
}

static void test_claim_contention_is_non_mutating(void) {
    const go_addr_key_t goroutine_key = {
        .pid = test_pid,
        .addr = 0x6100,
    };
    const tp_info_t current_tp = test_traceparent(3);
    const tp_info_t replacement_tp = test_traceparent(33);
    reset_test(&goroutine_key);
    setup_generic(&current_tp);
    const go_trace_state_t before = trace_state;
    const go_trace_lease_key_t lease_before = trace_lease_key;
    owner_claim_key = trace_state_key;
    owner_claim_present = 1;

    assert_bool(-1, push_go_trace(&goroutine_key, &replacement_tp), "contended push fails closed");
    assert_bytes(&before, &trace_state, sizeof(before), "contended push preserves state");
    assert_bytes(&lease_before,
                 &trace_lease_key,
                 sizeof(trace_lease_key),
                 "contended push leaves lease map untouched");
    assert_bool(1, owner_claim_present, "contended push preserves foreign claim");
}

static void test_claim_release_failure_strands_key(void) {
    const go_addr_key_t goroutine_key = {
        .pid = test_pid,
        .addr = 0x6200,
    };
    const tp_info_t traceparent = test_traceparent(4);
    reset_test(&goroutine_key);
    setup_generic(&traceparent);
    owner_claim_delete_failure = 1;

    assert_bool(-1, poison_go_trace(&goroutine_key), "release failure is reported");
    assert_bool(1, owner_claim_present, "failed release leaves exact claim");

    go_trace_parent_t resolved = {};
    assert_bool(k_go_trace_parent_error,
                resolve_test_go_trace(&resolved, &goroutine_key),
                "stranded claim keeps resolver closed");

    owner_claim_delete_failure = 0;
    assert_bool(0, release_go_trace_state(&trace_state_key), "manual release recovers claim");
    assert_bool(0, owner_claim_present, "manual release removes claim");
}

static void test_existing_state_update_failure_does_not_publish(void) {
    const go_addr_key_t goroutine_key = {
        .pid = test_pid,
        .addr = 0x6280,
    };
    const tp_info_t current_tp = test_traceparent(14);
    const tp_info_t replacement_tp = test_traceparent(54);
    reset_test(&goroutine_key);
    setup_generic(&current_tp);
    const go_trace_state_t state_before = trace_state;
    trace_state_exist_update_failure = 1;

    assert_bool(-1,
                push_go_trace(&goroutine_key, &replacement_tp),
                "exact state update failure is reported");
    assert_bytes(
        &state_before, &trace_state, sizeof(state_before), "failed exact update preserves state");
    assert_bool(0, trace_lease_present, "failed exact update removes new lease");
    assert_bool(0, owner_claim_present, "failed exact update releases claim");

    trace_state_exist_update_failure = 0;
    assert_bool(0,
                push_go_trace(&goroutine_key, &replacement_tp),
                "push retries after exact update failure");
    assert_bytes(replacement_tp.trace_id,
                 trace_state.generic_tp.trace_id,
                 sizeof(replacement_tp.trace_id),
                 "retry publishes replacement trace");
}

static void test_owner_publication_is_serialized_with_retirement(void) {
    const go_addr_key_t goroutine_key = {
        .pid = test_pid,
        .addr = 0x6300,
    };
    const tp_info_t owner_a_tp = test_traceparent(5);
    const tp_info_t owner_b_tp = test_traceparent(45);
    const u64 owner_a_span = 0xa001;
    const u64 owner_b_span = 0xb001;
    reset_test(&goroutine_key);
    setup_current_owner(&owner_a_tp, owner_a_span);

    publish_hook_goroutine = goroutine_key;
    publish_hook_tp = owner_b_tp;
    publish_hook_span = owner_b_span;
    owner_link_delete_publish_hook = 1;
    const go_addr_key_t owner_a_key = {
        .pid = test_pid,
        .addr = owner_a_span,
    };
    retire_go_trace_owner(&owner_a_key, &owner_a_tp);

    assert_bool(-1, publish_hook_result, "publication cannot interleave with retirement");
    assert_bool(0, trace_state.has_owner, "retirement clears retiring owner");
    assert_bool(0, owner_link_is_present(owner_a_span), "retirement removes retiring link");
    assert_bool(0, owner_link_is_present(owner_b_span), "failed publication adds no link");
    assert_bool(0, owner_claim_present, "retirement releases claim");

    assert_bool(0,
                publish_go_trace_owner(&goroutine_key, &owner_b_tp, owner_b_span),
                "publication succeeds after retirement");
    assert_bool(1, trace_state.has_owner, "new publication installs owner");
    assert_u64(owner_b_span, trace_state.owner.span_addr, "new owner span is current");
    assert_bool(1, owner_link_is_present(owner_b_span), "new owner link is present");
    assert_bool(0,
                publish_go_trace_owner(&goroutine_key, &owner_b_tp, owner_b_span),
                "same owner publication is idempotent");
}

static void test_owner_publication_snapshots_lru_traceparent(void) {
    const go_addr_key_t goroutine_key = {
        .pid = test_pid,
        .addr = 0x6380,
    };
    const tp_info_t published_tp = test_traceparent(15);
    const tp_info_t reused_tp = test_traceparent(115);
    const u64 owner_span = 0xb801;
    reset_test(&goroutine_key);
    pop_source_tp = published_tp;
    pop_reused_tp = reused_tp;
    generation_tp_reuse_hook = 1;

    assert_bool(0,
                publish_go_trace_owner(&goroutine_key, &pop_source_tp, owner_span),
                "publication survives traceparent LRU reuse");
    const go_trace_owner_t published_owner = test_owner(&published_tp, owner_span);
    assert_bytes(&published_owner,
                 &trace_state.owner,
                 sizeof(published_owner),
                 "publication uses pre-helper owner identity");
    assert_bytes(&reused_tp,
                 &pop_source_tp,
                 sizeof(pop_source_tp),
                 "generation lookup reuses publication source");
}

static void test_owner_publication_failure_releases_claim(void) {
    const go_addr_key_t goroutine_key = {
        .pid = test_pid,
        .addr = 0x6400,
    };
    const tp_info_t owner_tp = test_traceparent(6);
    const u64 owner_span = 0xc001;
    reset_test(&goroutine_key);
    trace_state_present = 1;
    owner_link_update_failure = 1;

    assert_bool(-1,
                publish_go_trace_owner(&goroutine_key, &owner_tp, owner_span),
                "owner-link update failure is reported");
    assert_bool(0, trace_state.has_owner, "failed publication adds no owner");
    assert_bool(1, trace_state.poisoned, "failed publication poisons state");
    assert_bool(0, owner_claim_present, "failed publication releases claim");

    owner_link_update_failure = 0;
    assert_bool(0,
                publish_go_trace_owner(&goroutine_key, &owner_tp, owner_span),
                "publication retries after link failure");
    assert_bool(1, trace_state.has_owner, "retry installs owner");
    assert_bool(0, trace_state.poisoned, "retry clears poison");
}

static void test_stale_retirement_preserves_current_owner(void) {
    const go_addr_key_t goroutine_key = {
        .pid = test_pid,
        .addr = 0x6500,
    };
    const tp_info_t stale_tp = test_traceparent(7);
    const tp_info_t current_tp = test_traceparent(47);
    const go_trace_owner_t stale_owner = test_owner(&stale_tp, 0xd001);
    const go_trace_owner_t current_owner = test_owner(&current_tp, 0xe001);
    reset_test(&goroutine_key);
    add_owner_link(&stale_owner, 0, 0);
    add_owner_link(&current_owner, &stale_owner, 1);
    trace_state.owner = current_owner;
    trace_state.has_owner = 1;
    trace_state_present = 1;

    const go_addr_key_t stale_key = {
        .pid = test_pid,
        .addr = stale_owner.span_addr,
    };
    retire_go_trace_owner(&stale_key, &stale_tp);

    assert_bool(1, trace_state.has_owner, "stale retirement keeps current owner");
    assert_bytes(&current_owner,
                 &trace_state.owner,
                 sizeof(current_owner),
                 "stale retirement preserves exact owner");
    assert_bool(1, owner_link_is_present(stale_owner.span_addr), "stale link remains");
    assert_bool(1, owner_link_is_present(current_owner.span_addr), "current link remains");
    assert_bool(0, owner_claim_present, "stale retirement releases claim");
}

static void test_retirement_rejects_cross_generation_link(void) {
    const go_addr_key_t goroutine_key = {
        .pid = test_pid,
        .addr = 0x6580,
    };
    const tp_info_t owner_tp = test_traceparent(77);
    const u64 owner_span = 0xe801;
    reset_test(&goroutine_key);
    setup_current_owner(&owner_tp, owner_span);
    const go_process_addr_key_t owner_process_key = test_process_key(owner_span);
    const int link_index = find_owner_link(&owner_process_key);
    if (link_index < 0) {
        failures++;
        return;
    }
    owner_link_values[link_index].goroutine.generation++;

    const go_addr_key_t owner_key = {
        .pid = test_pid,
        .addr = owner_span,
    };
    retire_go_trace_owner(&owner_key, &owner_tp);

    assert_bool(1, trace_state.has_owner, "cross-generation link cannot retire owner");
    assert_u64(owner_span, trace_state.owner.span_addr, "current owner remains installed");
    assert_bool(1, owner_link_is_present(owner_span), "cross-generation link remains");
    assert_bool(0, owner_claim_delete_calls, "cross-generation link acquires no claim");
}

static void test_retirement_snapshots_lru_inputs(void) {
    const go_addr_key_t goroutine_key = {
        .pid = test_pid,
        .addr = 0x65c0,
    };
    const tp_info_t retiring_tp = test_traceparent(78);
    const tp_info_t reused_tp = test_traceparent(118);
    const u64 retiring_span = 0xec01;
    reset_test(&goroutine_key);
    setup_current_owner(&retiring_tp, retiring_span);
    pop_source_tp = retiring_tp;
    pop_reused_tp = reused_tp;
    generation_source_owner_key = (go_addr_key_t){
        .pid = test_pid,
        .addr = retiring_span,
    };
    generation_reused_owner_key = (go_addr_key_t){
        .pid = test_pid,
        .addr = 0xdead,
    };
    generation_tp_reuse_hook = 1;
    generation_owner_key_reuse_hook = 1;

    retire_go_trace_owner(&generation_source_owner_key, &pop_source_tp);

    assert_bool(0, trace_state.has_owner, "retirement uses pre-helper owner identity");
    assert_bool(0, owner_link_is_present(retiring_span), "retirement removes original link");
    assert_bytes(&reused_tp,
                 &pop_source_tp,
                 sizeof(pop_source_tp),
                 "generation lookup reuses retirement traceparent");
    assert_u64(generation_reused_owner_key.addr,
               generation_source_owner_key.addr,
               "generation lookup reuses retirement key");
}

static void test_lifecycle_reset_defers_to_claimant(void) {
    const go_addr_key_t goroutine_key = {
        .pid = test_pid,
        .addr = 0x6600,
    };
    const tp_info_t traceparent = test_traceparent(8);
    reset_test(&goroutine_key);
    setup_generic(&traceparent);
    owner_claim_key = trace_state_key;
    owner_claim_present = 1;

    assert_bool(0, delete_go_trace_state(&goroutine_key), "reset defers to live claimant");
    assert_bool(1, reset_present, "deferred reset leaves terminal marker");
    assert_bool(1, trace_state_present, "foreign claimant retains state until release");
    assert_bool(1, owner_claim_present, "foreign claim remains live");

    assert_bool(1, release_go_trace_state(&trace_state_key), "claimant observes deferred reset");
    assert_bool(0, trace_state_present, "claimant release deletes state");
    assert_bool(0, reset_present, "claimant release consumes marker");
    assert_bool(0, owner_claim_present, "claimant release removes claim");
}

static void test_release_closes_postdelete_reset_window(void) {
    const go_addr_key_t goroutine_key = {
        .pid = test_pid,
        .addr = 0x6680,
    };
    const tp_info_t traceparent = test_traceparent(88);
    reset_test(&goroutine_key);
    setup_generic(&traceparent);
    owner_claim_delete_reset_hook = 1;

    assert_bool(-1, poison_go_trace(&goroutine_key), "postdelete reset aborts transition");
    assert_bool(0, trace_state_present, "postdelete reset removes state");
    assert_bool(0, reset_present, "postdelete reset marker is consumed");
    assert_bool(0, owner_claim_present, "postdelete reset releases reacquired claim");
    assert_bool(2, owner_claim_delete_calls, "release performs terminal post-pass");
}

static void test_claim_start_reset_prevents_stale_creation(void) {
    const go_addr_key_t goroutine_key = {
        .pid = test_pid,
        .addr = 0x6700,
    };
    reset_test(&goroutine_key);
    trace_state_scratch.has_owner = 1;
    trace_state_scratch.owner.span_addr = 0xfeed;
    claim_hook_goroutine = goroutine_key;
    claim_update_reset_hook = 1;

    assert_bool(-1, poison_go_trace(&goroutine_key), "claim-start reset aborts transition");
    assert_bool(0, claim_hook_result, "lifecycle reset publishes during claim");
    assert_bool(0, trace_state_present, "aborted transition creates no stale state");
    assert_bool(0, reset_present, "claim consumes terminal marker");
    assert_bool(0, owner_claim_present, "claim abort releases claim");
}

static void test_resolver_contention_fails_closed(void) {
    const go_addr_key_t goroutine_key = {
        .pid = test_pid,
        .addr = 0x6800,
    };
    const tp_info_t traceparent = test_traceparent(9);
    reset_test(&goroutine_key);
    setup_generic(&traceparent);
    owner_claim_key = trace_state_key;
    owner_claim_present = 1;

    go_trace_parent_t resolved = {};
    assert_bool(k_go_trace_parent_error,
                resolve_test_go_trace(&resolved, &goroutine_key),
                "contended resolver fails closed");
    assert_bool(1, trace_state_present, "contended resolver preserves state");
    assert_bool(1, owner_claim_present, "contended resolver preserves foreign claim");
}

static void test_resolver_revalidates_after_reset(void) {
    const go_addr_key_t goroutine_key = {
        .pid = test_pid,
        .addr = 0x6900,
    };
    const tp_info_t owner_tp = test_traceparent(10);
    const u64 owner_span = 0xf001;
    reset_test(&goroutine_key);
    setup_current_owner(&owner_tp, owner_span);
    set_active_owner(&owner_tp, owner_span, 1);
    active_hook_goroutine = goroutine_key;
    active_span_reset_hook = 1;

    go_trace_parent_t resolved = {};
    assert_bool(k_go_trace_parent_error,
                resolve_test_go_trace(&resolved, &goroutine_key),
                "reset during owner lookup invalidates resolution");
    assert_bool(0, claim_hook_result, "resolver hook publishes lifecycle reset");
    assert_bool(0, trace_state_present, "resolver release applies reset");
    assert_bool(0, reset_present, "resolver release consumes reset");
    assert_bool(0, owner_claim_present, "resolver release removes claim");
}

static void test_pop_snapshots_traceparent_before_generation_lookup(void) {
    const go_addr_key_t goroutine_key = {
        .pid = test_pid,
        .addr = 0x6a00,
    };
    const tp_info_t original_tp = test_traceparent(11);
    reset_test(&goroutine_key);
    pop_source_tp = original_tp;
    pop_reused_tp = test_traceparent(111);
    go_trace_lease_key_from_tp(&trace_lease_key, test_pid, test_generation, &original_tp);
    trace_lease_present = 1;
    generation_tp_reuse_hook = 1;

    assert_bool(0,
                pop_go_trace(&goroutine_key, &pop_source_tp),
                "pop deletes lease for pre-helper traceparent");
    assert_bool(0, trace_lease_present, "pop removes original lease");
    assert_bytes(&pop_reused_tp,
                 &pop_source_tp,
                 sizeof(pop_source_tp),
                 "generation lookup reuses source storage");
}

static void test_retirement_restores_final_bounded_candidate(void) {
    const go_addr_key_t goroutine_key = {
        .pid = test_pid,
        .addr = 0x6b00,
    };
    tp_info_t traceparents[k_go_owner_restore_depth + 2] = {};
    u64 span_addrs[k_go_owner_restore_depth + 2] = {};
    reset_test(&goroutine_key);
    for (int i = 0; i < k_go_owner_restore_depth + 2; i++) {
        traceparents[i] = test_traceparent((u8)(20 + i * 7));
        span_addrs[i] = 0x10000 + (u64)i;
    }
    setup_owner_chain(traceparents, span_addrs, k_go_owner_restore_depth + 2);
    set_active_owner(&traceparents[0], span_addrs[0], 1);

    const go_addr_key_t current_key = {
        .pid = test_pid,
        .addr = span_addrs[k_go_owner_restore_depth + 1],
    };
    retire_go_trace_owner(&current_key, &traceparents[k_go_owner_restore_depth + 1]);

    assert_bool(1, trace_state.has_owner, "bounded traversal restores final candidate");
    assert_u64(
        span_addrs[0], trace_state.owner.span_addr, "final bounded candidate becomes current");
    assert_bool(1, owner_link_is_present(span_addrs[0]), "restored owner link remains");
    assert_bool(
        k_go_owner_restore_depth + 1, owner_link_delete_calls, "retirement bounds link deletions");
}

static void test_retirement_stops_at_traversal_bound(void) {
    const go_addr_key_t goroutine_key = {
        .pid = test_pid,
        .addr = 0x6c00,
    };
    tp_info_t traceparents[k_go_owner_restore_depth + 3] = {};
    u64 span_addrs[k_go_owner_restore_depth + 3] = {};
    reset_test(&goroutine_key);
    for (int i = 0; i < k_go_owner_restore_depth + 3; i++) {
        traceparents[i] = test_traceparent((u8)(30 + i * 7));
        span_addrs[i] = 0x20000 + (u64)i;
    }
    setup_owner_chain(traceparents, span_addrs, k_go_owner_restore_depth + 3);
    set_active_owner(&traceparents[0], span_addrs[0], 1);

    const go_addr_key_t current_key = {
        .pid = test_pid,
        .addr = span_addrs[k_go_owner_restore_depth + 2],
    };
    retire_go_trace_owner(&current_key, &traceparents[k_go_owner_restore_depth + 2]);

    assert_bool(0, trace_state.has_owner, "traversal bound does not reach older owner");
    assert_bool(1, owner_link_is_present(span_addrs[1]), "unvisited link remains");
    assert_bool(1, owner_link_is_present(span_addrs[0]), "older live link remains");
    assert_bool(k_go_owner_restore_depth + 1,
                owner_link_delete_calls,
                "traversal deletes only bounded links");
}

int main(void) {
    test_poison_and_revoke_go_trace();
    test_new_state_clears_reused_scratch();
    test_claim_contention_is_non_mutating();
    test_claim_release_failure_strands_key();
    test_existing_state_update_failure_does_not_publish();
    test_owner_publication_is_serialized_with_retirement();
    test_owner_publication_snapshots_lru_traceparent();
    test_owner_publication_failure_releases_claim();
    test_stale_retirement_preserves_current_owner();
    test_retirement_rejects_cross_generation_link();
    test_retirement_snapshots_lru_inputs();
    test_lifecycle_reset_defers_to_claimant();
    test_release_closes_postdelete_reset_window();
    test_claim_start_reset_prevents_stale_creation();
    test_resolver_contention_fails_closed();
    test_resolver_revalidates_after_reset();
    test_pop_snapshots_traceparent_before_generation_lookup();
    test_retirement_restores_final_bounded_candidate();
    test_retirement_stops_at_traversal_bound();
    return failures == 0 ? 0 : 1;
}
