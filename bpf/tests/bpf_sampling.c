// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

static void *test_map_lookup(void *map, const void *key);
static long test_map_update(void *map, const void *key, const void *val, unsigned long long flags);
static long test_map_delete(void *map, const void *key);
static unsigned long long test_current_pid_tgid(void);
static unsigned int test_prandom(void);
static unsigned long long test_ktime(void);
static unsigned long long test_process_start_time(void);
static long test_bpf_loop(unsigned int nr_loops,
                          void *callback_fn,
                          void *callback_ctx,
                          unsigned long long flags);

#define BPF_ANY 0
#define BPF_EXIST 2
#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete
#define bpf_get_current_pid_tgid test_current_pid_tgid
#define bpf_get_prandom_u32 test_prandom
#define bpf_ktime_get_ns test_ktime
#define bpf_loop test_bpf_loop
#define OBI_CURRENT_PROCESS_START_TIME_NS test_process_start_time

#include <common/trace_helpers.h>
#include <common/hpack.h>
#include <generictracer/http1_sampling.h>

_Static_assert(sizeof(process_readiness_t) == 24, "process readiness ABI size");
_Static_assert(offsetof(process_readiness_t, epoch) == 8, "process readiness epoch ABI offset");
_Static_assert(offsetof(process_readiness_t, config_epoch) == 12,
               "process readiness config epoch ABI offset");
_Static_assert(offsetof(process_readiness_t, ready) == 16, "process readiness ready ABI offset");
_Static_assert(offsetof(process_readiness_t, auto_sdk_global_ready) == 17,
               "process readiness global Auto SDK ABI offset");

#undef OBI_CURRENT_PROCESS_START_TIME_NS
#undef bpf_loop
#undef bpf_ktime_get_ns
#undef bpf_get_prandom_u32
#undef bpf_get_current_pid_tgid
#undef bpf_map_update_elem
#undef bpf_map_lookup_elem
#undef bpf_map_delete_elem
#undef BPF_EXIST
#undef BPF_ANY

static unsigned int failures;
static const u32 test_pid = 123;
static const u64 test_start_time = 120000000ULL;
static int sampler_ready_present;
static process_readiness_t sampler_ready;
static int sampler_override_present;
static sampler_config_t sampler_override;
static int global_sampler_present;
static sampler_config_t global_sampler;
static int auto_ready_present;
static process_readiness_t auto_ready;
static unsigned int map_lookup_calls;
static unsigned int map_update_calls;
static unsigned int map_delete_calls;
static unsigned long long last_update_flags;
static unsigned int readiness_lookup_calls;
static unsigned int global_lookup_calls;
enum sampler_lookup_mutation {
    k_sampler_lookup_mutation_none,
    k_sampler_lookup_mutation_republish_before_override,
    k_sampler_lookup_mutation_remove_before_global,
    k_sampler_lookup_mutation_replace_readiness_config_before_recheck,
    k_sampler_lookup_mutation_replace_global_before_recheck,
};
static enum sampler_lookup_mutation sampler_lookup_mutation;

static void *test_map_lookup(void *map, const void *key) {
    map_lookup_calls++;
    const u32 map_key = *(const u32 *)key;

    if (map == &sampler_ready_pids) {
        readiness_lookup_calls++;
        if (sampler_lookup_mutation ==
                k_sampler_lookup_mutation_replace_readiness_config_before_recheck &&
            readiness_lookup_calls == 2) {
            sampler_lookup_mutation = k_sampler_lookup_mutation_none;
            sampler_ready.config_epoch++;
        }
        return sampler_ready_present && map_key == test_pid ? &sampler_ready : 0;
    }
    if (map == &sampler_overrides) {
        if (sampler_lookup_mutation == k_sampler_lookup_mutation_republish_before_override) {
            sampler_lookup_mutation = k_sampler_lookup_mutation_none;
            sampler_override_present = 0;
            sampler_ready.epoch++;
        }
        return sampler_override_present && map_key == test_pid ? &sampler_override : 0;
    }
    if (map == &global_sampler_config) {
        global_lookup_calls++;
        if (sampler_lookup_mutation == k_sampler_lookup_mutation_remove_before_global) {
            sampler_lookup_mutation = k_sampler_lookup_mutation_none;
            sampler_ready_present = 0;
        }
        if (sampler_lookup_mutation == k_sampler_lookup_mutation_replace_global_before_recheck &&
            global_lookup_calls == 2) {
            sampler_lookup_mutation = k_sampler_lookup_mutation_none;
            global_sampler.publication_epoch++;
        }
        return global_sampler_present && map_key == 0 ? &global_sampler : 0;
    }
    if (map == &go_auto_sdk_ready) {
        return auto_ready_present && map_key == test_pid ? &auto_ready : 0;
    }
    return 0;
}

static long test_map_update(void *map, const void *key, const void *val, unsigned long long flags) {
    map_update_calls++;
    last_update_flags = flags;
    if (map != &go_auto_sdk_ready || *(const u32 *)key != test_pid || !auto_ready_present) {
        return -1;
    }
    auto_ready = *(const process_readiness_t *)val;
    return 0;
}

static long test_map_delete(void *map, const void *key) {
    map_delete_calls++;
    if (map != &go_auto_sdk_ready || *(const u32 *)key != test_pid || !auto_ready_present) {
        return -1;
    }
    auto_ready_present = 0;
    return 0;
}

static unsigned long long test_current_pid_tgid(void) {
    return (unsigned long long)test_pid << 32;
}

static unsigned int test_prandom(void) {
    return UINT32_C(0x12345678);
}

static unsigned long long test_ktime(void) {
    return UINT64_C(42);
}

static unsigned long long test_process_start_time(void) {
    return test_start_time;
}

static long test_bpf_loop(unsigned int nr_loops,
                          void *callback_fn,
                          void *callback_ctx,
                          unsigned long long flags) {
    (void)nr_loops;
    (void)callback_fn;
    (void)callback_ctx;
    (void)flags;
    return 0;
}

static void assert_u64(uint64_t want, uint64_t got, const char *message) {
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

static void assert_bool(int want, int got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %d, got %d\n", message, want, got);
    failures++;
}

static void reset_maps(void) {
    sampler_ready_present = 0;
    memset(&sampler_ready, 0, sizeof(sampler_ready));
    sampler_override_present = 0;
    memset(&sampler_override, 0, sizeof(sampler_override));
    global_sampler_present = 0;
    memset(&global_sampler, 0, sizeof(global_sampler));
    auto_ready_present = 0;
    memset(&auto_ready, 0, sizeof(auto_ready));
    map_lookup_calls = 0;
    map_update_calls = 0;
    map_delete_calls = 0;
    last_update_flags = 0;
    readiness_lookup_calls = 0;
    global_lookup_calls = 0;
    sampler_lookup_mutation = k_sampler_lookup_mutation_none;
}

static void ready_global_sampler(u8 type) {
    reset_maps();
    sampler_ready_present = 1;
    sampler_ready.start_time = test_start_time;
    sampler_ready.epoch = 1;
    sampler_ready.config_epoch = 1;
    sampler_ready.ready = 1;
    global_sampler_present = 1;
    global_sampler.publication_epoch = 1;
    global_sampler.type = type;
}

static tp_info_t test_traceparent(u8 flags) {
    tp_info_t tp = {.flags = flags};
    for (u8 i = 0; i < TRACE_ID_SIZE_BYTES; i++) {
        tp.trace_id[i] = i + 1;
    }
    return tp;
}

static void encode_sampler_value(unsigned char *trace_id, uint64_t value) {
    const uint64_t encoded = value << 1;
    for (unsigned int i = 0; i < sizeof(encoded); i++) {
        trace_id[TRACE_ID_SIZE_BYTES - 1 - i] = (unsigned char)(encoded >> (i * 8));
    }
}

static void test_shared_ratio_vectors(void) {
    FILE *vectors = fopen("sampling_ratio_vectors.txt", "r");
    if (!vectors) {
        vectors = fopen("bpf/tests/sampling_ratio_vectors.txt", "r");
    }
    assert_bool(1, vectors != NULL, "open shared sampling ratio vectors");
    if (!vectors) {
        return;
    }

    char name[64];
    char ratio[32];
    unsigned long long threshold;
    unsigned long long value;
    unsigned int sampled;
    unsigned int count = 0;
    while (fscanf(vectors, "%63s %31s %llx %llx %u", name, ratio, &threshold, &value, &sampled) ==
           5) {
        (void)ratio;
        ready_global_sampler(k_sampler_trace_id_ratio);
        global_sampler.trace_id_upper_bound = (uint64_t)threshold;
        unsigned char trace_id[TRACE_ID_SIZE_BYTES] = {};
        encode_sampler_value(trace_id, (uint64_t)value);
        assert_bool((int)sampled, sampler_decision_for_process(trace_id, 0, 0, 0, test_pid), name);
        count++;
    }

    assert_bool(1, count > 0, "shared sampling ratio vectors are not empty");
    assert_bool(0, fclose(vectors), "close shared sampling ratio vectors");
}

static void test_readiness_fallback_and_required_failure(void) {
    ready_global_sampler(k_sampler_always_off);
    sampler_ready_present = 0;
    tp_info_t tp = test_traceparent(k_flag_sampled | k_flag_random);
    tp.sampling_decision = k_sampling_decision_pending;
    assert_bool(1,
                apply_sampling_decision_for_process(&tp, 1, 1, test_pid),
                "missing readiness preserves fallback");
    assert_bool(
        k_flag_sampled | k_flag_random, tp.flags, "missing readiness preserves sampled flag");
    assert_bool(
        k_sampling_decision_pending, tp.sampling_decision, "missing readiness remains undecided");
    assert_bool(1, tp.parent_remote, "missing readiness preserves remote parent state");

    sampler_ready_present = 1;
    sampler_ready.ready = 0;
    tp = test_traceparent(k_flag_sampled | k_flag_random);
    tp.sampling_decision = k_sampling_decision_pending;
    assert_bool(1,
                apply_sampling_decision_for_process(&tp, 0, 0, test_pid),
                "zero readiness preserves fallback");
    assert_bool(k_flag_sampled | k_flag_random, tp.flags, "zero readiness preserves sampled flag");
    assert_bool(
        k_sampling_decision_pending, tp.sampling_decision, "zero readiness remains undecided");

    sampler_ready.ready = 1;
    sampler_ready.start_time = test_start_time + 1;
    tp = test_traceparent(k_flag_sampled | k_flag_random);
    tp.sampling_decision = k_sampling_decision_pending;
    assert_bool(1,
                apply_sampling_decision_for_process(&tp, 0, 0, test_pid),
                "stale process readiness preserves fallback");
    assert_bool(
        k_flag_sampled | k_flag_random, tp.flags, "stale process readiness preserves sampled flag");
    assert_bool(k_sampling_decision_pending,
                tp.sampling_decision,
                "stale process readiness remains undecided");

    tp = test_traceparent(k_flag_sampled | k_flag_random);
    tp.sampling_decision = k_sampling_decision_pending;
    assert_bool(0, apply_required_sampling_decision(&tp, 0, 0), "required sampler fails closed");
    assert_bool(k_flag_random, tp.flags, "required sampler clears sampled flag");
    assert_bool(k_sampling_decision_fail_closed,
                tp.sampling_decision,
                "required sampler marks fail-closed decision");
}

static void test_reused_scratch_restarts_sampling(void) {
    ready_global_sampler(k_sampler_always_off);
    tp_info_t scratch = test_traceparent(k_flag_sampled | k_flag_random);
    reset_sampling_decision(&scratch);
    assert_bool(1,
                apply_sampling_decision_for_process(&scratch, 0, 0, test_pid),
                "first scratch span applies sampler");
    assert_bool(k_flag_random, scratch.flags, "first scratch span is not sampled");

    global_sampler.type = k_sampler_always_on;
    reset_sampling_decision(&scratch);
    assert_bool(1,
                apply_sampling_decision_for_process(&scratch, 0, 0, test_pid),
                "reused scratch applies sampler again");
    assert_bool(k_flag_sampled | k_flag_random,
                scratch.flags,
                "reused scratch does not retain the prior decision");
}

static void test_wire_commit_after_sampling_fallback(void) {
    reset_maps();
    tp_info_t tp = test_traceparent(0x84);
    tp.sampling_decision = k_sampling_decision_pending;

    assert_bool(1,
                apply_sampling_decision_for_process(&tp, 1, 0, test_pid),
                "missing readiness preserves wire fallback");
    assert_bool(k_sampling_decision_pending, tp.sampling_decision, "wire fallback remains pending");

    commit_outbound_traceparent(&tp);

    assert_bool(0x84, tp.flags, "wire commit preserves fallback flags");
    assert_bool(k_sampling_decision_pending,
                tp.sampling_decision,
                "wire commit preserves userspace fallback");
}

static void test_new_root_resets_dirty_sampling_decision(void) {
    ready_global_sampler(k_sampler_always_off);
    tp_info_t dirty = test_traceparent(k_flag_sampled | k_flag_random);
    dirty.sampling_decision = k_sampling_decision_applied;

    init_new_trace_for_process(&dirty, test_pid);

    assert_bool(k_flag_random, dirty.flags, "new root applies sampler to dirty storage");
    assert_bool(k_sampling_decision_applied,
                dirty.sampling_decision,
                "new root replaces a stale terminal decision");
}

static void test_fail_closed_root_keeps_terminal_decision(void) {
    ready_global_sampler(k_sampler_always_on);
    tp_info_t tp = test_traceparent(k_flag_sampled);
    apply_fail_closed_sampler_result(&tp);

    init_new_trace_fail_closed(&tp);

    assert_bool(1, valid_trace(tp.trace_id), "fail-closed root has a trace ID");
    assert_bool(1, valid_span(tp.span_id), "fail-closed root has a span ID");
    assert_bool(k_flag_random, tp.flags, "fail-closed root remains unsampled");
    assert_bool(k_sampling_decision_fail_closed,
                tp.sampling_decision,
                "fail-closed root keeps the terminal decision");
    assert_bool(0,
                apply_sampling_decision_for_process(&tp, 0, 0, test_pid),
                "fail-closed root cannot be resampled");
    assert_bool(k_flag_random, tp.flags, "always-on cannot resample a fail-closed root");
    assert_bool(0, map_lookup_calls, "fail-closed root does not read sampler maps");
}

static void test_terminal_decisions_are_idempotent(void) {
    ready_global_sampler(k_sampler_always_on);

    tp_info_t tp = test_traceparent(k_flag_random);
    tp.sampling_decision = k_sampling_decision_applied;
    assert_bool(1,
                apply_sampling_decision_for_process(&tp, 0, 0, test_pid),
                "applied decision remains authoritative");
    assert_bool(k_flag_random, tp.flags, "applied decision preserves flags");
    assert_bool(
        k_sampling_decision_applied, tp.sampling_decision, "applied decision remains terminal");
    assert_bool(0, map_lookup_calls, "applied decision does not read sampler maps");

    tp = test_traceparent(k_flag_sampled | k_flag_random);
    tp.sampling_decision = k_sampling_decision_fail_closed;
    assert_bool(0,
                apply_sampling_decision_for_process(&tp, 0, 0, test_pid),
                "fail-closed decision remains authoritative");
    assert_bool(k_flag_random, tp.flags, "fail-closed decision keeps sampled clear");
    assert_bool(k_sampling_decision_fail_closed,
                tp.sampling_decision,
                "fail-closed decision remains terminal");
    assert_bool(0, map_lookup_calls, "fail-closed decision does not read sampler maps");
}

static void test_parent_state_is_not_a_child_decision(void) {
    ready_global_sampler(k_sampler_parent_based);
    global_sampler.local_parent_not_sampled.type = k_sampler_always_on;

    tp_info_t parent = test_traceparent(k_flag_random);
    parent.sampling_decision = k_sampling_decision_fail_closed;
    tp_info_t child = {};
    inherit_parent_sampling_state(&child, &parent);

    assert_bool(k_flag_random, child.flags, "child inherits parent trace flags");
    assert_bool(k_sampling_decision_pending,
                child.sampling_decision,
                "child starts with a pending decision");
    assert_bool(1,
                apply_sampling_decision_for_process(&child, 1, 0, test_pid),
                "child applies its own sampler decision");
    assert_bool(
        k_flag_sampled | k_flag_random, child.flags, "local unsampled delegate can sample child");
    assert_bool(k_sampling_decision_applied,
                child.sampling_decision,
                "child decision becomes authoritative");
}

static void test_global_and_override_selection(void) {
    ready_global_sampler(k_sampler_always_off);
    unsigned char trace_id[TRACE_ID_SIZE_BYTES] = {};
    assert_bool(0,
                sampler_decision_for_process(trace_id, 0, 0, 0, test_pid),
                "ready PID uses global sampler");

    sampler_override_present = 1;
    sampler_override.publication_epoch = sampler_ready.config_epoch;
    sampler_override.type = k_sampler_always_on;
    assert_bool(1,
                sampler_decision_for_process(trace_id, 0, 0, 0, test_pid),
                "per-PID sampler overrides global sampler");

    sampler_override_present = 0;
    global_sampler_present = 0;
    assert_bool(-1,
                sampler_decision_for_process(trace_id, 0, 0, 0, test_pid),
                "missing sampler has no decision");

    global_sampler_present = 1;
    global_sampler.type = k_sampler_invalid;
    assert_bool(-1,
                sampler_decision_for_process(trace_id, 0, 0, 0, test_pid),
                "invalid sampler has no decision");
}

static void test_sampler_publication_is_coherent(void) {
    ready_global_sampler(k_sampler_always_on);
    sampler_override_present = 1;
    sampler_override.publication_epoch = sampler_ready.config_epoch;
    sampler_override.type = k_sampler_always_off;
    sampler_lookup_mutation = k_sampler_lookup_mutation_republish_before_override;
    unsigned char trace_id[TRACE_ID_SIZE_BYTES] = {};

    assert_bool(k_sampler_evaluation_unavailable,
                sampler_decision_for_process(trace_id, 0, 0, 0, test_pid),
                "same-incarnation republish cannot fall through to the global sampler");

    ready_global_sampler(k_sampler_always_on);
    sampler_lookup_mutation = k_sampler_lookup_mutation_remove_before_global;
    assert_bool(k_sampler_evaluation_unavailable,
                sampler_decision_for_process(trace_id, 0, 0, 0, test_pid),
                "sampler cleanup invalidates an in-flight decision");

    ready_global_sampler(k_sampler_always_on);
    sampler_lookup_mutation = k_sampler_lookup_mutation_replace_readiness_config_before_recheck;
    assert_bool(k_sampler_evaluation_unavailable,
                sampler_decision_for_process(trace_id, 0, 0, 0, test_pid),
                "readiness config replacement invalidates an in-flight decision");

    ready_global_sampler(k_sampler_always_on);
    sampler_lookup_mutation = k_sampler_lookup_mutation_replace_global_before_recheck;
    assert_bool(k_sampler_evaluation_unavailable,
                sampler_decision_for_process(trace_id, 0, 0, 0, test_pid),
                "global sampler replacement invalidates an in-flight decision");

    ready_global_sampler(k_sampler_always_on);
    sampler_ready.epoch = 0;
    assert_bool(k_sampler_evaluation_unavailable,
                sampler_decision_for_process(trace_id, 0, 0, 0, test_pid),
                "zero publication epoch is never authoritative");
}

static void test_authoritative_flag_updates(void) {
    ready_global_sampler(k_sampler_always_on);
    tp_info_t tp = test_traceparent(k_flag_random);
    assert_bool(1,
                apply_sampling_decision_for_process(&tp, 0, 0, test_pid),
                "always-on decision is authoritative");
    assert_bool(k_flag_sampled | k_flag_random, tp.flags, "always-on preserves random flag");
    assert_bool(1, tp.sampling_decision, "always-on sets decision marker");

    global_sampler.type = k_sampler_always_off;
    tp = test_traceparent(k_flag_sampled | k_flag_random);
    assert_bool(1,
                apply_sampling_decision_for_process(&tp, 0, 0, test_pid),
                "always-off decision is authoritative");
    assert_bool(k_flag_random, tp.flags, "always-off preserves random flag");
    assert_bool(1, tp.sampling_decision, "always-off sets decision marker");
}

static void test_ratio_evaluator(void) {
    const uint64_t threshold = UINT64_C(1) << 62;
    ready_global_sampler(k_sampler_trace_id_ratio);
    global_sampler.trace_id_upper_bound = threshold;
    unsigned char trace_id[TRACE_ID_SIZE_BYTES] = {};

    encode_sampler_value(trace_id, threshold - 1);
    assert_bool(1,
                sampler_decision_for_process(trace_id, 0, 0, 0, test_pid),
                "evaluator samples below ratio threshold");

    encode_sampler_value(trace_id, threshold);
    assert_bool(0,
                sampler_decision_for_process(trace_id, 0, 0, 0, test_pid),
                "evaluator drops at ratio threshold");
}

enum parent_route {
    parent_route_root,
    parent_route_remote_sampled,
    parent_route_remote_unsampled,
    parent_route_local_sampled,
    parent_route_local_unsampled,
};

static void test_parent_route(enum parent_route route,
                              u8 has_parent,
                              u8 parent_remote,
                              u8 parent_sampled,
                              const char *message) {
    ready_global_sampler(k_sampler_parent_based);
    global_sampler.root.type = k_sampler_always_off;
    global_sampler.remote_parent_sampled.type = k_sampler_always_off;
    global_sampler.remote_parent_not_sampled.type = k_sampler_always_off;
    global_sampler.local_parent_sampled.type = k_sampler_always_off;
    global_sampler.local_parent_not_sampled.type = k_sampler_always_off;

    switch (route) {
    case parent_route_root:
        global_sampler.root.type = k_sampler_always_on;
        break;
    case parent_route_remote_sampled:
        global_sampler.remote_parent_sampled.type = k_sampler_always_on;
        break;
    case parent_route_remote_unsampled:
        global_sampler.remote_parent_not_sampled.type = k_sampler_always_on;
        break;
    case parent_route_local_sampled:
        global_sampler.local_parent_sampled.type = k_sampler_always_on;
        break;
    case parent_route_local_unsampled:
        global_sampler.local_parent_not_sampled.type = k_sampler_always_on;
        break;
    }

    unsigned char trace_id[TRACE_ID_SIZE_BYTES] = {};
    assert_bool(
        1,
        sampler_decision_for_process(trace_id, has_parent, parent_remote, parent_sampled, test_pid),
        message);
}

static void test_parent_based_routes(void) {
    test_parent_route(parent_route_root, 0, 0, 0, "parent-based root delegate");
    test_parent_route(parent_route_remote_sampled, 1, 1, 1, "parent-based remote sampled delegate");
    test_parent_route(
        parent_route_remote_unsampled, 1, 1, 0, "parent-based remote unsampled delegate");
    test_parent_route(parent_route_local_sampled, 1, 0, 1, "parent-based local sampled delegate");
    test_parent_route(
        parent_route_local_unsampled, 1, 0, 0, "parent-based local unsampled delegate");
}

static void test_pending_produce_retry_preserves_parenthood(void) {
    ready_global_sampler(k_sampler_parent_based);
    global_sampler.root.type = k_sampler_always_on;
    global_sampler.local_parent_not_sampled.type = k_sampler_always_off;

    tp_info_t root = test_traceparent(k_flag_random);
    root.sampling_decision = k_sampling_decision_pending;
    assert_bool(1,
                apply_sampling_decision_for_process(&root, valid_span(root.parent_id), 0, test_pid),
                "pending produce root uses root delegate");
    assert_bool(k_flag_sampled | k_flag_random,
                root.flags,
                "pending produce root is sampled by root delegate");

    tp_info_t child = test_traceparent(k_flag_random);
    child.parent_id[0] = 1;
    child.sampling_decision = k_sampling_decision_pending;
    assert_bool(
        1,
        apply_sampling_decision_for_process(&child, valid_span(child.parent_id), 0, test_pid),
        "pending produce child uses local-parent delegate");
    assert_bool(
        k_flag_random, child.flags, "pending produce child is dropped by local-parent delegate");
}

static void evaluate_adopted_remote_parent(tp_info_t *candidate,
                                           const unsigned char *trace_id,
                                           const unsigned char *parent_id,
                                           u8 flags) {
    memcpy(candidate->trace_id, trace_id, sizeof(candidate->trace_id));
    memcpy(candidate->parent_id, parent_id, sizeof(candidate->parent_id));
    candidate->flags = flags;
    http1_prepare_adopted_traceparent(candidate, 0);
    apply_sampling_decision_for_process(candidate, 1, 1, test_pid);
}

static void test_adopted_remote_parent_restarts_sampling(void) {
    unsigned char adopted_trace_id[TRACE_ID_SIZE_BYTES] = {};
    unsigned char adopted_parent_id[SPAN_ID_SIZE_BYTES] = {};
    memset(adopted_trace_id, 0x40, sizeof(adopted_trace_id));
    memset(adopted_parent_id, 0x50, sizeof(adopted_parent_id));

    ready_global_sampler(k_sampler_always_on);
    tp_info_t candidate = test_traceparent(k_flag_random);
    candidate.sampling_decision = k_sampling_decision_applied;
    evaluate_adopted_remote_parent(&candidate, adopted_trace_id, adopted_parent_id, k_flag_random);
    assert_bool(k_flag_sampled | k_flag_random,
                candidate.flags,
                "always-on reevaluates an adopted remote parent");
    assert_bool(1, candidate.parent_remote, "adopted parent is classified remote");

    ready_global_sampler(k_sampler_always_off);
    candidate = test_traceparent(k_flag_sampled | k_flag_random);
    candidate.sampling_decision = k_sampling_decision_applied;
    evaluate_adopted_remote_parent(
        &candidate, adopted_trace_id, adopted_parent_id, k_flag_sampled | k_flag_random);
    assert_bool(k_flag_random,
                candidate.flags,
                "always-off does not reuse a sampled decision from the replaced candidate");

    ready_global_sampler(k_sampler_trace_id_ratio);
    global_sampler.trace_id_upper_bound = UINT64_C(1) << 62;
    encode_sampler_value(adopted_trace_id, global_sampler.trace_id_upper_bound);
    candidate = test_traceparent(k_flag_sampled | k_flag_random);
    candidate.sampling_decision = k_sampling_decision_applied;
    evaluate_adopted_remote_parent(
        &candidate, adopted_trace_id, adopted_parent_id, k_flag_sampled | k_flag_random);
    assert_bool(k_flag_random, candidate.flags, "ratio sampler evaluates the adopted trace ID");

    ready_global_sampler(k_sampler_parent_based);
    global_sampler.remote_parent_sampled.type = k_sampler_always_off;
    global_sampler.remote_parent_not_sampled.type = k_sampler_always_on;
    candidate = test_traceparent(k_flag_sampled | k_flag_random);
    candidate.sampling_decision = k_sampling_decision_applied;
    evaluate_adopted_remote_parent(&candidate, adopted_trace_id, adopted_parent_id, k_flag_random);
    assert_bool(k_flag_sampled | k_flag_random,
                candidate.flags,
                "parent-based sampler routes from adopted remote flags");
}

static hpack_traceparent_result_t
scan_hpack_fixture(const unsigned char *block, u32 block_len, hpack_dynamic_name_state_t *dynamic) {
    hpack_traceparent_scan_state_t scan = {};
    hpack_traceparent_scan_init(&scan, block_len, 1);
    for (u32 step = 0; step < k_hpack_tp_max_scan && !scan.done; step++) {
        hpack_traceparent_scan_step(block, &scan, dynamic);
    }
    if (!scan.done) {
        hpack_traceparent_scan_fail(&scan);
        hpack_dynamic_name_state_invalidate(dynamic);
    }
    return hpack_traceparent_scan_result(&scan);
}

static void test_dynamic_hpack_parent_based_delegate(void) {
    // golang.org/x/net/http2/hpack emitted these fields with one encoder. The
    // second field's 0x7e opener names dynamic index 62 from the first stream.
    static const unsigned char first_stream[] = {
        0x40, 0x88, 0x4d, 0x83, 0x21, 0x6b, 0x1d, 0x85, 0xa9, 0x3f, 0xa5, 0x00,
        0x16, 0x00, 0x40, 0x20, 0x32, 0x06, 0x80, 0xd8, 0x1c, 0x03, 0xa0, 0x78,
        0x0f, 0x80, 0x60, 0x8c, 0x04, 0x04, 0x80, 0x28, 0x25, 0x08, 0x16, 0x08,
        0x42, 0x20, 0xb2, 0x16, 0x82, 0xd8, 0x5c, 0x0b, 0xa1, 0x79, 0x60, 0x07,
    };
    static const unsigned char second_stream[] = {
        0x7e, 0xa6, 0x00, 0x16, 0x10, 0x44, 0x21, 0x32, 0x26, 0x84, 0xd8, 0x9c, 0x13, 0xa2,
        0x78, 0x4f, 0x88, 0x62, 0x8c, 0x44, 0x14, 0x82, 0x28, 0xa5, 0x64, 0x0b, 0x32, 0x16,
        0x44, 0xcb, 0x2c, 0xb4, 0xcb, 0x6c, 0xb8, 0xcb, 0xac, 0xbc, 0xb0, 0x01,
    };

    ready_global_sampler(k_sampler_parent_based);
    global_sampler.root.type = k_sampler_always_on;
    global_sampler.remote_parent_sampled.type = k_sampler_always_off;
    global_sampler.remote_parent_not_sampled.type = k_sampler_always_on;

    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    hpack_traceparent_result_t result =
        scan_hpack_fixture(first_stream, sizeof(first_stream), &dynamic);
    assert_bool(
        k_hpack_traceparent_found, result.status, "first realistic stream exposes traceparent");
    tp_info_t first = {};
    hpack_traceparent_decode_result_t decoded =
        hpack_decode_traceparent_value(first_stream + result.value_offset,
                                       result.encoded_value_len,
                                       result.value_huffman,
                                       &first,
                                       1);
    assert_bool(1, decoded.valid, "first realistic remote parent decodes");
    assert_bool(0x01, first.trace_id[0], "first realistic remote trace identity");
    assert_bool(0x11, first.parent_id[0], "first realistic remote parent identity");
    assert_bool(k_flag_sampled, first.flags, "first realistic remote parent is sampled");
    assert_bool(1,
                hpack_dynamic_store_traceparent(
                    &dynamic, result.inserted_slot, result.inserted_generation, &first),
                "first realistic remote parent is cached exactly");
    reset_sampling_decision(&first);
    assert_bool(1,
                apply_sampling_decision_for_process(&first, 1, 1, test_pid),
                "sampled remote parent selects its ParentBased delegate");
    assert_bool(1, first.parent_remote, "first decoded parent is classified remote");
    assert_bool(0, first.flags & k_flag_sampled, "remote-sampled delegate drops first stream");

    static const unsigned char newest_indexed[] = {0xbe};
    result = scan_hpack_fixture(newest_indexed, sizeof(newest_indexed), &dynamic);
    assert_bool(k_hpack_traceparent_found,
                result.status,
                "fully indexed sampled parent remains authoritative");
    tp_info_t indexed_first = {.flags = result.cached_flags};
    memcpy(indexed_first.trace_id, result.cached_trace_id, sizeof(indexed_first.trace_id));
    memcpy(indexed_first.parent_id, result.cached_parent_id, sizeof(indexed_first.parent_id));
    reset_sampling_decision(&indexed_first);
    assert_bool(1,
                apply_sampling_decision_for_process(&indexed_first, 1, 1, test_pid),
                "fully indexed sampled parent selects a remote delegate");
    assert_bool(1, indexed_first.parent_remote, "fully indexed sampled parent is remote");
    assert_bool(
        0, indexed_first.flags & k_flag_sampled, "remote-sampled off beats the root-on delegate");

    result = scan_hpack_fixture(second_stream, sizeof(second_stream), &dynamic);
    assert_bool(
        k_hpack_traceparent_found, result.status, "dynamic-name second stream exposes traceparent");
    tp_info_t second = {};
    decoded = hpack_decode_traceparent_value(second_stream + result.value_offset,
                                             result.encoded_value_len,
                                             result.value_huffman,
                                             &second,
                                             1);
    assert_bool(1, decoded.valid, "dynamic-name remote parent decodes");
    assert_bool(0x21, second.trace_id[0], "dynamic-name remote trace identity");
    assert_bool(0x31, second.parent_id[0], "dynamic-name remote parent identity");
    assert_bool(0, second.flags & k_flag_sampled, "dynamic-name remote parent is unsampled");
    assert_bool(1,
                hpack_dynamic_store_traceparent(
                    &dynamic, result.inserted_slot, result.inserted_generation, &second),
                "second realistic remote parent is cached exactly");
    reset_sampling_decision(&second);
    assert_bool(1,
                apply_sampling_decision_for_process(&second, 1, 1, test_pid),
                "unsampled remote parent selects its ParentBased delegate");
    assert_bool(1, second.parent_remote, "dynamic-name decoded parent is classified remote");
    assert_bool(k_flag_sampled,
                second.flags & k_flag_sampled,
                "remote-unsampled delegate samples second stream");

    global_sampler.root.type = k_sampler_always_off;
    result = scan_hpack_fixture(newest_indexed, sizeof(newest_indexed), &dynamic);
    assert_bool(k_hpack_traceparent_found,
                result.status,
                "fully indexed unsampled parent remains authoritative");
    tp_info_t indexed_second = {.flags = result.cached_flags};
    memcpy(indexed_second.trace_id, result.cached_trace_id, sizeof(indexed_second.trace_id));
    memcpy(indexed_second.parent_id, result.cached_parent_id, sizeof(indexed_second.parent_id));
    reset_sampling_decision(&indexed_second);
    assert_bool(1,
                apply_sampling_decision_for_process(&indexed_second, 1, 1, test_pid),
                "fully indexed unsampled parent selects a remote delegate");
    assert_bool(1, indexed_second.parent_remote, "fully indexed unsampled parent is remote");
    assert_bool(k_flag_sampled,
                indexed_second.flags & k_flag_sampled,
                "remote-unsampled on beats the root-off delegate");
}

static void test_hpack_desync_is_metric_only_fail_closed(void) {
    ready_global_sampler(k_sampler_parent_based);
    global_sampler.root.type = k_sampler_always_on;

    tp_info_t metric_trace = {.flags = k_flag_sampled};
    apply_fail_closed_sampler_result(&metric_trace);
    new_trace_id(&metric_trace);
    assert_bool(1,
                apply_sampling_decision_for_process(&metric_trace, 0, 0, test_pid) == 0,
                "desynced request keeps a terminal fail-closed decision");
    assert_bool(k_sampling_decision_fail_closed,
                metric_trace.sampling_decision,
                "desynced request cannot be root-resampled");
    assert_bool(0,
                metric_trace.flags & k_flag_sampled,
                "root-on cannot export a desynced unknown-parent span");
    assert_bool(1,
                valid_trace(metric_trace.trace_id),
                "desynced request retains a correlation ID for unsampled metrics");
}

static void test_auto_sdk_readiness(void) {
    reset_maps();
    assert_bool(1, go_auto_sdk_readiness() == 0, "absent Auto SDK readiness");
    assert_bool(0, go_auto_sdk_is_ready(), "absent Auto SDK is not ready");
    assert_bool(0, go_auto_sdk_activation_epoch(), "absent Auto SDK has no epoch");

    auto_ready_present = 1;
    assert_bool(1, go_auto_sdk_readiness() != 0, "disabled Auto SDK readiness is owned");
    assert_bool(0,
                go_auto_sdk_readiness_is_current(&auto_ready),
                "zero-start Auto SDK readiness is not current");
    assert_bool(0, go_auto_sdk_is_ready(), "disabled Auto SDK is not ready");
    assert_bool(0, go_auto_sdk_activation_epoch(), "disabled Auto SDK has no epoch");

    auto_ready.start_time = test_start_time;
    auto_ready.epoch = 17;
    auto_ready.ready = 1;
    assert_bool(
        1, go_auto_sdk_readiness_is_current(&auto_ready), "matching Auto SDK readiness is current");
    assert_bool(0, go_auto_sdk_is_ready(), "Auto SDK waits for sampler readiness");
    assert_bool(0, go_auto_sdk_activation_epoch(), "Auto SDK with no sampler has no epoch");

    sampler_ready_present = 1;
    sampler_ready.start_time = test_start_time;
    sampler_ready.epoch = 1;
    sampler_ready.config_epoch = 1;
    sampler_ready.ready = 1;
    assert_bool(1, go_auto_sdk_is_ready(), "enabled Auto SDK is ready");
    assert_bool(17, go_auto_sdk_activation_epoch(), "enabled Auto SDK publishes its epoch");
    assert_bool(0,
                go_auto_sdk_global_activation_epoch(),
                "direct-only Auto SDK readiness blocks global activation");
    auto_ready.auto_sdk_global_ready = 1;
    assert_bool(
        17, go_auto_sdk_global_activation_epoch(), "global Auto SDK readiness publishes its epoch");
    disable_go_auto_sdk();
    assert_bool(1, map_delete_calls, "disable deletes readiness");
    assert_bool(0, auto_ready_present, "disable removes readiness");

    auto_ready_present = 1;
    auto_ready.start_time = test_start_time + 1;
    auto_ready.ready = 1;
    assert_bool(0,
                go_auto_sdk_readiness_is_current(&auto_ready),
                "stale Auto SDK readiness is not current");
    assert_bool(0, go_auto_sdk_is_ready(), "stale Auto SDK readiness is not ready");
    assert_bool(0, go_auto_sdk_activation_epoch(), "stale Auto SDK has no current epoch");
    assert_bool(0, go_auto_sdk_global_activation_epoch(), "stale Auto SDK has no global epoch");
    disable_go_auto_sdk();
    assert_bool(0, auto_ready_present, "disable removes stale Auto SDK readiness");

    reset_maps();
    disable_go_auto_sdk();
    assert_bool(1, map_delete_calls, "disable tolerates absent readiness");
    assert_bool(0, auto_ready_present, "disable does not create readiness");
}

int main(void) {
    unsigned char trace_id[16] = {0};

    trace_id[8] = 0x12;
    trace_id[9] = 0x34;
    trace_id[10] = 0x56;
    trace_id[11] = 0x78;
    trace_id[12] = 0x9a;
    trace_id[13] = 0xbc;
    trace_id[14] = 0xde;
    trace_id[15] = 0xf0;
    assert_u64(UINT64_C(0x091a2b3c4d5e6f78), sampler_trace_id_value(trace_id), "big endian value");

    const uint64_t threshold = UINT64_C(1) << 62;
    uint64_t encoded = (threshold - 1) << 1;
    for (unsigned int i = 0; i < 8; i++) {
        trace_id[15 - i] = (unsigned char)(encoded >> (i * 8));
    }
    assert_bool(1, sampler_trace_id_ratio(trace_id, threshold), "below threshold");

    encoded = threshold << 1;
    for (unsigned int i = 0; i < 8; i++) {
        trace_id[15 - i] = (unsigned char)(encoded >> (i * 8));
    }
    assert_bool(0, sampler_trace_id_ratio(trace_id, threshold), "equal threshold");

    encoded = (threshold + 1) << 1;
    for (unsigned int i = 0; i < 8; i++) {
        trace_id[15 - i] = (unsigned char)(encoded >> (i * 8));
    }
    assert_bool(0, sampler_trace_id_ratio(trace_id, threshold), "above threshold");
    assert_bool(0, sampler_trace_id_ratio(trace_id, 0), "zero ratio");
    assert_bool(1, sampler_trace_id_ratio(trace_id, UINT64_C(1) << 63), "one ratio");
    test_shared_ratio_vectors();

    test_readiness_fallback_and_required_failure();
    test_reused_scratch_restarts_sampling();
    test_wire_commit_after_sampling_fallback();
    test_new_root_resets_dirty_sampling_decision();
    test_fail_closed_root_keeps_terminal_decision();
    test_terminal_decisions_are_idempotent();
    test_parent_state_is_not_a_child_decision();
    test_global_and_override_selection();
    test_sampler_publication_is_coherent();
    test_authoritative_flag_updates();
    test_ratio_evaluator();
    test_parent_based_routes();
    test_pending_produce_retry_preserves_parenthood();
    test_adopted_remote_parent_restarts_sampling();
    test_dynamic_hpack_parent_based_delegate();
    test_hpack_desync_is_metric_only_fail_closed();
    test_auto_sdk_readiness();

    return failures == 0 ? 0 : 1;
}
