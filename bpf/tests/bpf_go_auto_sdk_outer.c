// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags);
static void *test_map_lookup(void *map, const void *key);
static long test_map_delete(void *map, const void *key);
static long test_probe_write(void *dst, const void *src, unsigned int size);

#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2
#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete
#define bpf_probe_write_user test_probe_write

#include <gotracer/maps/auto_sdk.h>

#undef bpf_probe_write_user
#undef bpf_map_delete_elem
#undef bpf_map_update_elem
#undef bpf_map_lookup_elem
#undef BPF_NOEXIST
#undef BPF_EXIST
#undef BPF_ANY

_Static_assert(k_go_auto_sdk_outer_map_type == BPF_MAP_TYPE_HASH,
               "Auto SDK outer calls must be non-evicting");
_Static_assert(k_go_auto_sdk_inflight_map_type == BPF_MAP_TYPE_HASH,
               "Auto SDK in-flight state must be non-evicting");
_Static_assert(sizeof(go_auto_sdk_inflight_key_t) == 32, "Go Auto SDK in-flight key ABI changed");
_Static_assert(offsetof(go_auto_sdk_inflight_key_t, auto_sdk_epoch) == 24,
               "Go Auto SDK in-flight epoch ABI changed");
_Static_assert(sizeof(go_auto_sdk_inflight_t) == 8, "Go Auto SDK in-flight value ABI changed");
_Static_assert(offsetof(go_auto_sdk_inflight_t, state) == 0,
               "Go Auto SDK in-flight state ABI changed");
_Static_assert(sizeof(go_auto_sdk_outer_call_t) == 32, "Go Auto SDK outer-call value ABI changed");
_Static_assert(offsetof(go_auto_sdk_outer_call_t, direct_entry_kind) == 29,
               "Go Auto SDK direct-entry kind ABI changed");
_Static_assert(offsetof(go_auto_sdk_outer_call_t, direct_depth) == 30,
               "Go Auto SDK direct-entry depth ABI changed");
_Static_assert(offsetof(go_auto_sdk_outer_call_t, rejected_returns) == 31,
               "Go Auto SDK rejected-return count ABI changed");

static unsigned int failures;
static go_addr_key_t stored_key;
static go_auto_sdk_outer_call_t stored_call;
static u8 stored_present;
static go_auto_sdk_inflight_key_t inflight_key;
static go_auto_sdk_inflight_t inflight;
static u8 inflight_present;
static go_auto_sdk_inflight_key_t second_inflight_key;
static go_auto_sdk_inflight_t second_inflight;
static u8 second_inflight_present;
static u8 fail_probe_write;
static u8 fail_outer_update;
static u8 delete_outer_as_absent;

static void assert_bool(int want, int got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %d, got %d\n", message, want, got);
    failures++;
}

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    if (map == &go_auto_sdk_inflight) {
        const go_auto_sdk_inflight_key_t *candidate_key = key;
        if (inflight_present && memcmp(candidate_key, &inflight_key, sizeof(inflight_key)) == 0) {
            if (flags == 1) {
                return -1;
            }
            inflight = *(const go_auto_sdk_inflight_t *)value;
            return 0;
        }
        if (second_inflight_present &&
            memcmp(candidate_key, &second_inflight_key, sizeof(second_inflight_key)) == 0) {
            if (flags == 1) {
                return -1;
            }
            second_inflight = *(const go_auto_sdk_inflight_t *)value;
            return 0;
        }
        if (!inflight_present) {
            inflight_key = *candidate_key;
            inflight = *(const go_auto_sdk_inflight_t *)value;
            inflight_present = 1;
            return 0;
        }
        if (!second_inflight_present) {
            second_inflight_key = *candidate_key;
            second_inflight = *(const go_auto_sdk_inflight_t *)value;
            second_inflight_present = 1;
            return 0;
        }
        return -1;
    }
    if (map != &go_auto_sdk_outer_calls) {
        return -1;
    }
    if (fail_outer_update) {
        return -1;
    }
    const go_addr_key_t *candidate_key = key;
    if (stored_present && memcmp(candidate_key, &stored_key, sizeof(stored_key)) != 0) {
        return -1;
    }
    if (stored_present && flags == 1) {
        return -1;
    }
    if (!stored_present && flags == 2) {
        return -1;
    }
    stored_key = *candidate_key;
    stored_call = *(const go_auto_sdk_outer_call_t *)value;
    stored_present = 1;
    return 0;
}

static void *test_map_lookup(void *map, const void *key) {
    if (map == &go_auto_sdk_outer_calls) {
        if (!stored_present || memcmp(key, &stored_key, sizeof(stored_key)) != 0) {
            return NULL;
        }
        return &stored_call;
    }
    if (map != &go_auto_sdk_inflight) {
        return NULL;
    }
    if (inflight_present && memcmp(key, &inflight_key, sizeof(inflight_key)) == 0) {
        return &inflight;
    }
    if (second_inflight_present &&
        memcmp(key, &second_inflight_key, sizeof(second_inflight_key)) == 0) {
        return &second_inflight;
    }
    return NULL;
}

static long test_map_delete(void *map, const void *key) {
    if (map != &go_auto_sdk_outer_calls || !stored_present ||
        memcmp(key, &stored_key, sizeof(stored_key)) != 0) {
        return -1;
    }
    stored_present = 0;
    if (delete_outer_as_absent) {
        return -1;
    }
    return 0;
}

static long test_probe_write(void *dst, const void *src, unsigned int size) {
    if (fail_probe_write || !dst) {
        return -1;
    }
    memcpy(dst, src, size);
    return 0;
}

static void reset_state(void) {
    memset(&stored_key, 0, sizeof(stored_key));
    memset(&stored_call, 0, sizeof(stored_call));
    memset(&inflight_key, 0, sizeof(inflight_key));
    memset(&inflight, 0, sizeof(inflight));
    memset(&second_inflight_key, 0, sizeof(second_inflight_key));
    memset(&second_inflight, 0, sizeof(second_inflight));
    stored_present = 0;
    inflight_present = 0;
    second_inflight_present = 0;
    fail_probe_write = 0;
    fail_outer_update = 0;
    delete_outer_as_absent = 0;
}

static void test_saturation_preserves_live_outer_call(void) {
    reset_state();
    const go_addr_key_t old_key = {
        .pid = 42,
        .addr = 0x1000,
    };
    const go_addr_key_t new_key = {
        .pid = 42,
        .addr = 0x2000,
    };

    assert_bool(
        1,
        store_go_auto_sdk_outer_call(&old_key, 100, 7, 3, 0x3000, k_go_auto_sdk_outer_active) == 0,
        "store live outer call");
    const u8 new_activated =
        store_go_auto_sdk_outer_call(&new_key, 100, 7, 3, 0x4000, k_go_auto_sdk_outer_active) == 0;
    assert_bool(0, new_activated, "saturated new activation stays inactive");
    assert_bool(
        0,
        store_go_auto_sdk_outer_call(&new_key, 100, 7, 3, 0x4000, k_go_auto_sdk_outer_capture) == 0,
        "saturated capture cannot evict live state");
    assert_bool(1, stored_present, "live outer call remains stored");
    assert_bool(1,
                memcmp(&stored_key, &old_key, sizeof(old_key)) == 0,
                "new activation cannot replace the live key");
    assert_bool(k_go_auto_sdk_outer_active,
                stored_call.state,
                "new activation cannot alter the live state");
}

static void test_active_registration_and_consumption_preserve_count(void) {
    reset_state();
    const go_addr_key_t goroutine = {
        .pid = 42,
        .addr = 0x5000,
    };
    inflight_key = go_auto_sdk_inflight_key(42, 7, 100, 3);
    inflight_present = 1;

    assert_bool(1,
                register_go_auto_sdk_active_outer_call(&goroutine, &inflight_key, 0x6000) == 0,
                "active outer registration commits");
    assert_bool(1,
                go_auto_sdk_inflight_active_calls(&inflight),
                "active registration increments exact count");
    assert_bool(
        k_go_auto_sdk_outer_active, stored_call.state, "active registration stores active state");

    stored_call.state = k_go_auto_sdk_outer_consumed_active;
    assert_bool(1,
                go_auto_sdk_inflight_active_calls(&inflight),
                "active to consumed transition preserves count");
    assert_bool(1,
                finish_go_auto_sdk_active_call(&inflight_key),
                "outer return decrements committed count");
    assert_bool(
        0, go_auto_sdk_inflight_active_calls(&inflight), "outer return reaches exact zero once");
}

static void test_outer_insert_failure_poison_retains_nonzero_count(void) {
    reset_state();
    stored_key = (go_addr_key_t){
        .pid = 42,
        .addr = 0x7000,
    };
    stored_call.state = k_go_auto_sdk_outer_active;
    stored_present = 1;
    inflight_key = go_auto_sdk_inflight_key(42, 7, 100, 3);
    inflight_present = 1;
    const go_addr_key_t colliding = {
        .pid = 42,
        .addr = 0x8000,
    };

    assert_bool(0,
                register_go_auto_sdk_active_outer_call(&colliding, &inflight_key, 0x9000) == 0,
                "outer-map saturation fails registration");
    assert_bool(2,
                go_auto_sdk_inflight_active_calls(&inflight),
                "failed outer commit retains its count and poison sentinel");
    assert_bool(1,
                go_auto_sdk_inflight_poison_generation(&inflight),
                "failed outer commit poisons live drain authority");
}

static void test_pointer_value_wrapper_reuses_one_exact_count(void) {
    reset_state();
    const go_addr_key_t goroutine = {
        .pid = 42,
        .addr = 0xa000,
    };
    inflight_key = go_auto_sdk_inflight_key(42, 7, 100, 3);
    inflight_present = 1;

    assert_bool(1,
                register_go_auto_sdk_direct_outer_call(
                    &goroutine, &inflight_key, k_go_auto_sdk_direct_entry_pointer) == 0,
                "pointer wrapper registers direct outer call");
    assert_bool(1,
                go_auto_sdk_inflight_active_calls(&inflight),
                "pointer wrapper increments the exact count once");
    assert_bool(k_go_auto_sdk_direct_entry_pointer,
                stored_call.direct_entry_kind,
                "pointer wrapper kind is retained");
    assert_bool(1, stored_call.direct_depth, "pointer wrapper starts at depth one");

    assert_bool(1,
                nest_go_auto_sdk_direct_value_wrapper(&goroutine, &inflight_key),
                "nested value wrapper reuses pointer state");
    assert_bool(1,
                go_auto_sdk_inflight_active_calls(&inflight),
                "nested value wrapper does not double count");
    assert_bool(k_go_auto_sdk_direct_entry_nested_value,
                stored_call.direct_entry_kind,
                "nested wrapper transition is explicit");
    assert_bool(2, stored_call.direct_depth, "nested wrapper records depth two");

    const go_auto_sdk_outer_call_t nested = stored_call;
    assert_bool(1,
                unnest_go_auto_sdk_direct_value_wrapper(&goroutine, &inflight_key, &nested),
                "value return preserves the outer pointer wrapper");
    assert_bool(1,
                go_auto_sdk_inflight_active_calls(&inflight),
                "value return preserves the outer exact count");
    assert_bool(1, stored_call.direct_depth, "value return leaves one public wrapper");
    assert_bool(1,
                finish_go_auto_sdk_active_call(&inflight_key),
                "outer pointer return retires the exact count");
    assert_bool(
        0, go_auto_sdk_inflight_active_calls(&inflight), "outer pointer return reaches exact zero");
}

static void test_noncanonical_direct_reentry_cannot_reuse_state(void) {
    reset_state();
    const go_addr_key_t goroutine = {
        .pid = 42,
        .addr = 0xb000,
    };
    inflight_key = go_auto_sdk_inflight_key(42, 7, 100, 3);
    inflight_present = 1;

    assert_bool(1,
                register_go_auto_sdk_direct_outer_call(
                    &goroutine, &inflight_key, k_go_auto_sdk_direct_entry_value) == 0,
                "value receiver registers direct outer call");
    assert_bool(0,
                nest_go_auto_sdk_direct_value_wrapper(&goroutine, &inflight_key),
                "value-to-value reentry cannot claim wrapper reuse");
    assert_bool(1,
                go_auto_sdk_inflight_active_calls(&inflight),
                "rejected reuse does not alter the exact count");

    assert_bool(0,
                register_go_auto_sdk_direct_outer_call(
                    &goroutine, &inflight_key, k_go_auto_sdk_direct_entry_value) == 0,
                "noncanonical reentry collides instead of stealing state");
    assert_bool(3,
                go_auto_sdk_inflight_active_calls(&inflight),
                "ambiguous reentry retains both counts and poison sentinel");
    assert_bool(1,
                go_auto_sdk_inflight_poison_generation(&inflight),
                "ambiguous reentry poisons drain authority");
    assert_bool(1, stored_call.rejected_returns, "ambiguous reentry records its matching return");
    assert_bool(1,
                consume_go_auto_sdk_rejected_return(&goroutine),
                "rejected nested return is consumed before owner retirement");
    assert_bool(0, stored_call.rejected_returns, "rejected return count reaches zero");
    assert_bool(k_go_auto_sdk_outer_direct_active,
                stored_call.state,
                "rejected return leaves the original owner untouched");
}

static void test_stale_pre_is_retired_before_new_count(void) {
    reset_state();
    const go_addr_key_t goroutine = {
        .pid = 42,
        .addr = 0xb025,
    };
    stored_key = goroutine;
    stored_call = (go_auto_sdk_outer_call_t){
        .start_time = 99,
        .generation = GO_AUTO_SDK_PENDING_GENERATION,
        .flag_ptr = 0xb026,
        .auto_sdk_epoch = GO_AUTO_SDK_PENDING_EPOCH,
        .state = k_go_auto_sdk_outer_pre,
    };
    stored_present = 1;
    inflight_key = go_auto_sdk_pending_inflight_key();
    inflight.state = 1;
    inflight_present = 1;

    assert_bool(1,
                prepare_go_auto_sdk_outer_call_slot(&goroutine, 100),
                "replacement process retires stale PRE before admission");
    assert_bool(0, stored_present, "stale PRE owner is removed");
    assert_bool(
        0, go_auto_sdk_inflight_active_calls(&inflight), "stale PRE count is retired exactly");
    assert_bool(0,
                go_auto_sdk_inflight_poison_generation(&inflight),
                "stale retirement does not poison PRE");

    assert_bool(1,
                register_go_auto_sdk_pending_outer_call(&goroutine, 100, 0xb027) == 0,
                "replacement process acquires a fresh PRE count");
    assert_bool(1, stored_present, "replacement PRE owner is stored");
    assert_bool(100, stored_call.start_time, "replacement PRE uses current incarnation");
    assert_bool(0, stored_call.rejected_returns, "stale owner records no rejected return");
    assert_bool(
        1, go_auto_sdk_inflight_active_calls(&inflight), "replacement PRE owns one exact count");
    assert_bool(
        0, go_auto_sdk_inflight_poison_generation(&inflight), "replacement PRE remains drainable");
}

static void test_stale_direct_owner_is_retired_before_new_count(void) {
    reset_state();
    const go_addr_key_t goroutine = {
        .pid = 42,
        .addr = 0xb040,
    };
    stored_key = goroutine;
    stored_call = (go_auto_sdk_outer_call_t){
        .start_time = 99,
        .generation = 6,
        .auto_sdk_epoch = 2,
        .state = k_go_auto_sdk_outer_direct_active,
        .direct_entry_kind = k_go_auto_sdk_direct_entry_value,
        .direct_depth = 1,
    };
    stored_present = 1;
    inflight_key = go_auto_sdk_inflight_key(42, 6, 99, 2);
    inflight.state = 1;
    inflight_present = 1;
    second_inflight_key = go_auto_sdk_inflight_key(42, 7, 100, 3);
    second_inflight_present = 1;

    assert_bool(1,
                prepare_go_auto_sdk_outer_call_slot(&goroutine, 100),
                "replacement process retires stale direct owner before admission");
    assert_bool(0, stored_present, "stale direct owner is removed");
    assert_bool(
        0, go_auto_sdk_inflight_active_calls(&inflight), "stale direct count is retired exactly");

    assert_bool(1,
                register_go_auto_sdk_direct_outer_call(
                    &goroutine, &second_inflight_key, k_go_auto_sdk_direct_entry_value) == 0,
                "replacement process acquires a fresh direct count");
    assert_bool(1,
                go_auto_sdk_inflight_active_calls(&second_inflight),
                "replacement direct owner has one exact count");
    assert_bool(0,
                go_auto_sdk_inflight_poison_generation(&second_inflight),
                "replacement direct owner remains drainable");
    assert_bool(100, stored_call.start_time, "replacement direct owner uses current incarnation");
}

static void test_concurrent_stale_outer_cleanup_leaves_slot_ready(void) {
    reset_state();
    const go_addr_key_t goroutine = {
        .pid = 42,
        .addr = 0xb060,
    };
    stored_key = goroutine;
    stored_call = (go_auto_sdk_outer_call_t){
        .start_time = 99,
        .generation = 6,
        .auto_sdk_epoch = 2,
        .state = k_go_auto_sdk_outer_direct_active,
        .direct_entry_kind = k_go_auto_sdk_direct_entry_value,
        .direct_depth = 1,
    };
    stored_present = 1;
    delete_outer_as_absent = 1;

    assert_bool(1,
                prepare_go_auto_sdk_outer_call_slot(&goroutine, 100),
                "concurrent stale deletion leaves the slot ready");
    assert_bool(0, stored_present, "concurrent cleanup leaves no stale owner");
}

static void test_missing_stale_inflight_leaves_slot_ready(void) {
    reset_state();
    const go_addr_key_t goroutine = {
        .pid = 42,
        .addr = 0xb065,
    };
    stored_key = goroutine;
    stored_call = (go_auto_sdk_outer_call_t){
        .start_time = 99,
        .generation = 6,
        .auto_sdk_epoch = 2,
        .state = k_go_auto_sdk_outer_direct_active,
        .direct_entry_kind = k_go_auto_sdk_direct_entry_value,
        .direct_depth = 1,
    };
    stored_present = 1;

    assert_bool(1,
                prepare_go_auto_sdk_outer_call_slot(&goroutine, 100),
                "missing stale counter does not block the clear slot");
    assert_bool(0, stored_present, "stale owner is removed without its old counter");
}

static void test_rejected_pointer_wrapper_accounts_for_both_returns(void) {
    reset_state();
    const go_addr_key_t goroutine = {
        .pid = 42,
        .addr = 0xb050,
    };
    inflight_key = go_auto_sdk_inflight_key(42, 7, 100, 3);
    inflight_present = 1;

    assert_bool(1,
                register_go_auto_sdk_direct_outer_call(
                    &goroutine, &inflight_key, k_go_auto_sdk_direct_entry_pointer) == 0,
                "outer pointer wrapper registers");
    assert_bool(0,
                register_go_auto_sdk_direct_outer_call(
                    &goroutine, &inflight_key, k_go_auto_sdk_direct_entry_pointer) == 0,
                "reentrant pointer wrapper cannot replace its owner");
    assert_bool(
        1, stored_call.rejected_returns, "reentrant pointer entry records its pointer return");
    assert_bool(0,
                nest_go_auto_sdk_direct_value_wrapper(&goroutine, &inflight_key),
                "reentrant value wrapper cannot nest while a rejected return is pending");
    assert_bool(0,
                register_go_auto_sdk_direct_outer_call(
                    &goroutine, &inflight_key, k_go_auto_sdk_direct_entry_value) == 0,
                "reentrant value wrapper cannot replace its owner");
    assert_bool(
        2, stored_call.rejected_returns, "pointer invocation records both matching returns");

    assert_bool(
        1, consume_go_auto_sdk_rejected_return(&goroutine), "reentrant value return is consumed");
    assert_bool(
        1, consume_go_auto_sdk_rejected_return(&goroutine), "reentrant pointer return is consumed");
    assert_bool(0, stored_call.rejected_returns, "both rejected returns are exhausted");
    assert_bool(k_go_auto_sdk_outer_direct_active,
                stored_call.state,
                "rejected wrapper returns leave the original owner intact");
    assert_bool(1,
                finish_go_auto_sdk_active_call(&inflight_key),
                "original pointer return retires its exact count");
}

static void test_invalid_value_admission_preserves_pointer_owner(void) {
    reset_state();
    const go_addr_key_t goroutine = {
        .pid = 42,
        .addr = 0xb075,
    };
    inflight_key = go_auto_sdk_inflight_key(42, 7, 100, 3);
    inflight_present = 1;
    assert_bool(1,
                register_go_auto_sdk_direct_outer_call(
                    &goroutine, &inflight_key, k_go_auto_sdk_direct_entry_pointer) == 0,
                "pointer owner registers before readiness changes");

    assert_bool(0,
                mark_go_auto_sdk_direct_outer_call(
                    &goroutine, 7, 100, 0, k_go_auto_sdk_direct_entry_value) == 0,
                "value wrapper rejects a revoked activation epoch");
    assert_bool(1, stored_call.rejected_returns, "invalid value entry records its matching return");
    assert_bool(
        1, consume_go_auto_sdk_rejected_return(&goroutine), "invalid value return is consumed");
    assert_bool(k_go_auto_sdk_outer_direct_active,
                stored_call.state,
                "invalid value return leaves the pointer owner intact");
    assert_bool(
        1, go_auto_sdk_inflight_active_calls(&inflight), "pointer owner retains its exact count");
    assert_bool(1,
                finish_go_auto_sdk_active_call(&inflight_key),
                "pointer return performs the sole retirement");
    assert_bool(
        0, go_auto_sdk_inflight_active_calls(&inflight), "pointer count reaches zero exactly once");
}

static void test_rejected_global_return_cannot_retire_existing_owner(void) {
    reset_state();
    const go_addr_key_t goroutine = {
        .pid = 42,
        .addr = 0xb100,
    };
    inflight_key = go_auto_sdk_inflight_key(42, 7, 100, 3);
    inflight_present = 1;
    assert_bool(1,
                register_go_auto_sdk_active_outer_call(&goroutine, &inflight_key, 0xb200) == 0,
                "existing global owner registers");

    second_inflight_key = go_auto_sdk_pending_inflight_key();
    second_inflight_present = 1;
    assert_bool(0,
                register_go_auto_sdk_pending_outer_call(&goroutine, 100, 0xb300) == 0,
                "nested global registration cannot replace its owner");
    assert_bool(2,
                go_auto_sdk_inflight_active_calls(&second_inflight),
                "failed nested entry keeps its count and poison sentinel");
    assert_bool(1,
                go_auto_sdk_inflight_poison_generation(&second_inflight),
                "failed nested entry poisons its drain authority");
    assert_bool(1, stored_call.rejected_returns, "nested global entry records its return");
    assert_bool(1,
                consume_go_auto_sdk_rejected_return(&goroutine),
                "nested global return is consumed before owner retirement");
    assert_bool(k_go_auto_sdk_outer_active,
                stored_call.state,
                "nested global return leaves the original owner untouched");
}

static void test_rejected_return_saturation_is_sticky(void) {
    reset_state();
    stored_key = (go_addr_key_t){
        .pid = 42,
        .addr = 0xb400,
    };
    stored_call = (go_auto_sdk_outer_call_t){
        .start_time = 100,
        .generation = 7,
        .auto_sdk_epoch = 3,
        .state = k_go_auto_sdk_outer_direct_active,
        .direct_entry_kind = k_go_auto_sdk_direct_entry_value,
        .direct_depth = 1,
    };
    stored_call.rejected_returns = (u8)~0U;
    stored_present = 1;

    assert_bool(
        1, record_go_auto_sdk_rejected_return(&stored_key), "saturated rejection remains recorded");
    assert_bool(1,
                consume_go_auto_sdk_rejected_return(&stored_key),
                "saturated rejected return remains fail-closed");
    assert_bool(
        (u8)~0U, stored_call.rejected_returns, "saturated rejection count never exposes the owner");
}

static void test_stale_global_marker_cannot_skip_direct_count(void) {
    reset_state();
    const go_auto_sdk_inflight_key_t current = go_auto_sdk_inflight_key(42, 7, 100, 3);
    const go_auto_sdk_outer_call_t stale_global = {
        .start_time = 99,
        .generation = 6,
        .flag_ptr = 0xc000,
        .auto_sdk_epoch = 2,
        .state = k_go_auto_sdk_outer_active,
    };

    assert_bool(1,
                go_auto_sdk_outer_call_is_global(&stale_global),
                "stale global state is recognized for retirement");
    assert_bool(0,
                go_auto_sdk_outer_call_is_exact_counted_global(&stale_global, &current),
                "stale global state cannot authorize an uncounted direct call");

    const go_addr_key_t goroutine = {
        .pid = 42,
        .addr = 0xc100,
    };
    stored_key = goroutine;
    stored_call = stale_global;
    stored_present = 1;
    inflight_key = current;
    inflight_present = 1;
    assert_bool(0,
                register_go_auto_sdk_direct_outer_call(
                    &goroutine, &current, k_go_auto_sdk_direct_entry_value) == 0,
                "stale counted global state cannot be retired or stolen");
    assert_bool(2,
                go_auto_sdk_inflight_active_calls(&inflight),
                "stale global collision retains its count and poison sentinel");
    assert_bool(1,
                go_auto_sdk_inflight_poison_generation(&inflight),
                "stale global collision poisons current drain authority");
    assert_bool(k_go_auto_sdk_outer_active,
                stored_call.state,
                "stale counted global owner remains for its return");
}

static void test_revoked_readiness_reuses_admitted_global_count(void) {
    reset_state();
    const go_auto_sdk_inflight_key_t admitted = go_auto_sdk_inflight_key(42, 7, 100, 3);
    const go_auto_sdk_outer_call_t global = {
        .start_time = 100,
        .generation = 7,
        .flag_ptr = 0xc200,
        .auto_sdk_epoch = 3,
        .state = k_go_auto_sdk_outer_active,
    };
    const u32 current_readiness_epoch = 0;

    assert_bool(1,
                go_auto_sdk_outer_call_is_exact_counted_global(&global, &admitted),
                "admitted global owner is exact after readiness revocation");
    assert_bool(
        0, current_readiness_epoch, "test models readiness revoked before delayed direct entry");
    inflight_key = admitted;
    inflight_present = 1;
    inflight.state = 1;
    assert_bool(1,
                go_auto_sdk_inflight_active_calls(&inflight),
                "revoked readiness cannot retire the admitted global count");
}

static void test_post_mark_activation_promotes_without_retiring(void) {
    reset_state();
    const go_auto_sdk_inflight_key_t current = go_auto_sdk_inflight_key(42, 7, 100, 3);
    const go_addr_key_t goroutine = {
        .pid = 42,
        .addr = 0xd100,
    };
    inflight_key = current;
    inflight_present = 1;
    assert_bool(1,
                register_go_auto_sdk_counted_outer_call(
                    &goroutine, &current, 0xd000, k_go_auto_sdk_outer_capture) == 0,
                "capture owns an exact count before the flag can become true");
    const go_auto_sdk_outer_call_t capture = stored_call;

    assert_bool(1,
                go_auto_sdk_outer_call_is_global(&capture),
                "capture state is recognized for replacement");
    assert_bool(0,
                go_auto_sdk_outer_call_is_exact_counted_global(&capture, &current),
                "capture state cannot authorize an uncounted direct call");

    assert_bool(
        1,
        resolve_go_auto_sdk_counted_capture(&goroutine, &capture, k_go_auto_sdk_capture_promote),
        "post-mark activation promotes the capture in place");
    assert_bool(1,
                go_auto_sdk_inflight_active_calls(&inflight),
                "capture-to-active promotion preserves the exact count");
    assert_bool(k_go_auto_sdk_outer_active,
                stored_call.state,
                "capture activation race promotes global ownership in place");
    assert_bool(1,
                finish_go_auto_sdk_active_call(&current),
                "owning global return retires the promoted capture count");
    assert_bool(0,
                go_auto_sdk_inflight_active_calls(&inflight),
                "promoted capture reaches zero only at its owning return");
}

static void test_noexist_loss_preserves_counted_capture(void) {
    reset_state();
    const go_auto_sdk_inflight_key_t current = go_auto_sdk_inflight_key(42, 7, 100, 3);
    const go_addr_key_t goroutine = {
        .pid = 42,
        .addr = 0xd200,
    };
    inflight_key = current;
    inflight_present = 1;
    assert_bool(1,
                register_go_auto_sdk_counted_outer_call(
                    &goroutine, &current, 0xd000, k_go_auto_sdk_outer_capture) == 0,
                "capture registers before a competing publication");
    const go_auto_sdk_outer_call_t capture = stored_call;

    // Model a BPF_NOEXIST loss to another exact CAPTURED publisher. The
    // losing invocation remains counted until its own NewSpan return.
    assert_bool(
        1,
        resolve_go_auto_sdk_counted_capture(&goroutine, &capture, k_go_auto_sdk_capture_preserve),
        "exact publication conflict preserves the capture");
    assert_bool(k_go_auto_sdk_outer_capture,
                stored_call.state,
                "NOEXIST loss cannot clear or consume capture ownership");
    assert_bool(1,
                go_auto_sdk_inflight_active_calls(&inflight),
                "NOEXIST loss cannot decrement the exact count");
    assert_bool(0,
                go_auto_sdk_inflight_poison_generation(&inflight),
                "an exact competing capture is not ambiguous");
    assert_bool(1,
                finish_go_auto_sdk_active_call(&current),
                "owning NewSpan return retires the preserved capture");
    assert_bool(0,
                go_auto_sdk_inflight_active_calls(&inflight),
                "preserved capture reaches zero only at its owning return");
}

static void test_pending_gate_handoff_never_drops_ownership(void) {
    reset_state();
    const go_addr_key_t goroutine = {
        .pid = 42,
        .addr = 0xd300,
    };
    const go_auto_sdk_inflight_key_t pending = go_auto_sdk_pending_inflight_key();
    inflight_key = pending;
    inflight_present = 1;

    assert_bool(1,
                register_go_auto_sdk_pending_outer_call(&goroutine, 100, 0xd000) == 0,
                "preprovisioned global latch registers PRE ownership");
    assert_bool(1, inflight_present, "pending registration retains the reserved map entry");
    assert_bool(1,
                memcmp(&inflight_key, &pending, sizeof(pending)) == 0,
                "PRE registration uses the fixed global sentinel");
    assert_bool(1,
                go_auto_sdk_inflight_active_calls(&inflight),
                "pending registration owns the call before gate reread");
    assert_bool(k_go_auto_sdk_outer_pre,
                stored_call.state,
                "pending registration stores dedicated PRE ownership");
    const go_auto_sdk_outer_call_t pending_capture = stored_call;

    const go_auto_sdk_inflight_key_t active = go_auto_sdk_inflight_key(42, 7, 100, 3);
    second_inflight_key = active;
    second_inflight_present = 1;
    assert_bool(1,
                migrate_go_auto_sdk_pending_capture(&goroutine, &pending_capture, &active),
                "gate publication migrates ownership to the real epoch");
    assert_bool(0,
                go_auto_sdk_inflight_active_calls(&inflight),
                "pending count retires only after real ownership commits");
    assert_bool(1,
                go_auto_sdk_inflight_active_calls(&second_inflight),
                "real count is held before pending ownership retires");
    assert_bool(7, stored_call.generation, "outer ownership records the fresh generation");
    assert_bool(3, stored_call.auto_sdk_epoch, "outer ownership records the published epoch");
    assert_bool(k_go_auto_sdk_outer_capture,
                stored_call.state,
                "migration commits exact CAPTURE ownership before PRE retires");
}

static void test_pending_return_retires_fixed_global_latch(void) {
    reset_state();
    const go_addr_key_t goroutine = {
        .pid = 42,
        .addr = 0xd400,
    };
    inflight_key = go_auto_sdk_pending_inflight_key();
    inflight_present = 1;
    assert_bool(1,
                register_go_auto_sdk_pending_outer_call(&goroutine, 100, 0xd000) == 0,
                "PRE registration acquires the fixed global latch");
    const go_auto_sdk_outer_call_t pending = stored_call;
    const go_auto_sdk_inflight_key_t return_key =
        go_auto_sdk_outer_inflight_key(&goroutine, &pending);
    assert_bool(1,
                finish_go_auto_sdk_active_call(&return_key),
                "PRE return resolves to the fixed sentinel independent of process PID");
    assert_bool(0,
                go_auto_sdk_inflight_active_calls(&inflight),
                "PRE return retires exactly one global latch count");
}

static void test_counter_saturation_and_underflow_poison(void) {
    reset_state();
    inflight_key = go_auto_sdk_inflight_key(42, 7, 100, 3);
    inflight_present = 1;
    inflight.state = MAX_CONCURRENT_SHARED_REQUESTS;
    assert_bool(0, begin_go_auto_sdk_active_call(&inflight_key), "counter saturation fails closed");
    assert_bool(MAX_CONCURRENT_SHARED_REQUESTS + 1,
                go_auto_sdk_inflight_active_calls(&inflight),
                "counter saturation adds only the poison sentinel");
    assert_bool(
        1, go_auto_sdk_inflight_poison_generation(&inflight), "counter saturation poisons drain");

    inflight.state = 0;
    assert_bool(0, finish_go_auto_sdk_active_call(&inflight_key), "counter underflow fails closed");
    assert_bool(
        1, go_auto_sdk_inflight_active_calls(&inflight), "counter underflow adds a sentinel");
    assert_bool(
        1, go_auto_sdk_inflight_poison_generation(&inflight), "counter underflow poisons drain");
}

static void test_packed_counter_poison_ordering(void) {
    reset_state();
    inflight_key = go_auto_sdk_inflight_key(42, 7, 100, 3);
    inflight_present = 1;

    inflight.state = 1;
    poison_go_auto_sdk_inflight(&inflight_key);
    assert_bool(1,
                finish_go_auto_sdk_active_call(&inflight_key),
                "a poisoned owner can still retire its exact count");
    assert_bool(1,
                go_auto_sdk_inflight_active_calls(&inflight),
                "poison before retirement preserves one low-word sentinel");
    assert_bool(1,
                go_auto_sdk_inflight_poison_generation(&inflight),
                "poison before retirement remains sticky");

    inflight.state = 1;
    assert_bool(
        1, finish_go_auto_sdk_active_call(&inflight_key), "an unpoisoned owner retires normally");
    poison_go_auto_sdk_inflight(&inflight_key);
    assert_bool(1,
                go_auto_sdk_inflight_active_calls(&inflight),
                "poison after retirement adds one low-word sentinel");
    assert_bool(1,
                go_auto_sdk_inflight_poison_generation(&inflight),
                "poison after retirement makes zero non-drainable");

    inflight.state = GO_AUTO_SDK_INFLIGHT_POISON_UNIT;
    assert_bool(0,
                finish_go_auto_sdk_active_call(&inflight_key),
                "a duplicate retirement cannot borrow from poison");
    assert_bool(0,
                go_auto_sdk_inflight_active_calls(&inflight),
                "a duplicate retirement leaves the low word at zero");
    assert_bool(1,
                go_auto_sdk_inflight_poison_generation(&inflight),
                "a duplicate retirement cannot clear poison");

    inflight.state = MAX_CONCURRENT_SHARED_REQUESTS;
    assert_bool(0,
                begin_go_auto_sdk_active_call(&inflight_key),
                "the configured active-call bound rejects admission");
    assert_bool(MAX_CONCURRENT_SHARED_REQUESTS + 1,
                go_auto_sdk_inflight_active_calls(&inflight),
                "bound rejection adds only the poison sentinel");
    assert_bool(1,
                go_auto_sdk_inflight_poison_generation(&inflight),
                "bound rejection poisons the lifetime word");
}

static void test_sampled_decision_is_synchronously_false(void) {
    reset_state();
    bool sampled = true;
    assert_bool(1, force_go_auto_sdk_unsampled(&sampled), "sampled decision write succeeds");
    assert_bool(0, sampled, "sampled decision is false before validation");

    sampled = true;
    fail_probe_write = 1;
    assert_bool(
        0, force_go_auto_sdk_unsampled(&sampled), "sampled decision write failure is observable");
    assert_bool(1, sampled, "failed write cannot claim a false decision");
}

static go_auto_sdk_outer_call_t global_handoff_call(enum go_auto_sdk_outer_state state) {
    return (go_auto_sdk_outer_call_t){
        .start_time = 100,
        .generation = 7,
        .flag_ptr = 0xe000,
        .auto_sdk_epoch = 3,
        .state = state,
    };
}

static go_auto_sdk_outer_call_t direct_handoff_call(enum go_auto_sdk_direct_entry_kind kind,
                                                    u8 depth) {
    return (go_auto_sdk_outer_call_t){
        .start_time = 100,
        .generation = 7,
        .auto_sdk_epoch = 3,
        .state = k_go_auto_sdk_outer_direct_active,
        .direct_entry_kind = kind,
        .direct_depth = depth,
    };
}

static enum go_auto_sdk_handoff_owner consume_handoff(const go_auto_sdk_outer_call_t *call,
                                                      u64 generation,
                                                      u32 epoch,
                                                      u8 global_handoff,
                                                      u8 handoff_failed,
                                                      u8 capture_committed,
                                                      u8 incarnation_matches) {
    stored_key = (go_addr_key_t){
        .pid = 42,
        .addr = 0xf000,
    };
    stored_call = *call;
    stored_present = 1;
    return consume_exact_go_auto_sdk_handoff(&stored_key,
                                             call,
                                             generation,
                                             epoch,
                                             global_handoff,
                                             handoff_failed,
                                             capture_committed,
                                             incarnation_matches);
}

static void test_inner_handoff_requires_exact_ownership(void) {
    reset_state();
    const go_auto_sdk_outer_call_t active = global_handoff_call(k_go_auto_sdk_outer_active);

    assert_bool(k_go_auto_sdk_handoff_none,
                consume_handoff(&active, 7, 0, 1, 0, 0, 1),
                "zero span epoch cannot claim ownership");
    assert_bool(
        k_go_auto_sdk_outer_active, stored_call.state, "zero epoch preserves the outer state");
    assert_bool(k_go_auto_sdk_handoff_none,
                consume_handoff(&active, 7, 3, 1, 1, 0, 1),
                "failed handoff cannot claim ownership");
    assert_bool(k_go_auto_sdk_handoff_none,
                consume_handoff(&active, 8, 3, 1, 0, 0, 1),
                "generation mismatch cannot claim ownership");
    assert_bool(k_go_auto_sdk_handoff_none,
                consume_handoff(&active, 7, 4, 1, 0, 0, 1),
                "epoch mismatch cannot claim ownership");
    assert_bool(k_go_auto_sdk_handoff_none,
                consume_handoff(&active, 7, 3, 0, 0, 0, 1),
                "global state cannot claim a direct handoff");
    assert_bool(k_go_auto_sdk_handoff_none,
                consume_handoff(&active, 7, 3, 1, 0, 0, 0),
                "stale process incarnation cannot claim ownership");

    assert_bool(k_go_auto_sdk_handoff_global,
                consume_handoff(&active, 7, 3, 1, 0, 0, 1),
                "exact active global handoff is consumed");
    assert_bool(k_go_auto_sdk_outer_consumed_active,
                stored_call.state,
                "exact global handoff records consumption");

    const go_auto_sdk_outer_call_t capture = global_handoff_call(k_go_auto_sdk_outer_capture);
    assert_bool(k_go_auto_sdk_handoff_none,
                consume_handoff(&capture, 7, 3, 1, 0, 0, 1),
                "uncommitted capture cannot claim ownership");
    assert_bool(k_go_auto_sdk_outer_capture,
                stored_call.state,
                "uncommitted capture remains available to its outer return");
    assert_bool(k_go_auto_sdk_handoff_global,
                consume_handoff(&capture, 7, 3, 1, 0, 1, 1),
                "committed exact capture is consumed");
    assert_bool(k_go_auto_sdk_outer_consumed_active,
                stored_call.state,
                "committed capture records consumption");
}

static void test_inner_direct_handoff_metadata_is_exact(void) {
    reset_state();
    const go_auto_sdk_outer_call_t pointer =
        direct_handoff_call(k_go_auto_sdk_direct_entry_pointer, 1);
    const go_auto_sdk_outer_call_t value = direct_handoff_call(k_go_auto_sdk_direct_entry_value, 1);
    const go_auto_sdk_outer_call_t nested =
        direct_handoff_call(k_go_auto_sdk_direct_entry_nested_value, 2);
    const go_auto_sdk_outer_call_t invalid =
        direct_handoff_call(k_go_auto_sdk_direct_entry_nested_value, 1);

    assert_bool(k_go_auto_sdk_handoff_direct,
                consume_handoff(&pointer, 7, 3, 0, 0, 0, 1),
                "exact pointer wrapper handoff is consumed");
    assert_bool(k_go_auto_sdk_outer_direct_consumed,
                stored_call.state,
                "pointer wrapper records consumption");
    assert_bool(k_go_auto_sdk_handoff_direct,
                consume_handoff(&value, 7, 3, 0, 0, 0, 1),
                "exact value wrapper handoff is consumed");
    assert_bool(k_go_auto_sdk_handoff_direct,
                consume_handoff(&nested, 7, 3, 0, 0, 0, 1),
                "exact nested wrapper handoff is consumed");
    assert_bool(k_go_auto_sdk_handoff_none,
                consume_handoff(&invalid, 7, 3, 0, 0, 0, 1),
                "invalid direct metadata cannot claim ownership");
    assert_bool(k_go_auto_sdk_outer_direct_active,
                stored_call.state,
                "invalid direct metadata remains available to its outer return");
    assert_bool(k_go_auto_sdk_handoff_none,
                consume_handoff(&pointer, 7, 3, 1, 0, 0, 1),
                "direct state cannot claim a global handoff");
}

static void test_failed_inner_consumption_preserves_outer_state(void) {
    reset_state();
    const go_auto_sdk_outer_call_t active = global_handoff_call(k_go_auto_sdk_outer_active);
    fail_outer_update = 1;

    assert_bool(k_go_auto_sdk_handoff_none,
                consume_handoff(&active, 7, 3, 1, 0, 0, 1),
                "failed BPF_EXIST transition cannot claim ownership");
    assert_bool(k_go_auto_sdk_outer_active,
                stored_call.state,
                "failed transition preserves ownership for the outer return");
}

int main(void) {
    test_saturation_preserves_live_outer_call();
    test_active_registration_and_consumption_preserve_count();
    test_outer_insert_failure_poison_retains_nonzero_count();
    test_pointer_value_wrapper_reuses_one_exact_count();
    test_noncanonical_direct_reentry_cannot_reuse_state();
    test_stale_pre_is_retired_before_new_count();
    test_stale_direct_owner_is_retired_before_new_count();
    test_concurrent_stale_outer_cleanup_leaves_slot_ready();
    test_missing_stale_inflight_leaves_slot_ready();
    test_rejected_pointer_wrapper_accounts_for_both_returns();
    test_invalid_value_admission_preserves_pointer_owner();
    test_rejected_global_return_cannot_retire_existing_owner();
    test_rejected_return_saturation_is_sticky();
    test_stale_global_marker_cannot_skip_direct_count();
    test_revoked_readiness_reuses_admitted_global_count();
    test_post_mark_activation_promotes_without_retiring();
    test_noexist_loss_preserves_counted_capture();
    test_pending_gate_handoff_never_drops_ownership();
    test_pending_return_retires_fixed_global_latch();
    test_counter_saturation_and_underflow_poison();
    test_packed_counter_poison_ordering();
    test_sampled_decision_is_synchronously_false();
    test_inner_handoff_requires_exact_ownership();
    test_inner_direct_handoff_metadata_is_exact();
    test_failed_inner_consumption_preserves_outer_state();
    return failures ? 1 : 0;
}
