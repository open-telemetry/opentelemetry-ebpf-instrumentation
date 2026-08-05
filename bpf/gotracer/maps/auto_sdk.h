// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/go_addr_key.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

#define GO_AUTO_SDK_PENDING_EPOCH ((u32)~0U)
#define GO_AUTO_SDK_PENDING_GENERATION ((u64)~0ULL)
#define GO_AUTO_SDK_PENDING_PID ((u64)0)
#define GO_AUTO_SDK_PENDING_START_TIME ((u64)~0ULL)
#define GO_AUTO_SDK_INFLIGHT_POISON_UNIT (1ULL << 32)
#define GO_AUTO_SDK_INFLIGHT_POISON_MARKER (GO_AUTO_SDK_INFLIGHT_POISON_UNIT | 1ULL)

enum go_auto_sdk_outer_state : u8 {
    k_go_auto_sdk_outer_none = 0,
    k_go_auto_sdk_outer_capture = 1,
    k_go_auto_sdk_outer_active = 2,
    k_go_auto_sdk_outer_consumed_active = 3,
    k_go_auto_sdk_outer_direct_active = 4,
    k_go_auto_sdk_outer_direct_consumed = 5,
    k_go_auto_sdk_outer_pre = 6,
};

enum go_auto_sdk_direct_entry_kind : u8 {
    k_go_auto_sdk_direct_entry_none = 0,
    k_go_auto_sdk_direct_entry_pointer = 1,
    k_go_auto_sdk_direct_entry_value = 2,
    k_go_auto_sdk_direct_entry_nested_value = 3,
};

enum go_auto_sdk_capture_resolution : u8 {
    k_go_auto_sdk_capture_preserve = 0,
    k_go_auto_sdk_capture_promote = 1,
    k_go_auto_sdk_capture_poison = 2,
};

enum go_auto_sdk_handoff_owner : u8 {
    k_go_auto_sdk_handoff_none = 0,
    k_go_auto_sdk_handoff_global = 1,
    k_go_auto_sdk_handoff_direct = 2,
};

typedef struct go_auto_sdk_outer_call {
    u64 start_time;
    u64 generation;
    u64 flag_ptr;
    u32 auto_sdk_epoch;
    u8 state;
    u8 direct_entry_kind;
    u8 direct_depth;
    u8 rejected_returns;
} go_auto_sdk_outer_call_t;

typedef struct go_auto_sdk_inflight_key {
    u64 pid;
    u64 generation;
    u64 start_time;
    u32 auto_sdk_epoch;
    u32 _pad;
} go_auto_sdk_inflight_key_t;

typedef struct go_auto_sdk_inflight {
    u64 state;
} go_auto_sdk_inflight_t;

static __always_inline u8
go_auto_sdk_outer_call_has_no_direct_metadata(const go_auto_sdk_outer_call_t *call) {
    return call && call->direct_entry_kind == k_go_auto_sdk_direct_entry_none &&
           call->direct_depth == 0;
}

static __always_inline u8
go_auto_sdk_direct_handoff_metadata_valid(const go_auto_sdk_outer_call_t *call) {
    return call && !call->flag_ptr &&
           ((call->direct_depth == 1 &&
             (call->direct_entry_kind == k_go_auto_sdk_direct_entry_pointer ||
              call->direct_entry_kind == k_go_auto_sdk_direct_entry_value)) ||
            (call->direct_depth == 2 &&
             call->direct_entry_kind == k_go_auto_sdk_direct_entry_nested_value));
}

static __always_inline enum go_auto_sdk_handoff_owner
go_auto_sdk_classify_handoff(const go_auto_sdk_outer_call_t *call,
                             u64 current_generation,
                             u32 span_auto_sdk_epoch,
                             u8 global_handoff,
                             u8 handoff_failed,
                             u8 capture_activation_committed,
                             u8 process_incarnation_matches) {
    if (!call || !current_generation || !span_auto_sdk_epoch || !call->start_time ||
        call->generation != current_generation || call->auto_sdk_epoch != span_auto_sdk_epoch ||
        handoff_failed || !process_incarnation_matches) {
        return k_go_auto_sdk_handoff_none;
    }
    if (global_handoff) {
        if (!call->flag_ptr || !go_auto_sdk_outer_call_has_no_direct_metadata(call)) {
            return k_go_auto_sdk_handoff_none;
        }
        if (call->state == k_go_auto_sdk_outer_active ||
            (call->state == k_go_auto_sdk_outer_capture && capture_activation_committed)) {
            return k_go_auto_sdk_handoff_global;
        }
        return k_go_auto_sdk_handoff_none;
    }
    if (call->state == k_go_auto_sdk_outer_direct_active &&
        go_auto_sdk_direct_handoff_metadata_valid(call)) {
        return k_go_auto_sdk_handoff_direct;
    }
    return k_go_auto_sdk_handoff_none;
}

static __always_inline u8 go_auto_sdk_outer_call_is_global(const go_auto_sdk_outer_call_t *call) {
    return go_auto_sdk_outer_call_has_no_direct_metadata(call) &&
           (call->state == k_go_auto_sdk_outer_capture ||
            call->state == k_go_auto_sdk_outer_active ||
            call->state == k_go_auto_sdk_outer_consumed_active);
}

static __always_inline u8 go_auto_sdk_outer_call_is_exact_counted_global(
    const go_auto_sdk_outer_call_t *call, const go_auto_sdk_inflight_key_t *key) {
    return call && key && key->pid && key->generation && key->start_time && key->auto_sdk_epoch &&
           call->flag_ptr && go_auto_sdk_outer_call_has_no_direct_metadata(call) &&
           (call->state == k_go_auto_sdk_outer_active ||
            call->state == k_go_auto_sdk_outer_consumed_active) &&
           call->start_time == key->start_time && call->generation == key->generation &&
           call->auto_sdk_epoch == key->auto_sdk_epoch;
}

enum { k_go_auto_sdk_outer_map_type = BPF_MAP_TYPE_HASH };
enum { k_go_auto_sdk_inflight_map_type = BPF_MAP_TYPE_HASH };

struct {
    __uint(type, k_go_auto_sdk_outer_map_type);
    __type(key, go_addr_key_t);
    __type(value, go_auto_sdk_outer_call_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_auto_sdk_outer_calls SEC(".maps");

struct {
    __uint(type, k_go_auto_sdk_inflight_map_type);
    __type(key, go_auto_sdk_inflight_key_t);
    __type(value, go_auto_sdk_inflight_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_auto_sdk_inflight SEC(".maps");

// Outer-call state is keyed by goroutine, so a reentrant entry can collide
// with its caller. Record that failed entry in the existing value: returns are
// LIFO on one goroutine and must skip the matching number of rejected frames
// before the original owner may retire its state. Saturation remains sticky
// and fail-closed.
static __always_inline u8 record_go_auto_sdk_rejected_return(const go_addr_key_t *goroutine_key) {
    if (!goroutine_key) {
        return 0;
    }
    go_auto_sdk_outer_call_t *stored = bpf_map_lookup_elem(&go_auto_sdk_outer_calls, goroutine_key);
    if (!stored) {
        return 0;
    }
    if (stored->rejected_returns != (u8)~0U) {
        stored->rejected_returns++;
    }
    return 1;
}

static __always_inline u8 consume_go_auto_sdk_rejected_return(const go_addr_key_t *goroutine_key) {
    if (!goroutine_key) {
        return 0;
    }
    go_auto_sdk_outer_call_t *stored = bpf_map_lookup_elem(&go_auto_sdk_outer_calls, goroutine_key);
    if (!stored || !stored->rejected_returns) {
        return 0;
    }
    if (stored->rejected_returns != (u8)~0U) {
        stored->rejected_returns--;
    }
    return 1;
}

static __always_inline enum go_auto_sdk_handoff_owner
consume_exact_go_auto_sdk_handoff(const go_addr_key_t *goroutine_key,
                                  const go_auto_sdk_outer_call_t *call,
                                  u64 current_generation,
                                  u32 span_auto_sdk_epoch,
                                  u8 global_handoff,
                                  u8 handoff_failed,
                                  u8 capture_activation_committed,
                                  u8 process_incarnation_matches) {
    const enum go_auto_sdk_handoff_owner owner =
        go_auto_sdk_classify_handoff(call,
                                     current_generation,
                                     span_auto_sdk_epoch,
                                     global_handoff,
                                     handoff_failed,
                                     capture_activation_committed,
                                     process_incarnation_matches);
    if (owner == k_go_auto_sdk_handoff_none || !goroutine_key) {
        return k_go_auto_sdk_handoff_none;
    }
    go_auto_sdk_outer_call_t consumed = *call;
    consumed.state = owner == k_go_auto_sdk_handoff_global ? k_go_auto_sdk_outer_consumed_active
                                                           : k_go_auto_sdk_outer_direct_consumed;
    if (bpf_map_update_elem(&go_auto_sdk_outer_calls, goroutine_key, &consumed, BPF_EXIST) != 0) {
        return k_go_auto_sdk_handoff_none;
    }
    return owner;
}

static __always_inline go_auto_sdk_inflight_key_t go_auto_sdk_inflight_key(u64 pid,
                                                                           u64 generation,
                                                                           u64 start_time,
                                                                           u32 auto_sdk_epoch) {
    return (go_auto_sdk_inflight_key_t){
        .pid = pid,
        .generation = generation,
        .start_time = start_time,
        .auto_sdk_epoch = auto_sdk_epoch,
    };
}

static __always_inline go_auto_sdk_inflight_key_t go_auto_sdk_pending_inflight_key(void) {
    return go_auto_sdk_inflight_key(GO_AUTO_SDK_PENDING_PID,
                                    GO_AUTO_SDK_PENDING_GENERATION,
                                    GO_AUTO_SDK_PENDING_START_TIME,
                                    GO_AUTO_SDK_PENDING_EPOCH);
}

static __always_inline u8
go_auto_sdk_is_pending_inflight_key(const go_auto_sdk_inflight_key_t *key) {
    return key && key->pid == GO_AUTO_SDK_PENDING_PID &&
           key->generation == GO_AUTO_SDK_PENDING_GENERATION &&
           key->start_time == GO_AUTO_SDK_PENDING_START_TIME &&
           key->auto_sdk_epoch == GO_AUTO_SDK_PENDING_EPOCH;
}

static __always_inline u8 go_auto_sdk_inflight_key_valid(const go_auto_sdk_inflight_key_t *key) {
    return key && key->generation && key->start_time && key->auto_sdk_epoch &&
           (key->pid || go_auto_sdk_is_pending_inflight_key(key));
}

static __always_inline go_auto_sdk_inflight_key_t go_auto_sdk_outer_inflight_key(
    const go_addr_key_t *goroutine_key, const go_auto_sdk_outer_call_t *call) {
    if (call && call->state == k_go_auto_sdk_outer_pre) {
        return go_auto_sdk_pending_inflight_key();
    }
    return go_auto_sdk_inflight_key(goroutine_key ? goroutine_key->pid : 0,
                                    call ? call->generation : 0,
                                    call ? call->start_time : 0,
                                    call ? call->auto_sdk_epoch : 0);
}

static __always_inline u64 go_auto_sdk_inflight_read_state(const go_auto_sdk_inflight_t *inflight) {
    return *(volatile const u64 *)&inflight->state;
}

static __always_inline u32 go_auto_sdk_inflight_active_calls_from_state(const u64 state) {
    return (u32)state;
}

static __always_inline u32 go_auto_sdk_inflight_poison_generation_from_state(const u64 state) {
    return (u32)(state >> 32);
}

static __always_inline u32
go_auto_sdk_inflight_active_calls(const go_auto_sdk_inflight_t *inflight) {
    return go_auto_sdk_inflight_active_calls_from_state(go_auto_sdk_inflight_read_state(inflight));
}

static __always_inline u32
go_auto_sdk_inflight_poison_generation(const go_auto_sdk_inflight_t *inflight) {
    return go_auto_sdk_inflight_poison_generation_from_state(
        go_auto_sdk_inflight_read_state(inflight));
}

static __always_inline void poison_go_auto_sdk_inflight(const go_auto_sdk_inflight_key_t *key) {
    if (!go_auto_sdk_inflight_key_valid(key)) {
        return;
    }
    go_auto_sdk_inflight_t *inflight = bpf_map_lookup_elem(&go_auto_sdk_inflight, key);
    if (!inflight) {
        return;
    }
    const u64 state = go_auto_sdk_inflight_read_state(inflight);
    if (!go_auto_sdk_inflight_poison_generation_from_state(state)) {
        // The low-word sentinel prevents a non-atomic userspace map copy from
        // combining the old poison word with a post-poison zero active count.
        // The ignored result keeps this as legacy XADD on minimum kernels.
        // Concurrent first poisoners may add more than one marker, but later
        // poison attempts observe a nonzero high word and cannot wrap it.
        __sync_fetch_and_add(&inflight->state, GO_AUTO_SDK_INFLIGHT_POISON_MARKER);
    }
}

static __always_inline u8 begin_go_auto_sdk_active_call(const go_auto_sdk_inflight_key_t *key) {
    if (!go_auto_sdk_inflight_key_valid(key)) {
        return 0;
    }
    go_auto_sdk_inflight_t *inflight = bpf_map_lookup_elem(&go_auto_sdk_inflight, key);
    if (!inflight) {
        return 0;
    }
    u64 state = go_auto_sdk_inflight_read_state(inflight);
    if (go_auto_sdk_inflight_poison_generation_from_state(state) ||
        go_auto_sdk_inflight_active_calls_from_state(state) >= MAX_CONCURRENT_SHARED_REQUESTS) {
        poison_go_auto_sdk_inflight(key);
        return 0;
    }

    // The active count is bounded by the outer-call map, so +1 cannot carry
    // into the poison generation. Ignoring the result emits legacy XADD
    // instead of a fetch atomic unavailable on older supported kernels.
    __sync_fetch_and_add(&inflight->state, (u64)1);
    state = go_auto_sdk_inflight_read_state(inflight);
    if (go_auto_sdk_inflight_poison_generation_from_state(state) ||
        go_auto_sdk_inflight_active_calls_from_state(state) > MAX_CONCURRENT_SHARED_REQUESTS) {
        // No outer owner exists to retire this admission. Retaining the
        // increment keeps every failed race visibly non-drainable.
        poison_go_auto_sdk_inflight(key);
        return 0;
    }
    return 1;
}

static __always_inline u8 finish_go_auto_sdk_active_call(const go_auto_sdk_inflight_key_t *key) {
    if (!go_auto_sdk_inflight_key_valid(key)) {
        return 0;
    }
    go_auto_sdk_inflight_t *inflight = bpf_map_lookup_elem(&go_auto_sdk_inflight, key);
    if (!inflight) {
        return 0;
    }
    const u64 state = go_auto_sdk_inflight_read_state(inflight);
    const u32 active_calls = go_auto_sdk_inflight_active_calls_from_state(state);
    if (!active_calls || active_calls > MAX_CONCURRENT_SHARED_REQUESTS) {
        poison_go_auto_sdk_inflight(key);
        return 0;
    }

    // Only the successful outer-map owner deletion may retire a count.
    // Under that invariant, adding -1 cannot borrow from the poison word.
    __sync_fetch_and_add(&inflight->state, ~(u64)0);
    return 1;
}

static __always_inline long clear_go_auto_sdk_outer_call(const go_addr_key_t *goroutine_key) {
    return bpf_map_delete_elem(&go_auto_sdk_outer_calls, goroutine_key);
}

static __always_inline u8 go_auto_sdk_outer_call_counted(const u8 state) {
    return state == k_go_auto_sdk_outer_pre || state == k_go_auto_sdk_outer_active ||
           state == k_go_auto_sdk_outer_capture || state == k_go_auto_sdk_outer_consumed_active ||
           state == k_go_auto_sdk_outer_direct_active ||
           state == k_go_auto_sdk_outer_direct_consumed;
}

static __always_inline u8 retire_go_auto_sdk_outer_call(const go_addr_key_t *goroutine_key,
                                                        const go_auto_sdk_outer_call_t *call) {
    if (!call || clear_go_auto_sdk_outer_call(goroutine_key)) {
        return 0;
    }
    if (!go_auto_sdk_outer_call_counted(call->state)) {
        return 1;
    }
    const go_auto_sdk_inflight_key_t inflight_key =
        go_auto_sdk_outer_inflight_key(goroutine_key, call);
    return finish_go_auto_sdk_active_call(&inflight_key);
}

static __always_inline void
poison_go_auto_sdk_outer_inflight(const go_addr_key_t *goroutine_key,
                                  const go_auto_sdk_outer_call_t *call) {
    if (!call || !go_auto_sdk_outer_call_counted(call->state)) {
        return;
    }
    const go_auto_sdk_inflight_key_t inflight_key =
        go_auto_sdk_outer_inflight_key(goroutine_key, call);
    poison_go_auto_sdk_inflight(&inflight_key);
}

// Uprobes can run in a replacement process before userspace has reaped a
// goroutine key left by the previous PID incarnation. Retire that owner before
// acquiring a new count; otherwise a failed BPF_NOEXIST store would leave an
// unrepresented, poisoned count that no return probe can retire.
static __always_inline u8 prepare_go_auto_sdk_outer_call_slot(const go_addr_key_t *goroutine_key,
                                                              const u64 current_start_time) {
    if (!goroutine_key || !current_start_time) {
        return 0;
    }
    const go_auto_sdk_outer_call_t *stored =
        bpf_map_lookup_elem(&go_auto_sdk_outer_calls, goroutine_key);
    if (!stored) {
        return 1;
    }
    const go_auto_sdk_outer_call_t found = *stored;
    if (found.start_time == current_start_time) {
        return 1;
    }
    if (clear_go_auto_sdk_outer_call(goroutine_key)) {
        const go_auto_sdk_outer_call_t *current =
            bpf_map_lookup_elem(&go_auto_sdk_outer_calls, goroutine_key);
        return !current || current->start_time == current_start_time;
    }
    if (go_auto_sdk_outer_call_counted(found.state)) {
        const go_auto_sdk_inflight_key_t stale_key =
            go_auto_sdk_outer_inflight_key(goroutine_key, &found);
        finish_go_auto_sdk_active_call(&stale_key);
    }
    return 1;
}

static __always_inline long
store_go_auto_sdk_outer_call_with_direct(const go_addr_key_t *goroutine_key,
                                         u64 start_time,
                                         u64 generation,
                                         u32 auto_sdk_epoch,
                                         u64 flag_ptr,
                                         enum go_auto_sdk_outer_state state,
                                         enum go_auto_sdk_direct_entry_kind direct_entry_kind,
                                         u8 direct_depth) {
    if (!goroutine_key || !start_time ||
        (state != k_go_auto_sdk_outer_pre && state != k_go_auto_sdk_outer_capture &&
         state != k_go_auto_sdk_outer_active && state != k_go_auto_sdk_outer_direct_active) ||
        (state == k_go_auto_sdk_outer_direct_active &&
         (direct_entry_kind == k_go_auto_sdk_direct_entry_none || direct_depth != 1)) ||
        (state != k_go_auto_sdk_outer_direct_active &&
         (direct_entry_kind != k_go_auto_sdk_direct_entry_none || direct_depth != 0))) {
        return -1;
    }
    const go_auto_sdk_outer_call_t call = {
        .start_time = start_time,
        .generation = generation,
        .flag_ptr = flag_ptr,
        .auto_sdk_epoch = auto_sdk_epoch,
        .state = state,
        .direct_entry_kind = direct_entry_kind,
        .direct_depth = direct_depth,
    };
    return bpf_map_update_elem(&go_auto_sdk_outer_calls, goroutine_key, &call, BPF_NOEXIST);
}

static __always_inline long store_go_auto_sdk_outer_call(const go_addr_key_t *goroutine_key,
                                                         u64 start_time,
                                                         u64 generation,
                                                         u32 auto_sdk_epoch,
                                                         u64 flag_ptr,
                                                         enum go_auto_sdk_outer_state state) {
    return store_go_auto_sdk_outer_call_with_direct(goroutine_key,
                                                    start_time,
                                                    generation,
                                                    auto_sdk_epoch,
                                                    flag_ptr,
                                                    state,
                                                    k_go_auto_sdk_direct_entry_none,
                                                    0);
}

static __always_inline long register_go_auto_sdk_counted_outer_call_with_direct(
    const go_addr_key_t *goroutine_key,
    const go_auto_sdk_inflight_key_t *inflight_key,
    u64 flag_ptr,
    enum go_auto_sdk_outer_state state,
    enum go_auto_sdk_direct_entry_kind direct_entry_kind,
    u8 direct_depth) {
    if (state != k_go_auto_sdk_outer_capture && state != k_go_auto_sdk_outer_active &&
        state != k_go_auto_sdk_outer_direct_active) {
        record_go_auto_sdk_rejected_return(goroutine_key);
        return -1;
    }
    if (!begin_go_auto_sdk_active_call(inflight_key)) {
        record_go_auto_sdk_rejected_return(goroutine_key);
        return -1;
    }
    const long ret = store_go_auto_sdk_outer_call_with_direct(goroutine_key,
                                                              inflight_key->start_time,
                                                              inflight_key->generation,
                                                              inflight_key->auto_sdk_epoch,
                                                              flag_ptr,
                                                              state,
                                                              direct_entry_kind,
                                                              direct_depth);
    if (ret) {
        // The process flag may already be true, so rolling the count back
        // would make an untracked call look drain-safe before its inner probe.
        record_go_auto_sdk_rejected_return(goroutine_key);
        poison_go_auto_sdk_inflight(inflight_key);
    }
    return ret;
}

static __always_inline long register_go_auto_sdk_pending_outer_call(
    const go_addr_key_t *goroutine_key, u64 process_start_time, u64 flag_ptr) {
    const go_auto_sdk_inflight_key_t pending_key = go_auto_sdk_pending_inflight_key();
    if (!begin_go_auto_sdk_active_call(&pending_key)) {
        record_go_auto_sdk_rejected_return(goroutine_key);
        poison_go_auto_sdk_inflight(&pending_key);
        return -1;
    }
    if (!goroutine_key || !process_start_time || !flag_ptr) {
        record_go_auto_sdk_rejected_return(goroutine_key);
        poison_go_auto_sdk_inflight(&pending_key);
        return -1;
    }
    const long ret = store_go_auto_sdk_outer_call(goroutine_key,
                                                  process_start_time,
                                                  GO_AUTO_SDK_PENDING_GENERATION,
                                                  GO_AUTO_SDK_PENDING_EPOCH,
                                                  flag_ptr,
                                                  k_go_auto_sdk_outer_pre);
    if (ret) {
        record_go_auto_sdk_rejected_return(goroutine_key);
        poison_go_auto_sdk_inflight(&pending_key);
    }
    return ret;
}

static __always_inline long
register_go_auto_sdk_counted_outer_call(const go_addr_key_t *goroutine_key,
                                        const go_auto_sdk_inflight_key_t *inflight_key,
                                        u64 flag_ptr,
                                        enum go_auto_sdk_outer_state state) {
    return register_go_auto_sdk_counted_outer_call_with_direct(
        goroutine_key, inflight_key, flag_ptr, state, k_go_auto_sdk_direct_entry_none, 0);
}

// A successfully registered capture owns an exact count until its matching
// global NewSpan return. Publication races may only preserve that capture,
// promote it in place, or poison its counter; none may retire the count.
static __always_inline u8
resolve_go_auto_sdk_counted_capture(const go_addr_key_t *goroutine_key,
                                    const go_auto_sdk_outer_call_t *capture,
                                    enum go_auto_sdk_capture_resolution resolution) {
    if (!goroutine_key || !capture || capture->state != k_go_auto_sdk_outer_capture ||
        !capture->flag_ptr || !go_auto_sdk_outer_call_has_no_direct_metadata(capture)) {
        return 0;
    }
    const go_auto_sdk_inflight_key_t key =
        capture->generation == GO_AUTO_SDK_PENDING_GENERATION &&
                capture->auto_sdk_epoch == GO_AUTO_SDK_PENDING_EPOCH
            ? go_auto_sdk_pending_inflight_key()
            : go_auto_sdk_inflight_key(goroutine_key->pid,
                                       capture->generation,
                                       capture->start_time,
                                       capture->auto_sdk_epoch);
    if (resolution == k_go_auto_sdk_capture_poison) {
        poison_go_auto_sdk_inflight(&key);
        return 1;
    }
    if (resolution == k_go_auto_sdk_capture_preserve) {
        return 1;
    }
    if (resolution != k_go_auto_sdk_capture_promote) {
        poison_go_auto_sdk_inflight(&key);
        return 0;
    }
    go_auto_sdk_outer_call_t active = *capture;
    active.state = k_go_auto_sdk_outer_active;
    if (bpf_map_update_elem(&go_auto_sdk_outer_calls, goroutine_key, &active, BPF_EXIST) != 0) {
        poison_go_auto_sdk_inflight(&key);
        return 0;
    }
    return 1;
}

// A pre-readiness handler must reread the readiness gate before returning to
// the userspace flag-load instruction. If the gate appeared, ownership moves
// to the real epoch without any interval in which neither counter is held.
static __always_inline u8
migrate_go_auto_sdk_pending_capture(const go_addr_key_t *goroutine_key,
                                    const go_auto_sdk_outer_call_t *pending,
                                    const go_auto_sdk_inflight_key_t *active_key) {
    if (!goroutine_key || !pending || pending->state != k_go_auto_sdk_outer_pre ||
        pending->generation != GO_AUTO_SDK_PENDING_GENERATION ||
        pending->auto_sdk_epoch != GO_AUTO_SDK_PENDING_EPOCH ||
        pending->start_time != active_key->start_time ||
        !go_auto_sdk_inflight_key_valid(active_key) ||
        go_auto_sdk_is_pending_inflight_key(active_key)) {
        return 0;
    }
    const go_auto_sdk_inflight_key_t pending_key = go_auto_sdk_pending_inflight_key();
    if (!begin_go_auto_sdk_active_call(active_key)) {
        poison_go_auto_sdk_inflight(&pending_key);
        poison_go_auto_sdk_inflight(active_key);
        return 0;
    }
    go_auto_sdk_outer_call_t migrated = *pending;
    migrated.generation = active_key->generation;
    migrated.auto_sdk_epoch = active_key->auto_sdk_epoch;
    migrated.state = k_go_auto_sdk_outer_capture;
    if (bpf_map_update_elem(&go_auto_sdk_outer_calls, goroutine_key, &migrated, BPF_EXIST) != 0) {
        poison_go_auto_sdk_inflight(&pending_key);
        poison_go_auto_sdk_inflight(active_key);
        return 0;
    }
    if (!finish_go_auto_sdk_active_call(&pending_key)) {
        poison_go_auto_sdk_inflight(&pending_key);
        poison_go_auto_sdk_inflight(active_key);
        return 0;
    }
    return 1;
}

static __always_inline long
register_go_auto_sdk_active_outer_call(const go_addr_key_t *goroutine_key,
                                       const go_auto_sdk_inflight_key_t *inflight_key,
                                       u64 flag_ptr) {
    return register_go_auto_sdk_counted_outer_call(
        goroutine_key, inflight_key, flag_ptr, k_go_auto_sdk_outer_active);
}

static __always_inline long
register_go_auto_sdk_direct_outer_call(const go_addr_key_t *goroutine_key,
                                       const go_auto_sdk_inflight_key_t *inflight_key,
                                       enum go_auto_sdk_direct_entry_kind direct_entry_kind) {
    if (direct_entry_kind != k_go_auto_sdk_direct_entry_pointer &&
        direct_entry_kind != k_go_auto_sdk_direct_entry_value) {
        record_go_auto_sdk_rejected_return(goroutine_key);
        return -1;
    }
    return register_go_auto_sdk_counted_outer_call_with_direct(
        goroutine_key, inflight_key, 0, k_go_auto_sdk_outer_direct_active, direct_entry_kind, 1);
}

// A pointer-receiver Start wrapper calls the value-receiver Start symbol in
// supported auto/sdk releases. Both symbols are probed, but they are one
// logical public call and therefore own one exact in-flight count. Only that
// exact pointer-to-value transition can reuse the outer state.
static __always_inline long
nest_go_auto_sdk_direct_value_wrapper(const go_addr_key_t *goroutine_key,
                                      const go_auto_sdk_inflight_key_t *inflight_key) {
    if (!goroutine_key || !go_auto_sdk_inflight_key_valid(inflight_key)) {
        return -1;
    }
    const go_auto_sdk_outer_call_t *stored =
        bpf_map_lookup_elem(&go_auto_sdk_outer_calls, goroutine_key);
    if (!stored || stored->state != k_go_auto_sdk_outer_direct_active || stored->rejected_returns ||
        stored->direct_entry_kind != k_go_auto_sdk_direct_entry_pointer ||
        stored->direct_depth != 1 || stored->start_time != inflight_key->start_time ||
        stored->generation != inflight_key->generation ||
        stored->auto_sdk_epoch != inflight_key->auto_sdk_epoch) {
        return 0;
    }
    go_auto_sdk_outer_call_t nested = *stored;
    nested.direct_entry_kind = k_go_auto_sdk_direct_entry_nested_value;
    nested.direct_depth = 2;
    if (bpf_map_update_elem(&go_auto_sdk_outer_calls, goroutine_key, &nested, BPF_EXIST) != 0) {
        poison_go_auto_sdk_inflight(inflight_key);
        return -1;
    }
    return 1;
}

static __always_inline long
mark_go_auto_sdk_direct_outer_call(const go_addr_key_t *goroutine_key,
                                   const u64 generation,
                                   const u64 start_time,
                                   const u32 auto_sdk_epoch,
                                   enum go_auto_sdk_direct_entry_kind direct_entry_kind) {
    if (!start_time) {
        record_go_auto_sdk_rejected_return(goroutine_key);
        return -1;
    }
    if (!prepare_go_auto_sdk_outer_call_slot(goroutine_key, start_time)) {
        return -1;
    }
    const go_auto_sdk_inflight_key_t inflight_key =
        go_auto_sdk_inflight_key(goroutine_key->pid, generation, start_time, auto_sdk_epoch);
    if (direct_entry_kind == k_go_auto_sdk_direct_entry_value) {
        const long nested = nest_go_auto_sdk_direct_value_wrapper(goroutine_key, &inflight_key);
        if (nested != 0) {
            if (nested < 0) {
                record_go_auto_sdk_rejected_return(goroutine_key);
            }
            return nested > 0 ? 0 : -1;
        }
    }
    return register_go_auto_sdk_direct_outer_call(goroutine_key, &inflight_key, direct_entry_kind);
}

static __always_inline long
unnest_go_auto_sdk_direct_value_wrapper(const go_addr_key_t *goroutine_key,
                                        const go_auto_sdk_inflight_key_t *inflight_key,
                                        const go_auto_sdk_outer_call_t *call) {
    if (!goroutine_key || !go_auto_sdk_inflight_key_valid(inflight_key) || !call ||
        (call->state != k_go_auto_sdk_outer_direct_active &&
         call->state != k_go_auto_sdk_outer_direct_consumed) ||
        call->direct_entry_kind != k_go_auto_sdk_direct_entry_nested_value ||
        call->direct_depth != 2 || call->start_time != inflight_key->start_time ||
        call->generation != inflight_key->generation ||
        call->auto_sdk_epoch != inflight_key->auto_sdk_epoch) {
        return 0;
    }
    go_auto_sdk_outer_call_t outer = *call;
    outer.direct_depth = 1;
    if (bpf_map_update_elem(&go_auto_sdk_outer_calls, goroutine_key, &outer, BPF_EXIST) != 0) {
        poison_go_auto_sdk_inflight(inflight_key);
        return -1;
    }
    return 1;
}

static __always_inline u8 force_go_auto_sdk_unsampled(void *sampled_ptr) {
    bool sampled = false;
    return sampled_ptr && bpf_probe_write_user(sampled_ptr, &sampled, sizeof(sampled)) == 0;
}
