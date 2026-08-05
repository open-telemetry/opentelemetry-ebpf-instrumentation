// Copyright The OpenTelemetry Authors
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation copied from https://github.com/open-telemetry/opentelemetry-go-instrumentation/blob/main/internal/pkg/instrumentation/bpf/go.opentelemetry.io/auto/sdk/bpf/probe.bpf.c
// and has been adapted to OBI.

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/algorithm.h>
#include <common/common.h>
#include <common/globals.h>
#include <common/http_types.h>
#include <common/map_sizing.h>
#include <common/ringbuf.h>
#include <common/scratch_mem.h>

#include <generictracer/k_tracer_tailcall.h>

#include <gotracer/go_common.h>

#include <gotracer/maps/auto_sdk.h>

#include <gotracer/types/otel_types.h>

enum { k_go_interface_type_offset = 8 };
enum { k_go_ptr_arr_size = 16 };
enum { k_go_max_event_opts = 5 };
enum { k_go_max_span_start_opts = 128 };
enum { k_go_span_start_attribute_opts_per_tail = 5 };
enum { k_go_max_span_start_route_attrs = 128 };
enum { k_go_span_start_route_scan_steps_per_tail = 52 };
// These bounds keep user-memory walks verifier-safe. Auto SDK sampling fails
// closed when either bound is exceeded.
enum { k_go_max_span_start_config_opts = 128 };
enum { k_go_max_span_end_opts = 128 };
enum { k_go_max_context_scan_depth = 128 };
enum { k_go_time_nsec_shift = 30 };

static const u64 k_go_time_has_monotonic = 1ULL << 63;
static const u64 k_go_time_nsec_mask = (1ULL << k_go_time_nsec_shift) - 1;
static const s64 k_go_time_wall_to_internal = 59453308800LL;
static const s64 k_go_time_unix_to_internal = 62135596800LL;
static const s64 k_go_time_max_unix_seconds = 9223372036LL;
static const u64 k_go_time_max_unix_nanoseconds = 854775807ULL;

enum go_context_parent_result : s8 {
    k_go_context_parent_error = -1,
    k_go_context_parent_not_found = 0,
    k_go_context_parent_found = 1,
    k_go_context_parent_explicit_root = 2,
};

enum span_trace_parent_result : s8 {
    k_span_trace_parent_error = -1,
    k_span_trace_parent_not_found = 0,
    k_span_trace_parent_ready = 1,
};

const char ERROR_KEY[] = "error message";
const u32 ERROR_KEY_SIZE = sizeof(ERROR_KEY) - 1;

typedef struct span_info {
    span_name_t name;
    u64 opts_ptr;
    u64 opts_len;
    u64 context_data;
    u32 auto_sdk_epoch;
    u8 span_kind;
    u8 new_root;
    u8 unsupported_options;
    u8 global_handoff;
    u8 handoff_failed;
    u8 _pad[7];
} span_info_t;

typedef struct go_time_value {
    u64 wall;
    s64 ext;
} go_time_value_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_process_addr_key_t); // process generation and goroutine
    __type(value, span_info_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} span_names SEC(".maps");

static __always_inline long mark_go_auto_sdk_outer_call(const go_addr_key_t *goroutine_key,
                                                        const u64 generation,
                                                        const u32 auto_sdk_epoch,
                                                        const u64 flag_ptr,
                                                        enum go_auto_sdk_outer_state state) {
    const u64 start_time = current_process_start_time_ns();
    if (!start_time) {
        return -1;
    }
    const go_auto_sdk_inflight_key_t inflight_key =
        go_auto_sdk_inflight_key(goroutine_key->pid, generation, start_time, auto_sdk_epoch);
    if (state == k_go_auto_sdk_outer_capture || state == k_go_auto_sdk_outer_active) {
        return register_go_auto_sdk_counted_outer_call(
            goroutine_key, &inflight_key, flag_ptr, state);
    }
    return store_go_auto_sdk_outer_call(
        goroutine_key, start_time, generation, auto_sdk_epoch, flag_ptr, state);
}

static __always_inline u8
go_auto_sdk_direct_outer_call_valid(const go_auto_sdk_outer_call_t *call) {
    if (!call) {
        return 0;
    }
    return (call->direct_depth == 1 &&
            (call->direct_entry_kind == k_go_auto_sdk_direct_entry_pointer ||
             call->direct_entry_kind == k_go_auto_sdk_direct_entry_value ||
             call->direct_entry_kind == k_go_auto_sdk_direct_entry_nested_value)) ||
           (call->direct_depth == 2 &&
            call->direct_entry_kind == k_go_auto_sdk_direct_entry_nested_value);
}

static __always_inline u8 retire_go_auto_sdk_direct_return(const go_addr_key_t *goroutine_key,
                                                           const go_auto_sdk_outer_call_t *call) {
    if (!call ||
        (call->state != k_go_auto_sdk_outer_direct_active &&
         call->state != k_go_auto_sdk_outer_direct_consumed) ||
        !go_auto_sdk_direct_outer_call_valid(call)) {
        poison_go_auto_sdk_outer_inflight(goroutine_key, call);
        return 0;
    }
    if (call->direct_depth == 1) {
        return retire_go_auto_sdk_outer_call(goroutine_key, call);
    }
    const go_auto_sdk_inflight_key_t inflight_key = go_auto_sdk_inflight_key(
        goroutine_key->pid, call->generation, call->start_time, call->auto_sdk_epoch);
    return unnest_go_auto_sdk_direct_value_wrapper(goroutine_key, &inflight_key, call) > 0;
}

static __always_inline enum go_auto_sdk_handoff_owner
consume_go_auto_sdk_outer_call(const go_addr_key_t *goroutine_key,
                               go_auto_sdk_outer_call_t *call,
                               u64 current_generation,
                               u32 span_auto_sdk_epoch,
                               u8 global_handoff,
                               u8 handoff_failed,
                               u8 capture_activation_committed) {
    const go_auto_sdk_outer_call_t *stored_call =
        bpf_map_lookup_elem(&go_auto_sdk_outer_calls, goroutine_key);
    if (!stored_call) {
        return k_go_auto_sdk_handoff_none;
    }
    const go_auto_sdk_outer_call_t found = *stored_call;
    *call = found;
    if (!process_incarnation_matches_current((u32)goroutine_key->pid, found.start_time)) {
        retire_go_auto_sdk_outer_call(goroutine_key, &found);
        return k_go_auto_sdk_handoff_none;
    }
    return consume_exact_go_auto_sdk_handoff(goroutine_key,
                                             &found,
                                             current_generation,
                                             span_auto_sdk_epoch,
                                             global_handoff,
                                             handoff_failed,
                                             capture_activation_committed,
                                             1);
}

typedef struct go_value_context_signature {
    // context.valueCtx fields are immutable and distinguish a live context from a reused heap
    // address after the original context has been collected.
    u64 parent_type;
    u64 parent_data;
    u64 key_type;
    u64 key_data;
    u64 value_type;
    u64 value_data;
} go_value_context_signature_t;

typedef struct go_auto_context_value {
    tp_info_t tp;
    go_value_context_signature_t signature;
} go_auto_context_value_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_process_addr_key_t); // process generation and context.Context data pointer
    __type(value, go_auto_context_value_t);
    __uint(max_entries, MAX_CONCURRENT_CUSTOM_SPANS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_auto_contexts SEC(".maps");

static __always_inline span_info_t *
lookup_span_info_for_generation(const go_addr_key_t *goroutine_key, const u64 generation) {
    go_process_addr_key_t key = {};
    if (!go_process_addr_key_from_generation(&key, goroutine_key, generation)) {
        return 0;
    }
    return bpf_map_lookup_elem(&span_names, &key);
}

static __always_inline span_info_t *lookup_span_info(const go_addr_key_t *goroutine_key) {
    return lookup_span_info_for_generation(goroutine_key,
                                           go_process_generation(goroutine_key->pid));
}

static __always_inline long update_span_info(const go_addr_key_t *goroutine_key,
                                             const span_info_t *span_info) {
    go_process_addr_key_t key = {};
    if (!go_process_addr_key_from_go_addr(&key, goroutine_key)) {
        return -1;
    }
    return bpf_map_update_elem(&span_names, &key, span_info, BPF_ANY);
}

static __always_inline long delete_span_info(const go_addr_key_t *goroutine_key) {
    go_process_addr_key_t key = {};
    if (!go_process_addr_key_from_go_addr(&key, goroutine_key)) {
        return -1;
    }
    return bpf_map_delete_elem(&span_names, &key);
}

static __always_inline long delete_span_info_for_generation(const go_addr_key_t *goroutine_key,
                                                            const u64 generation) {
    go_process_addr_key_t key = {};
    if (!go_process_addr_key_from_generation(&key, goroutine_key, generation)) {
        return -1;
    }
    return bpf_map_delete_elem(&span_names, &key);
}

static __always_inline void delete_auto_sdk_span_infos(const go_addr_key_t *goroutine_key,
                                                       const u64 outer_generation,
                                                       const u64 current_generation) {
    if (outer_generation) {
        delete_span_info_for_generation(goroutine_key, outer_generation);
    }
    if (current_generation && current_generation != outer_generation) {
        delete_span_info_for_generation(goroutine_key, current_generation);
    }
}

static __always_inline go_auto_context_value_t *
lookup_go_auto_context(const go_addr_key_t *context_key) {
    go_process_addr_key_t key = {};
    if (!go_process_addr_key_from_go_addr(&key, context_key)) {
        return 0;
    }
    return bpf_map_lookup_elem(&go_auto_contexts, &key);
}

static __always_inline long delete_go_auto_context(const go_addr_key_t *context_key) {
    go_process_addr_key_t key = {};
    if (!go_process_addr_key_from_go_addr(&key, context_key)) {
        return -1;
    }
    return bpf_map_delete_elem(&go_auto_contexts, &key);
}

static __always_inline long update_go_auto_context(const go_addr_key_t *context_key,
                                                   const go_auto_context_value_t *value) {
    go_process_addr_key_t key = {};
    if (!go_process_addr_key_from_go_addr(&key, context_key)) {
        return -1;
    }
    return bpf_map_update_elem(&go_auto_contexts, &key, value, BPF_ANY);
}

typedef struct go_auto_sdk_type_info {
    u64 trace_context_key_type;
    u64 non_recording_span_type;
    u64 recording_span_type;
    u64 attribute_option_type;
    u64 timestamp_option_type;
    u64 non_recording_span_context_pos;
    u64 recording_span_context_pos;
    u64 span_context_trace_id_pos;
    u64 span_context_span_id_pos;
    u64 span_context_trace_flags_pos;
    u64 span_context_remote_pos;
} go_auto_sdk_type_info_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, go_process_key_t);
    __type(value, go_auto_sdk_type_info_t);
    __uint(max_entries, k_max_concurrent_pids);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_auto_sdk_type_infos SEC(".maps");

typedef struct go_auto_sdk_flag {
    u64 flag_ptr;
    u64 start_time;
    u32 epoch;
    u8 activated;
    u8 _pad[3];
} go_auto_sdk_flag_t;

enum go_auto_sdk_flag_state : u8 {
    k_go_auto_sdk_flag_captured = 0,
    k_go_auto_sdk_flag_active = 1,
    k_go_auto_sdk_flag_quiescing = 2,
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, go_process_key_t);
    __type(value, go_auto_sdk_flag_t);
    __uint(max_entries, k_max_concurrent_pids);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_auto_sdk_flags SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_auto_sdk_flag_events SEC(".maps");

static __always_inline u8 go_auto_sdk_process_quiescing(const u32 host_pid,
                                                        const u64 generation,
                                                        const u32 auto_sdk_epoch) {
    const go_process_key_t process_key = {
        .pid = host_pid,
        .generation = generation,
    };
    const go_auto_sdk_flag_t *flag = bpf_map_lookup_elem(&go_auto_sdk_flags, &process_key);
    return flag && flag->activated == k_go_auto_sdk_flag_quiescing &&
           flag->start_time == current_process_start_time_ns() && flag->epoch == auto_sdk_epoch;
}

static __always_inline u8 promote_go_auto_sdk_capture_to_active(
    const go_addr_key_t *goroutine_key, const go_auto_sdk_outer_call_t *capture) {
    const go_process_key_t process_key = {
        .pid = goroutine_key->pid,
        .generation = capture->generation,
    };
    const go_auto_sdk_flag_t *published = bpf_map_lookup_elem(&go_auto_sdk_flags, &process_key);
    if (!published) {
        return 0;
    }
    const go_auto_sdk_flag_t snapshot = *published;
    if (snapshot.activated != k_go_auto_sdk_flag_active || snapshot.flag_ptr != capture->flag_ptr ||
        snapshot.start_time != capture->start_time || snapshot.epoch != capture->auto_sdk_epoch) {
        return 0;
    }
    return resolve_go_auto_sdk_counted_capture(
        goroutine_key, capture, k_go_auto_sdk_capture_promote);
}

static __always_inline enum go_auto_sdk_capture_resolution
go_auto_sdk_capture_publication_resolution(const go_auto_sdk_outer_call_t *capture,
                                           const go_auto_sdk_flag_t *published) {
    if (!capture || !published || published->flag_ptr != capture->flag_ptr ||
        published->start_time != capture->start_time ||
        published->epoch != capture->auto_sdk_epoch) {
        return k_go_auto_sdk_capture_poison;
    }
    if (published->activated == k_go_auto_sdk_flag_active) {
        return k_go_auto_sdk_capture_promote;
    }
    if (published->activated == k_go_auto_sdk_flag_captured ||
        published->activated == k_go_auto_sdk_flag_quiescing) {
        return k_go_auto_sdk_capture_preserve;
    }
    return k_go_auto_sdk_capture_poison;
}

static __always_inline enum go_auto_sdk_capture_resolution
resolve_go_auto_sdk_capture_publication(const go_addr_key_t *goroutine_key,
                                        const go_auto_sdk_outer_call_t *capture,
                                        const go_auto_sdk_flag_t *published) {
    const enum go_auto_sdk_capture_resolution resolution =
        go_auto_sdk_capture_publication_resolution(capture, published);
    resolve_go_auto_sdk_counted_capture(goroutine_key, capture, resolution);
    return resolution;
}

static __always_inline u8
go_auto_sdk_capture_activation_committed(const go_addr_key_t *goroutine_key) {
    const go_auto_sdk_outer_call_t *stored =
        bpf_map_lookup_elem(&go_auto_sdk_outer_calls, goroutine_key);
    if (!stored || stored->state != k_go_auto_sdk_outer_capture || !stored->flag_ptr ||
        !go_auto_sdk_outer_call_has_no_direct_metadata(stored)) {
        return 0;
    }
    const go_auto_sdk_outer_call_t capture = *stored;
    const go_process_key_t process_key = {
        .pid = goroutine_key->pid,
        .generation = capture.generation,
    };
    const go_auto_sdk_flag_t *published = bpf_map_lookup_elem(&go_auto_sdk_flags, &process_key);
    if (!published) {
        return 0;
    }
    const go_auto_sdk_flag_t snapshot = *published;
    return (snapshot.activated == k_go_auto_sdk_flag_active ||
            snapshot.activated == k_go_auto_sdk_flag_quiescing) &&
           snapshot.flag_ptr == capture.flag_ptr && snapshot.start_time == capture.start_time &&
           snapshot.epoch == capture.auto_sdk_epoch;
}

typedef struct go_span_option_function_key {
    u64 host_pid;
    u64 generation;
    u64 function;
} go_span_option_function_key_t;

enum {
    k_go_span_option_kind = 1,
    k_go_span_option_new_root = 2,
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, go_span_option_function_key_t);
    __type(value, u8);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_span_option_functions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, otel_span_t);
    __uint(max_entries, 2);
} span_mem SEC(".maps");

typedef struct go_auto_span_buffer {
    u8 type;
    u8 parent_remote;
    u8 _pad[2];
    u32 size;
    pid_info pid;
    unsigned char buf[k_go_auto_span_json_max_len];
} go_auto_span_buffer_t;

_Static_assert(__builtin_offsetof(go_auto_span_buffer_t, parent_remote) == 1,
               "Go Auto SDK parent remoteness ABI changed");
_Static_assert(__builtin_offsetof(go_auto_span_buffer_t, buf) ==
                   __builtin_offsetof(go_auto_span_t, buf),
               "Go Auto SDK event header ABI changed");

SCRATCH_MEM_TYPED(go_auto_span, go_auto_span_buffer_t);

static __always_inline otel_span_t *span_zero_memory() {
    const u32 zero = 0;
    return bpf_map_lookup_elem(&span_mem, &zero);
}

static __always_inline otel_span_t *span_memory() {
    const u32 one = 1;
    return bpf_map_lookup_elem(&span_mem, &one);
}

static __always_inline otel_span_t *zero_initialised_span() {
    otel_span_t *zero_span = span_zero_memory();

    if (!zero_span) {
        return 0;
    }

    const u32 one = 1;
    bpf_map_update_elem(&span_mem, &one, zero_span, BPF_ANY);

    return span_memory();
}

static __always_inline void
read_span_name(unsigned char *buf, const u64 span_name_len, void *span_name_ptr) {
    const u64 span_name_size = min(k_max_span_name_len, span_name_len);
    bpf_probe_read_user(buf, span_name_size, span_name_ptr);
}

static __always_inline u8 read_go_time_unix_nano(void *time_ptr, u64 *timestamp) {
    if (!time_ptr || !timestamp) {
        return 0;
    }

    go_time_value_t value = {};
    if (bpf_probe_read_user(&value, sizeof(value), time_ptr) != 0) {
        return 0;
    }

    s64 seconds = value.ext;
    if (value.wall & k_go_time_has_monotonic) {
        seconds =
            k_go_time_wall_to_internal + (s64)((value.wall << 1) >> (k_go_time_nsec_shift + 1));
    }
    if (seconds < k_go_time_unix_to_internal) {
        return 0;
    }

    const s64 unix_seconds = seconds - k_go_time_unix_to_internal;
    const u64 nanoseconds = value.wall & k_go_time_nsec_mask;
    if (unix_seconds > k_go_time_max_unix_seconds ||
        (unix_seconds == k_go_time_max_unix_seconds &&
         nanoseconds > k_go_time_max_unix_nanoseconds)) {
        return 0;
    }

    *timestamp = (u64)unix_seconds * 1000000000ULL + nanoseconds;
    return 1;
}

static __noinline void read_span_start_options(span_info_t *span_info) {
    void *opts_ptr = (void *)span_info->opts_ptr;
    u64 len = span_info->opts_len;
    if (len > k_go_max_span_start_config_opts) {
        span_info->unsupported_options = 1;
        return;
    }
    bpf_clamp_umax(len, k_go_max_span_start_config_opts);
#pragma clang loop unroll(disable)
    for (int i = 0; i < k_go_max_span_start_config_opts; i++) {
        if (i >= len) {
            break;
        }

        void *option = 0;
        bpf_probe_read_user(
            &option, sizeof(option), opts_ptr + (i * k_go_ptr_arr_size) + sizeof(void *));
        if (!option) {
            continue;
        }

        u64 function = 0;
        bpf_probe_read_user(&function, sizeof(function), option);
        const u64 host_pid = bpf_get_current_pid_tgid() >> 32;
        const u64 generation = go_process_generation(host_pid);
        if (!generation) {
            span_info->unsupported_options = 1;
            return;
        }
        go_span_option_function_key_t function_key = {
            .host_pid = host_pid,
            .generation = generation,
            .function = function,
        };
        const u8 *option_type = bpf_map_lookup_elem(&go_span_option_functions, &function_key);
        if (!option_type) {
            continue;
        }
        if (*option_type == k_go_span_option_new_root) {
            span_info->new_root = 1;
            continue;
        }
        if (*option_type != k_go_span_option_kind) {
            continue;
        }

        span_info->span_kind = k_otel_span_kind_internal;
        s64 span_kind = 0;
        bpf_probe_read_user(&span_kind, sizeof(span_kind), option + sizeof(void *));
        if (span_kind >= k_otel_span_kind_internal && span_kind <= k_otel_span_kind_consumer) {
            span_info->span_kind = (u8)span_kind;
        }
    }
}

static __always_inline u8 span_context_offsets_available() {
    off_table_t *ot = get_offsets_table();
    if (!ot) {
        return 0;
    }

    const u64 span_id_pos = go_offset_of(ot, (go_offset){.v = _span_context_span_id_pos});
    const u64 flags_pos = go_offset_of(ot, (go_offset){.v = _span_context_trace_flags_pos});
    return span_id_pos && flags_pos;
}

static __always_inline long
write_go_span_context(void *go_sc, const tp_info_t *tp, const unsigned char *span_id) {
    if (!g_bpf_header_propagation || !go_sc || !tp || !span_id) {
        return -1;
    }

    off_table_t *ot = get_offsets_table();
    if (!ot) {
        return -2;
    }

    const u64 trace_id_pos = go_offset_of(ot, (go_offset){.v = _span_context_trace_id_pos});
    const u64 span_id_pos = go_offset_of(ot, (go_offset){.v = _span_context_span_id_pos});
    const u64 flags_pos = go_offset_of(ot, (go_offset){.v = _span_context_trace_flags_pos});
    if (!span_id_pos || !flags_pos) {
        return -3;
    }

    long ret =
        bpf_probe_write_user((void *)(go_sc + trace_id_pos), tp->trace_id, TRACE_ID_SIZE_BYTES);
    if (ret != 0) {
        return ret;
    }
    ret = bpf_probe_write_user((void *)(go_sc + span_id_pos), span_id, SPAN_ID_SIZE_BYTES);
    if (ret != 0) {
        return ret;
    }
    return bpf_probe_write_user((void *)(go_sc + flags_pos), &tp->flags, sizeof(tp->flags));
}

static __always_inline u8 fail_closed_go_span_context(void *go_sc) {
    if (!go_sc) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();
    if (!ot) {
        return 0;
    }

    const u64 trace_id_pos = go_offset_of(ot, (go_offset){.v = _span_context_trace_id_pos});
    const u64 span_id_pos = go_offset_of(ot, (go_offset){.v = _span_context_span_id_pos});
    const u64 flags_pos = go_offset_of(ot, (go_offset){.v = _span_context_trace_flags_pos});
    if (!span_id_pos || !flags_pos) {
        return 0;
    }

    const u8 flags = 0;
    if (bpf_probe_write_user((void *)(go_sc + flags_pos), &flags, sizeof(flags)) == 0) {
        return 1;
    }

    const unsigned char empty_trace_id[TRACE_ID_SIZE_BYTES] = {};
    if (bpf_probe_write_user(
            (void *)(go_sc + trace_id_pos), empty_trace_id, sizeof(empty_trace_id)) == 0) {
        return 1;
    }

    const unsigned char empty_span_id[SPAN_ID_SIZE_BYTES] = {};
    return bpf_probe_write_user(
               (void *)(go_sc + span_id_pos), empty_span_id, sizeof(empty_span_id)) == 0;
}

static __always_inline long
write_unsampled_go_span_context(void *go_sc, const tp_info_t *tp, const unsigned char *span_id) {
    if (!g_bpf_header_propagation || !go_sc || !tp || !span_id) {
        return -1;
    }

    off_table_t *ot = get_offsets_table();
    if (!ot) {
        return -2;
    }

    const u64 trace_id_pos = go_offset_of(ot, (go_offset){.v = _span_context_trace_id_pos});
    const u64 span_id_pos = go_offset_of(ot, (go_offset){.v = _span_context_span_id_pos});
    const u64 flags_pos = go_offset_of(ot, (go_offset){.v = _span_context_trace_flags_pos});
    if (!span_id_pos || !flags_pos) {
        return -3;
    }

    const u8 flags = tp->flags & ~k_flag_sampled;
    long ret = bpf_probe_write_user((void *)(go_sc + flags_pos), &flags, sizeof(flags));
    if (ret == 0) {
        ret =
            bpf_probe_write_user((void *)(go_sc + trace_id_pos), tp->trace_id, TRACE_ID_SIZE_BYTES);
    }
    if (ret == 0) {
        ret = bpf_probe_write_user((void *)(go_sc + span_id_pos), span_id, SPAN_ID_SIZE_BYTES);
    }
    if (ret != 0) {
        fail_closed_go_span_context(go_sc);
    }
    return ret;
}

static __always_inline u8 same_value_context(const go_value_context_signature_t *left,
                                             const go_value_context_signature_t *right) {
    return left->parent_type == right->parent_type && left->parent_data == right->parent_data &&
           left->key_type == right->key_type && left->key_data == right->key_data &&
           left->value_type == right->value_type && left->value_data == right->value_data;
}

static __always_inline const go_auto_sdk_type_info_t *go_auto_sdk_type_info() {
    const u64 host_pid = bpf_get_current_pid_tgid() >> 32;
    go_process_key_t key = {};
    if (!go_process_key_from_pid(&key, host_pid)) {
        return 0;
    }
    return bpf_map_lookup_elem(&go_auto_sdk_type_infos, &key);
}

static __always_inline s8 external_trace_parent(const go_value_context_signature_t *signature,
                                                const go_auto_sdk_type_info_t *type_info,
                                                tp_info_t *parent,
                                                u8 *parent_remote) {
    if (!signature || !type_info || !signature->key_data || !signature->value_data ||
        signature->key_type != type_info->trace_context_key_type) {
        return k_go_context_parent_not_found;
    }

    u64 context_key = 1;
    if (bpf_probe_read_user(&context_key, sizeof(context_key), (void *)signature->key_data) != 0) {
        return k_go_context_parent_error;
    }
    if (context_key != 0) {
        return k_go_context_parent_not_found;
    }
    u64 span_context_pos = 0;
    if (type_info->non_recording_span_type &&
        signature->value_type == type_info->non_recording_span_type) {
        span_context_pos = type_info->non_recording_span_context_pos;
    } else if (type_info->recording_span_type &&
               signature->value_type == type_info->recording_span_type) {
        span_context_pos = type_info->recording_span_context_pos;
    } else {
        return k_go_context_parent_error;
    }

    void *span_context = (void *)(signature->value_data + span_context_pos);
    if (bpf_probe_read_user(parent->trace_id,
                            sizeof(parent->trace_id),
                            span_context + type_info->span_context_trace_id_pos) != 0 ||
        bpf_probe_read_user(parent->span_id,
                            sizeof(parent->span_id),
                            span_context + type_info->span_context_span_id_pos) != 0 ||
        bpf_probe_read_user(&parent->flags,
                            sizeof(parent->flags),
                            span_context + type_info->span_context_trace_flags_pos) != 0 ||
        bpf_probe_read_user(parent_remote,
                            sizeof(*parent_remote),
                            span_context + type_info->span_context_remote_pos) != 0) {
        return k_go_context_parent_error;
    }

    if (!valid_trace(parent->trace_id) || !valid_span(parent->span_id)) {
        return k_go_context_parent_explicit_root;
    }

    return k_go_context_parent_found;
}

static __noinline s8 trace_parent_from_context(void *context_data,
                                               tp_info_t *parent,
                                               u8 *parent_remote) {
    go_addr_key_t context_key = {};
    const go_auto_sdk_type_info_t *type_info = go_auto_sdk_type_info();

#pragma clang loop unroll(disable)
    for (int i = 0; i < k_go_max_context_scan_depth; i++) {
        if (!context_data) {
            return k_go_context_parent_not_found;
        }

        go_value_context_signature_t signature = {};
        const long signature_result =
            bpf_probe_read_user(&signature, sizeof(signature), context_data);
        go_addr_key_from_id(&context_key, context_data);
        go_auto_context_value_t *value = lookup_go_auto_context(&context_key);
        if (value) {
            go_auto_context_value_t candidate = {};
            __builtin_memcpy(&candidate, value, sizeof(candidate));
            if (signature_result == 0 && same_value_context(&signature, &candidate.signature)) {
                __builtin_memcpy(parent, &candidate.tp, sizeof(*parent));
                *parent_remote = 0;
                return k_go_context_parent_found;
            }
            delete_go_auto_context(&context_key);
        }

        if (signature_result != 0) {
            return type_info ? k_go_context_parent_error : k_go_context_parent_not_found;
        }
        if (!signature.parent_type) {
            return k_go_context_parent_not_found;
        }
        if (type_info) {
            const s8 external_result =
                external_trace_parent(&signature, type_info, parent, parent_remote);
            if (external_result != k_go_context_parent_not_found) {
                return external_result;
            }
        }

        void *parent_data = (void *)signature.parent_data;
        if (!parent_data || parent_data == context_data) {
            return k_go_context_parent_not_found;
        }
        context_data = parent_data;
    }

    return type_info ? k_go_context_parent_error : k_go_context_parent_not_found;
}

static __always_inline u8 init_root_trace_parent(tp_info_t *tp, u8 require_sampler) {
    __builtin_memset(tp, 0, sizeof(*tp));
    tp->flags = k_flag_sampled;
    new_trace_id(tp);
    urand_bytes(tp->span_id, SPAN_ID_SIZE_BYTES);
    tp->ts = bpf_ktime_get_ns();
    if (require_sampler) {
        return apply_required_sampling_decision(tp, 0, 0);
    }
    return apply_sampling_decision(tp, 0, 0);
}

static __always_inline s8 init_span_trace_parent(otel_span_t *span,
                                                 go_addr_key_t *g_key,
                                                 void *context_data,
                                                 u8 new_root,
                                                 u8 allow_root,
                                                 u8 require_sampler) {
    tp_info_t parent = {};
    u8 found_parent = 0;
    u8 parent_remote = 0;
    if (!new_root) {
        const s8 context_result = trace_parent_from_context(context_data, &parent, &parent_remote);
        if (context_result == k_go_context_parent_error) {
            return k_span_trace_parent_error;
        }
        found_parent = context_result == k_go_context_parent_found;
        if (context_result == k_go_context_parent_not_found) {
            tp_info_t go_parent = {};
            const s8 go_parent_result = tp_info_from_parent_go(g_key, 0, &go_parent);
            if (go_parent_result == k_go_trace_parent_error) {
                return k_span_trace_parent_error;
            }
            if (go_parent_result == k_go_trace_parent_found) {
                __builtin_memcpy(&parent, &go_parent, sizeof(parent));
                found_parent = 1;
            }
        }
    }

    if (found_parent) {
        __builtin_memcpy(&span->prev_tp, &parent, sizeof(tp_info_t));
        tp_from_parent(&span->tp, &parent);
    } else if (allow_root) {
        if (!init_root_trace_parent(&span->tp, require_sampler)) {
            return k_span_trace_parent_not_found;
        }
        return k_span_trace_parent_ready;
    } else {
        return k_span_trace_parent_not_found;
    }

    urand_bytes(span->tp.span_id, SPAN_ID_SIZE_BYTES);
    span->tp.ts = bpf_ktime_get_ns();
    const u8 sampler_ready =
        require_sampler ? apply_required_sampling_decision(&span->tp, found_parent, parent_remote)
                        : apply_sampling_decision(&span->tp, found_parent, parent_remote);
    if (!sampler_ready && allow_root) {
        return k_span_trace_parent_not_found;
    }

    return k_span_trace_parent_ready;
}

static __always_inline u8 publish_span_trace_parent(const otel_span_t *span,
                                                    const go_addr_key_t *g_key,
                                                    const go_addr_key_t *s_key) {
    return publish_go_trace_owner(g_key, &span->tp, s_key->addr) == 0;
}

static __always_inline long track_span_context(const otel_span_t *span, void *context_data) {
    if (!context_data) {
        return -1;
    }

    go_addr_key_t context_key = {};
    go_addr_key_from_id(&context_key, context_data);
    go_auto_context_value_t value = {};
    if (bpf_probe_read_user(&value.signature, sizeof(value.signature), context_data) != 0) {
        return -2;
    }
    __builtin_memcpy(&value.tp, &span->tp, sizeof(value.tp));
    return update_go_auto_context(&context_key, &value);
}

typedef struct tracer_start_args {
    void *tracer;
    void *context_data;
    void *name;
    u64 name_len;
    void *options;
    u64 options_len;
} tracer_start_args_t;

static __always_inline void pointer_tracer_start_args(struct pt_regs *ctx,
                                                      tracer_start_args_t *args) {
    args->tracer = GO_PARAM1(ctx);
    args->context_data = GO_PARAM3(ctx);
    args->name = GO_PARAM4(ctx);
    args->name_len = (u64)GO_PARAM5(ctx);
    args->options = GO_PARAM6(ctx);
    args->options_len = (u64)GO_PARAM7(ctx);
}

static __always_inline u8 value_tracer_start_args(struct pt_regs *ctx, tracer_start_args_t *args) {
#if defined(__TARGET_ARCH_x86)
    const void *sp = (const void *)PT_REGS_SP(ctx);
    u64 stack_args[7] = {};
    if (bpf_probe_read_user(&stack_args, sizeof(stack_args), sp + sizeof(void *)) != 0) {
        return 0;
    }
    args->context_data = (void *)stack_args[1];
    args->name = (void *)stack_args[2];
    args->name_len = stack_args[3];
    args->options = (void *)stack_args[4];
    args->options_len = stack_args[5];
#elif defined(__TARGET_ARCH_arm64)
    PT_REGS_ARM64 *regs = (PT_REGS_ARM64 *)ctx;
    args->context_data = (void *)regs->regs[9];
    args->name = (void *)regs->regs[10];
    args->name_len = regs->regs[11];
    args->options = (void *)regs->regs[12];
    args->options_len = regs->regs[13];
#else
    return 0;
#endif
    return 1;
}

static __always_inline int tracer_start(struct pt_regs *ctx,
                                        const tracer_start_args_t *args,
                                        u8 check_delegate,
                                        u8 global_handoff,
                                        u8 args_valid,
                                        enum go_auto_sdk_direct_entry_kind direct_entry_kind) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    if (check_delegate) {
        off_table_t *ot = get_offsets_table();

        void *delegate_ptr = NULL;
        bpf_probe_read_user(
            &delegate_ptr,
            sizeof(delegate_ptr),
            (void *)(args->tracer + go_offset_of(ot, (go_offset){.v = _tracer_delegate_pos})));
        if (delegate_ptr != NULL) {
            // Delegate is set, so we should not instrument this call
            return 0;
        }
    }
    const u32 auto_sdk_epoch =
        global_handoff ? go_auto_sdk_global_activation_epoch() : go_auto_sdk_activation_epoch();
    const u64 generation = global_handoff ? 0 : go_process_generation(g_key.pid);
    const u64 start_time = global_handoff ? 0 : current_process_start_time_ns();
    if (!global_handoff) {
        const span_info_t *existing = lookup_span_info(&g_key);
        if (existing && existing->global_handoff) {
            const go_auto_sdk_outer_call_t *stored =
                bpf_map_lookup_elem(&go_auto_sdk_outer_calls, &g_key);
            if (stored) {
                const go_auto_sdk_outer_call_t outer = *stored;
                const go_auto_sdk_inflight_key_t owner_key = go_auto_sdk_inflight_key(
                    g_key.pid, generation, start_time, existing->auto_sdk_epoch);
                if (go_auto_sdk_outer_call_is_exact_counted_global(&outer, &owner_key)) {
                    return 0;
                }
                const u8 exact_capture = outer.state == k_go_auto_sdk_outer_capture &&
                                         go_auto_sdk_outer_call_is_global(&outer) &&
                                         outer.flag_ptr && outer.start_time == start_time &&
                                         outer.generation == generation &&
                                         outer.auto_sdk_epoch == existing->auto_sdk_epoch;
                if (exact_capture) {
                    // CAPTURE owns the same exact count from NewSpan entry.
                    // Promote it in place when activation won the race; if
                    // activation is already quiescing, preserve it for the
                    // owning global return and its counter retirement.
                    promote_go_auto_sdk_capture_to_active(&g_key, &outer);
                    return 0;
                }
            }
        }
    }
    u8 handoff_failed = !args_valid;
    if (!global_handoff) {
        if (mark_go_auto_sdk_direct_outer_call(
                &g_key, generation, start_time, auto_sdk_epoch, direct_entry_kind) != 0) {
            handoff_failed = 1;
        }
    }
    span_info_t span_info = {
        .auto_sdk_epoch = auto_sdk_epoch,
        .span_kind = k_otel_span_kind_internal,
        .global_handoff = global_handoff,
        .handoff_failed = handoff_failed,
    };

    // Getting span name
    read_span_name(span_info.name.buf, args->name_len, args->name);

    span_info.opts_ptr = (u64)args->options;
    span_info.opts_len = args->options_len;
    span_info.context_data = (u64)args->context_data;
    if (span_info.opts_ptr && span_info.opts_len) {
        read_span_start_options(&span_info);
    }
    const u32 current_auto_sdk_epoch =
        global_handoff ? go_auto_sdk_global_activation_epoch() : go_auto_sdk_activation_epoch();
    if (!auto_sdk_epoch || current_auto_sdk_epoch != auto_sdk_epoch ||
        (!global_handoff && (go_process_generation(g_key.pid) != generation ||
                             current_process_start_time_ns() != start_time))) {
        span_info.auto_sdk_epoch = 0;
        if (!global_handoff) {
            span_info.handoff_failed = 1;
        }
    }

    bpf_dbg_printk("span_info.name.buf=[%s]", span_info.name.buf);

    if (update_span_info(&g_key, &span_info) != 0) {
        poison_go_trace(&g_key);
    }
    return 0;
}

SEC("uprobe/tracer_Start")
int obi_uprobe_tracer_Start(struct pt_regs *ctx) {
    tracer_start_args_t args = {};
    pointer_tracer_start_args(ctx, &args);
    return tracer_start(ctx, &args, 0, 0, 1, k_go_auto_sdk_direct_entry_pointer);
}

SEC("uprobe/tracer_Start_value")
int obi_uprobe_tracer_Start_Value(struct pt_regs *ctx) {
    tracer_start_args_t args = {};
    const u8 args_valid = value_tracer_start_args(ctx, &args);
    return tracer_start(ctx, &args, 0, 0, args_valid, k_go_auto_sdk_direct_entry_value);
}

SEC("uprobe/tracer_Start_global")
int obi_uprobe_tracer_Start_global(struct pt_regs *ctx) {
    tracer_start_args_t args = {};
    pointer_tracer_start_args(ctx, &args);
    return tracer_start(ctx, &args, 1, 1, 1, k_go_auto_sdk_direct_entry_none);
}

SEC("uprobe/tracer_new_span")
int obi_uprobe_tracer_NewSpan(struct pt_regs *ctx) {
    void *flag_ptr = GO_PARAM4(ctx);
    const u32 host_pid = bpf_get_current_pid_tgid() >> 32;
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, GOROUTINE_PTR(ctx));
    const u64 start_time = current_process_start_time_ns();
    if (!prepare_go_auto_sdk_outer_call_slot(&g_key, start_time)) {
        return 0;
    }
    // The uprobe is placed immediately before the process-global bool load.
    // Acquire the global pre-admission latch before observing readiness or
    // generation. Activation cannot write true while a handler that may have
    // observed the old readiness state still owns this count.
    const long pending_ret =
        register_go_auto_sdk_pending_outer_call(&g_key, start_time, (u64)flag_ptr);

    // These snapshots must remain after the PRE acquisition. A handler paused
    // before acquisition can therefore only resume by either seeing the newly
    // published readiness and migrating to its exact counter, or poisoning the
    // global latch before returning to the userspace load.
    const u32 auto_sdk_epoch = go_auto_sdk_global_activation_epoch();
    const u64 generation = go_process_generation(host_pid);
    const u64 gated_start_time = current_process_start_time_ns();
    span_info_t *span_info = generation ? lookup_span_info_for_generation(&g_key, generation) : 0;
    if (pending_ret != 0) {
        if (span_info) {
            span_info->auto_sdk_epoch = 0;
            span_info->handoff_failed = 1;
        }
        return 0;
    }

    go_auto_sdk_outer_call_t capture = {
        .start_time = start_time,
        .generation = GO_AUTO_SDK_PENDING_GENERATION,
        .flag_ptr = (u64)flag_ptr,
        .auto_sdk_epoch = GO_AUTO_SDK_PENDING_EPOCH,
        .state = k_go_auto_sdk_outer_pre,
    };

    // Without readiness the process-global bool is still false. Preserve PRE
    // through the owning return so activation must wait for this load to
    // complete before it can write true.
    if (!auto_sdk_epoch) {
        if (span_info) {
            span_info->auto_sdk_epoch = 0;
            span_info->handoff_failed = 1;
        }
        return 0;
    }

    const go_auto_sdk_inflight_key_t active_key =
        go_auto_sdk_inflight_key(host_pid, generation, gated_start_time, auto_sdk_epoch);
    if (!generation || gated_start_time != start_time ||
        !migrate_go_auto_sdk_pending_capture(&g_key, &capture, &active_key)) {
        poison_go_auto_sdk_outer_inflight(&g_key, &capture);
        if (span_info) {
            span_info->auto_sdk_epoch = 0;
            span_info->handoff_failed = 1;
        }
        return 0;
    }
    capture.generation = generation;
    capture.auto_sdk_epoch = auto_sdk_epoch;
    capture.state = k_go_auto_sdk_outer_capture;

    const u8 enabled = g_bpf_header_propagation && span_context_offsets_available() && span_info &&
                       span_info->global_handoff && !span_info->handoff_failed &&
                       span_info->auto_sdk_epoch == auto_sdk_epoch;
    if (!enabled && span_info) {
        span_info->auto_sdk_epoch = 0;
        span_info->handoff_failed = 1;
    }

    // From this point until this invocation's NewSpan return, the capture owns
    // one exact count. Re-read publication after registration: activation or
    // a competing discovery may have changed the flag since the entry
    // snapshot. Every resolution preserves the count in place.
    const go_process_key_t publication_key = {
        .pid = host_pid,
        .generation = generation,
    };
    const go_auto_sdk_flag_t *published = bpf_map_lookup_elem(&go_auto_sdk_flags, &publication_key);
    if (published) {
        const go_auto_sdk_flag_t post_mark_snapshot = *published;
        if (resolve_go_auto_sdk_capture_publication(&g_key, &capture, &post_mark_snapshot) ==
                k_go_auto_sdk_capture_poison &&
            span_info) {
            span_info->auto_sdk_epoch = 0;
            span_info->handoff_failed = 1;
        }
        return 0;
    }
    if (!enabled) {
        return 0;
    }

    const go_auto_sdk_flag_t flag = {
        .flag_ptr = (u64)flag_ptr,
        .start_time = start_time,
        .epoch = auto_sdk_epoch,
    };
    const long update_ret =
        start_time ? bpf_map_update_elem(&go_auto_sdk_flags, &publication_key, &flag, BPF_NOEXIST)
                   : -1;
    if (update_ret != 0) {
        published = bpf_map_lookup_elem(&go_auto_sdk_flags, &publication_key);
        if (published) {
            const go_auto_sdk_flag_t conflict_snapshot = *published;
            if (resolve_go_auto_sdk_capture_publication(&g_key, &capture, &conflict_snapshot) ==
                k_go_auto_sdk_capture_poison) {
                span_info = lookup_span_info_for_generation(&g_key, generation);
                if (span_info) {
                    span_info->auto_sdk_epoch = 0;
                    span_info->handoff_failed = 1;
                }
            }
        } else {
            resolve_go_auto_sdk_counted_capture(&g_key, &capture, k_go_auto_sdk_capture_poison);
            span_info = lookup_span_info_for_generation(&g_key, generation);
            if (span_info) {
                span_info->auto_sdk_epoch = 0;
                span_info->handoff_failed = 1;
            }
        }
        bpf_dbg_printk("failed to capture Go OTel auto span flag: update=%ld", update_ret);
    }
    return 0;
}

SEC("uprobe/tracer_new_span_return")
int obi_uprobe_tracer_NewSpan_Return(struct pt_regs *ctx) {
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, GOROUTINE_PTR(ctx));
    if (consume_go_auto_sdk_rejected_return(&g_key)) {
        return 0;
    }
    const go_auto_sdk_outer_call_t *stored_call =
        bpf_map_lookup_elem(&go_auto_sdk_outer_calls, &g_key);
    if (!stored_call) {
        return 0;
    }
    const go_auto_sdk_outer_call_t call = *stored_call;
    if (call.state != k_go_auto_sdk_outer_pre && call.state != k_go_auto_sdk_outer_capture &&
        call.state != k_go_auto_sdk_outer_active &&
        call.state != k_go_auto_sdk_outer_consumed_active) {
        return 0;
    }
    if (!retire_go_auto_sdk_outer_call(&g_key, &call)) {
        return 0;
    }
    if (call.state != k_go_auto_sdk_outer_capture || !call.flag_ptr ||
        !process_incarnation_matches_current((u32)g_key.pid, call.start_time) ||
        go_process_generation((u32)g_key.pid) != call.generation ||
        go_auto_sdk_global_activation_epoch() != call.auto_sdk_epoch) {
        return 0;
    }

    go_process_key_t process_key = {
        .pid = g_key.pid,
        .generation = call.generation,
    };
    const go_auto_sdk_flag_t *published = bpf_map_lookup_elem(&go_auto_sdk_flags, &process_key);
    if (!published || published->activated != k_go_auto_sdk_flag_captured ||
        published->flag_ptr != call.flag_ptr || published->start_time != call.start_time ||
        published->epoch != call.auto_sdk_epoch) {
        return 0;
    }
    if (bpf_ringbuf_output(
            &go_auto_sdk_flag_events, &process_key, sizeof(process_key), BPF_RB_FORCE_WAKEUP) !=
        0) {
        bpf_dbg_printk("failed to publish Go OTel auto span flag discovery");
    }
    return 0;
}

typedef struct go_span_start_tail_state {
    go_addr_key_t span_key;
    go_addr_key_t goroutine_key;
    u64 context_data;
    u64 opts_ptr;
    u64 attribute_option_type;
    u64 timestamp_option_type;
    u64 route_attrs_buf;
    u8 opts_len;
    u8 attribute_opts_len;
    u8 next_attribute_opt;
    u8 publish_parent;
    u8 route_attribute_opt_pos;
    u8 route_attr_pos;
    u8 route_attrs_scanned;
    u8 special_attrs_found;
    u8 attribute_opts[k_go_max_span_start_opts];
} go_span_start_tail_state_t;

SCRATCH_MEM_TYPED(go_span_start_tail, go_span_start_tail_state_t);

typedef struct go_span_set_attributes_state {
    go_addr_key_t span_key;
    u64 attrs_buf;
    u64 attrs_len;
    u8 attr_pos;
    u8 special_attrs_found;
    u8 _pad[6];
} go_span_set_attributes_state_t;

SCRATCH_MEM_TYPED(go_span_set_attributes, go_span_set_attributes_state_t);

static __always_inline int finalize_go_span_start() {
    go_span_start_tail_state_t *state = go_span_start_tail_mem();
    if (!state) {
        return 0;
    }

    otel_span_t *span = lookup_active_span(&state->span_key);
    if (span) {
        if (!state->publish_parent ||
            publish_span_trace_parent(span, &state->goroutine_key, &state->span_key)) {
            track_span_context(span, (void *)state->context_data);
        } else {
            poison_go_trace(&state->goroutine_key);
            delete_active_span(&state->span_key);
        }
    }

    delete_span_info(&state->goroutine_key);
    return 0;
}

static __noinline u8 capture_go_span_start_special_attrs(go_span_start_tail_state_t *state,
                                                         otel_span_t *span) {
    if (!state || !span) {
        return 0;
    }

    const u8 required = required_go_otel_special_attrs(span->span_kind);
#pragma clang loop unroll(disable)
    for (u8 step = 0; step < k_go_span_start_route_scan_steps_per_tail; step++) {
        if ((state->special_attrs_found & required) == required) {
            return 1;
        }
        if (!state->route_attr_pos) {
            if (!state->route_attribute_opt_pos ||
                state->route_attrs_scanned >= k_go_max_span_start_route_attrs) {
                break;
            }

            u8 attribute_opt = state->route_attribute_opt_pos - 1;
            state->route_attribute_opt_pos = attribute_opt;
            bpf_clamp_umax(attribute_opt, k_go_max_span_start_opts - 1);
            u8 option_index = state->attribute_opts[attribute_opt];
            if (option_index >= state->opts_len || option_index >= k_go_max_span_start_opts) {
                continue;
            }
            bpf_clamp_umax(option_index, k_go_max_span_start_opts - 1);

            void *option = (void *)state->opts_ptr + (option_index * k_go_ptr_arr_size);
            void *option_data = 0;
            bpf_probe_read_user(&option_data, sizeof(option_data), option + sizeof(void *));
            if (!option_data) {
                continue;
            }

            u64 attributes_len = 0;
            void *attributes_usr_buf = 0;
            bpf_probe_read_user(&attributes_usr_buf, sizeof(attributes_usr_buf), option_data);
            bpf_probe_read_user(
                &attributes_len, sizeof(attributes_len), option_data + sizeof(void *));
            if (!attributes_usr_buf || !attributes_len) {
                continue;
            }

            state->route_attrs_buf = (u64)attributes_usr_buf;
            state->route_attr_pos = (u8)min(attributes_len, (u64)k_go_otel_max_attribute_scan);
        }

        if (state->route_attrs_scanned >= k_go_max_span_start_route_attrs) {
            break;
        }

        u8 attr_index = state->route_attr_pos - 1;
        state->route_attr_pos = attr_index;
        state->route_attrs_scanned++;
        bpf_clamp_umax(attr_index, k_go_otel_max_attribute_scan - 1);
        go_otel_key_value_t *go_attrs = (void *)state->route_attrs_buf;
        state->special_attrs_found |=
            capture_go_otel_special_attr(&go_attrs[attr_index], span, state->special_attrs_found);
    }
    return (state->special_attrs_found & required) == required;
}

static __always_inline int collect_go_span_start_attributes(struct pt_regs *ctx) {
    go_span_start_tail_state_t *state = go_span_start_tail_mem();
    if (!state) {
        return 0;
    }

    otel_span_t *span = lookup_active_span(&state->span_key);
    if (!span) {
        return finalize_go_span_start();
    }

    void *timestamp_option_data = 0;
#pragma clang loop unroll(disable)
    for (u8 option_index = 0; option_index < k_go_max_span_start_opts; option_index++) {
        if (option_index >= state->opts_len) {
            break;
        }

        void *option = (void *)state->opts_ptr + (option_index * k_go_ptr_arr_size);
        void *type = 0;
        bpf_probe_read_user(&type, sizeof(type), option);
        if (!type) {
            continue;
        }

        void *itype = 0;
        bpf_probe_read_user(&itype, sizeof(itype), type + k_go_interface_type_offset);
        void *option_data = 0;
        bpf_probe_read_user(&option_data, sizeof(option_data), option + sizeof(void *));
        if (!itype || !option_data) {
            continue;
        }

        if ((u64)itype == state->attribute_option_type) {
            u8 attribute_opt = state->attribute_opts_len;
            if (attribute_opt < k_go_max_span_start_opts) {
                bpf_clamp_umax(attribute_opt, k_go_max_span_start_opts - 1);
                state->attribute_opts[attribute_opt] = option_index;
                state->attribute_opts_len = attribute_opt + 1;
            }
            continue;
        }

        if ((u64)itype == state->timestamp_option_type) {
            timestamp_option_data = option_data;
        }
    }

    if (timestamp_option_data) {
        u64 timestamp = 0;
        if (read_go_time_unix_nano(timestamp_option_data, &timestamp)) {
            span->start_time = timestamp;
            span->start_time_wall = 1;
        }
    }

    if (state->attribute_opts_len) {
        state->route_attribute_opt_pos = state->attribute_opts_len;
        bpf_tail_call_static(ctx, &jump_table, k_tail_go_span_start_route);
        bpf_tail_call_static(ctx, &jump_table, k_tail_go_span_start_apply_attributes);
    }

    return finalize_go_span_start();
}

static __always_inline int apply_go_span_start_attributes(struct pt_regs *ctx) {
    go_span_start_tail_state_t *state = go_span_start_tail_mem();
    if (!state) {
        return 0;
    }

    otel_span_t *span = lookup_active_span(&state->span_key);
    if (!span) {
        return finalize_go_span_start();
    }

#pragma clang loop unroll(full)
    for (u8 i = 0; i < k_go_span_start_attribute_opts_per_tail; i++) {
        if (state->next_attribute_opt >= state->attribute_opts_len) {
            break;
        }

        u8 attribute_opt = state->next_attribute_opt;
        if (attribute_opt >= k_go_max_span_start_opts) {
            break;
        }
        bpf_clamp_umax(attribute_opt, k_go_max_span_start_opts - 1);
        state->next_attribute_opt = attribute_opt + 1;
        u8 option_index = state->attribute_opts[attribute_opt];
        if (option_index >= state->opts_len || option_index >= k_go_max_span_start_opts) {
            continue;
        }
        bpf_clamp_umax(option_index, k_go_max_span_start_opts - 1);
        void *option = (void *)state->opts_ptr + (option_index * k_go_ptr_arr_size);
        void *option_data = 0;
        bpf_probe_read_user(&option_data, sizeof(option_data), option + sizeof(void *));
        if (!option_data) {
            continue;
        }

        void *attributes_usr_buf = 0;
        u64 attributes_len = 0;
        bpf_probe_read_user(&attributes_usr_buf, sizeof(attributes_usr_buf), option_data);
        bpf_probe_read_user(&attributes_len, sizeof(attributes_len), option_data + sizeof(void *));
        if (attributes_usr_buf && attributes_len) {
            convert_go_otel_attributes(attributes_usr_buf, attributes_len, &span->span_attrs);
        }
    }

    if (state->next_attribute_opt < state->attribute_opts_len) {
        bpf_tail_call_static(ctx, &jump_table, k_tail_go_span_start_apply_attributes);
    }

    return finalize_go_span_start();
}

static __always_inline int begin_go_span_start_attributes(struct pt_regs *ctx,
                                                          otel_span_t *span,
                                                          const go_addr_key_t *goroutine_key,
                                                          const go_addr_key_t *span_key,
                                                          void *context_data,
                                                          const span_info_t *span_info,
                                                          u8 publish_parent) {
    go_span_start_tail_state_t *state = go_span_start_tail_mem();
    if (!state) {
        if (!publish_parent || publish_span_trace_parent(span, goroutine_key, span_key)) {
            track_span_context(span, context_data);
        } else {
            poison_go_trace(goroutine_key);
            delete_active_span(span_key);
        }
        delete_span_info(goroutine_key);
        return 0;
    }

    __builtin_memset(state, 0, sizeof(*state));
    state->span_key = *span_key;
    state->goroutine_key = *goroutine_key;
    state->context_data = (u64)context_data;
    state->publish_parent = publish_parent;
    span->span_attrs.valid_attrs = 0;

    const go_auto_sdk_type_info_t *type_info = go_auto_sdk_type_info();
    if (span_info->opts_ptr && span_info->opts_len && type_info) {
        state->opts_ptr = span_info->opts_ptr;
        state->opts_len = (u8)min(span_info->opts_len, (u64)k_go_max_span_start_opts);
        state->attribute_option_type = type_info->attribute_option_type;
        state->timestamp_option_type = type_info->timestamp_option_type;
    }

    if (state->opts_len && (state->attribute_option_type || state->timestamp_option_type)) {
        bpf_tail_call_static(ctx, &jump_table, k_tail_go_span_start_attributes);
    }

    return finalize_go_span_start();
}

SEC("uprobe/go_span_start_attributes")
int obi_uprobe_go_span_start_attributes(struct pt_regs *ctx) {
    return collect_go_span_start_attributes(ctx);
}

SEC("uprobe/go_span_start_apply_attributes")
int obi_uprobe_go_span_start_apply_attributes(struct pt_regs *ctx) {
    return apply_go_span_start_attributes(ctx);
}

SEC("uprobe/go_span_start_route")
int obi_uprobe_go_span_start_route(struct pt_regs *ctx) {
    go_span_start_tail_state_t *state = go_span_start_tail_mem();
    if (!state) {
        return 0;
    }

    otel_span_t *span = lookup_active_span(&state->span_key);
    if (!span) {
        return finalize_go_span_start();
    }

    const u8 found_special_attrs = capture_go_span_start_special_attrs(state, span);
    if (!found_special_attrs && state->route_attrs_scanned < k_go_max_span_start_route_attrs &&
        (state->route_attribute_opt_pos || state->route_attr_pos)) {
        bpf_tail_call_static(ctx, &jump_table, k_tail_go_span_start_route);
    }
    bpf_tail_call_static(ctx, &jump_table, k_tail_go_span_start_apply_attributes);
    return finalize_go_span_start();
}

// This instrumentation attaches uprobe to the following function:
// func (t *tracer) Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span)
// https://github.com/open-telemetry/opentelemetry-go/blob/98b32a6c3a87fbee5d34c063b9096f416b250897/internal/global/trace.go#L149
SEC("uprobe/tracer_Start_ret")
int obi_uprobe_tracer_Start_Returns(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    void *span_ptr = (void *)GO_PARAM4(ctx);
    void *context_data = (void *)GO_PARAM2(ctx);
    bpf_dbg_printk("=== uprobe/tracer_Start_ret ===");
    bpf_dbg_printk("goroutine_addr=%lx, span_ptr=%lx", goroutine_addr, span_ptr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    if (!consume_go_auto_sdk_rejected_return(&g_key)) {
        const go_auto_sdk_outer_call_t *stored_outer_call =
            bpf_map_lookup_elem(&go_auto_sdk_outer_calls, &g_key);
        if (stored_outer_call) {
            const go_auto_sdk_outer_call_t outer_call = *stored_outer_call;
            if (outer_call.state == k_go_auto_sdk_outer_direct_active ||
                outer_call.state == k_go_auto_sdk_outer_direct_consumed) {
                retire_go_auto_sdk_direct_return(&g_key, &outer_call);
            }
        }
    }

    span_info_t *span_info = lookup_span_info(&g_key);
    if (!span_info) {
        return 0;
    }
    if (!span_ptr) {
        poison_go_trace(&g_key);
        delete_span_info(&g_key);
        return 0;
    }

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);
    otel_span_t *active_span = lookup_active_span(&s_key);
    if (active_span) {
        active_span->span_name = span_info->name;
        active_span->span_kind = span_info->span_kind;
        return begin_go_span_start_attributes(
            ctx, active_span, &g_key, &s_key, context_data, span_info, 0);
    }
    otel_span_t *span = zero_initialised_span();

    if (!span) {
        poison_go_trace(&g_key);
        delete_span_info(&g_key);
        return 0;
    }

    span->span_name = span_info->name;
    span->span_kind = span_info->span_kind;
    span->start_time = bpf_ktime_get_ns();

    const s8 parent_result = init_span_trace_parent(
        span, &g_key, (void *)span_info->context_data, span_info->new_root, span_info->new_root, 0);
    if (parent_result == k_span_trace_parent_error) {
        __builtin_memset(&span->tp, 0, sizeof(span->tp));
        span->tp.ts = span->start_time;
        new_trace_id(&span->tp);
        urand_bytes(span->tp.span_id, SPAN_ID_SIZE_BYTES);
        apply_fail_closed_sampler_result(&span->tp);
        poison_go_trace(&g_key);
    }

    if (parent_result != k_span_trace_parent_not_found &&
        update_active_span(&s_key, span, BPF_ANY) == 0) {
        otel_span_t *stored_span = lookup_active_span(&s_key);
        if (stored_span) {
            return begin_go_span_start_attributes(ctx,
                                                  stored_span,
                                                  &g_key,
                                                  &s_key,
                                                  context_data,
                                                  span_info,
                                                  parent_result == k_span_trace_parent_ready);
        }
        delete_active_span(&s_key);
    }

    if (parent_result != k_span_trace_parent_not_found) {
        poison_go_trace(&g_key);
    }
    delete_span_info(&g_key);
    return 0;
}

static __always_inline u8 store_unsampled_auto_span(otel_span_t *span,
                                                    const go_addr_key_t *s_key,
                                                    u8 fail_closed) {
    if (!span->start_time) {
        span->start_time = bpf_ktime_get_ns();
    }
    span->auto_span = 1;
    if (!valid_trace(span->tp.trace_id) || !valid_span(span->tp.span_id)) {
        __builtin_memset(&span->tp, 0, sizeof(span->tp));
        span->tp.ts = span->start_time;
        new_trace_id(&span->tp);
        urand_bytes(span->tp.span_id, SPAN_ID_SIZE_BYTES);
    }
    if (fail_closed) {
        apply_fail_closed_sampler_result(&span->tp);
    } else {
        apply_sampler_result(&span->tp, 0);
    }
    return update_active_span(s_key, span, BPF_ANY) == 0;
}

static __always_inline u8 store_and_publish_unsampled_auto_span(otel_span_t *span,
                                                                const go_addr_key_t *g_key,
                                                                const go_addr_key_t *s_key,
                                                                u8 fail_closed) {
    if (!store_unsampled_auto_span(span, s_key, fail_closed)) {
        delete_span_info(g_key);
        poison_go_trace(g_key);
        return 0;
    }
    otel_span_t *stored_span = lookup_active_span(s_key);
    if (!stored_span) {
        delete_span_info(g_key);
        poison_go_trace(g_key);
        return 0;
    }
    if (publish_span_trace_parent(stored_span, g_key, s_key)) {
        return 1;
    }
    poison_go_trace(g_key);
    return 0;
}

SEC("uprobe/auto_sdk_tracer_start")
int obi_uprobe_auto_sdk_tracer_Start(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    const u64 generation = go_process_generation(g_key.pid);
    span_info_t *current_span_info =
        generation ? lookup_span_info_for_generation(&g_key, generation) : 0;
    const u32 span_auto_sdk_epoch = current_span_info ? current_span_info->auto_sdk_epoch : 0;
    const u8 global_handoff = current_span_info && current_span_info->global_handoff;
    const u8 handoff_failed = current_span_info && current_span_info->handoff_failed;
    const u8 new_root = current_span_info && current_span_info->new_root;
    const u8 unsupported_options = current_span_info && current_span_info->unsupported_options;
    const u8 capture_activation_committed =
        current_span_info && go_auto_sdk_capture_activation_committed(&g_key);
    go_auto_sdk_outer_call_t outer_call = {};
    const enum go_auto_sdk_handoff_owner owner =
        consume_go_auto_sdk_outer_call(&g_key,
                                       &outer_call,
                                       generation,
                                       span_auto_sdk_epoch,
                                       global_handoff,
                                       handoff_failed,
                                       capture_activation_committed);
    if (!generation || !current_span_info) {
        delete_auto_sdk_span_infos(&g_key, outer_call.generation, generation);
        return 0;
    }
    if (owner == k_go_auto_sdk_handoff_none) {
        if (outer_call.generation && outer_call.generation != generation) {
            delete_span_info_for_generation(&g_key, outer_call.generation);
        }
        return 0;
    }

    // Ownerless private SDK calls are outside OBI's admission protocol and
    // must remain untouched. Once an exact global/direct owner is proven,
    // synchronously force fail-closed sampling before any later validation.
    void *sampled_ptr = GO_PARAM6(ctx);
    bool sampled = false;
    if (!force_go_auto_sdk_unsampled(sampled_ptr)) {
        poison_go_auto_sdk_outer_inflight(&g_key, &outer_call);
        delete_auto_sdk_span_infos(&g_key, outer_call.generation, generation);
        poison_go_trace(&g_key);
        return 0;
    }
    if (!g_bpf_header_propagation || !span_context_offsets_available()) {
        delete_auto_sdk_span_infos(&g_key, outer_call.generation, generation);
        poison_go_trace(&g_key);
        return 0;
    }
    if (go_auto_sdk_process_quiescing((u32)g_key.pid, generation, outer_call.auto_sdk_epoch)) {
        delete_auto_sdk_span_infos(&g_key, outer_call.generation, generation);
        return 0;
    }

    void *span_ptr = (void *)GO_PARAM4(ctx);
    if (!span_ptr) {
        delete_auto_sdk_span_infos(&g_key, outer_call.generation, generation);
        poison_go_trace(&g_key);
        return 0;
    }

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);
    if (lookup_active_span(&s_key)) {
        delete_auto_sdk_span_infos(&g_key, outer_call.generation, generation);
        poison_go_trace(&g_key);
        return 0;
    }

    otel_span_t *span = zero_initialised_span();
    if (!span) {
        delete_auto_sdk_span_infos(&g_key, outer_call.generation, generation);
        poison_go_trace(&g_key);
        return 0;
    }
    span->start_time = bpf_ktime_get_ns();
    span->auto_span = 1;
    void *parent_span_context = GO_PARAM5(ctx);
    void *span_context = GO_PARAM7(ctx);
    if (unsupported_options) {
        store_and_publish_unsampled_auto_span(span, &g_key, &s_key, 1);
        fail_closed_go_span_context(parent_span_context);
        write_unsampled_go_span_context(span_context, &span->tp, span->tp.span_id);
        return 0;
    }
    s8 parent_result = init_span_trace_parent(span, &g_key, GO_PARAM3(ctx), new_root, 1, 1);
    if (parent_result == k_span_trace_parent_error) {
        store_and_publish_unsampled_auto_span(span, &g_key, &s_key, 1);
        write_unsampled_go_span_context(span_context, &span->tp, span->tp.span_id);
        return 0;
    }
    if (parent_result != k_span_trace_parent_ready) {
        const u8 fail_closed = span->tp.sampling_decision == k_sampling_decision_fail_closed;
        store_and_publish_unsampled_auto_span(span, &g_key, &s_key, fail_closed);
        write_unsampled_go_span_context(span_context, &span->tp, span->tp.span_id);
        return 0;
    }

    long ret = write_go_span_context(parent_span_context, &span->prev_tp, span->prev_tp.span_id);
    if (ret != 0) {
        store_and_publish_unsampled_auto_span(span, &g_key, &s_key, 1);
        fail_closed_go_span_context(parent_span_context);
        write_unsampled_go_span_context(span_context, &span->tp, span->tp.span_id);
        return 0;
    }

    ret = write_go_span_context(span_context, &span->tp, span->tp.span_id);
    if (ret != 0) {
        store_and_publish_unsampled_auto_span(span, &g_key, &s_key, 1);
        write_unsampled_go_span_context(span_context, &span->tp, span->tp.span_id);
        return 0;
    }

    if (update_active_span(&s_key, span, BPF_ANY) != 0) {
        apply_fail_closed_sampler_result(&span->tp);
        write_unsampled_go_span_context(span_context, &span->tp, span->tp.span_id);
        delete_auto_sdk_span_infos(&g_key, outer_call.generation, generation);
        poison_go_trace(&g_key);
        return 0;
    }
    otel_span_t *stored_span = lookup_active_span(&s_key);
    if (!stored_span) {
        apply_fail_closed_sampler_result(&span->tp);
        write_unsampled_go_span_context(span_context, &span->tp, span->tp.span_id);
        delete_auto_sdk_span_infos(&g_key, outer_call.generation, generation);
        poison_go_trace(&g_key);
        return 0;
    }
    if (!publish_span_trace_parent(stored_span, &g_key, &s_key)) {
        if (stored_span) {
            apply_fail_closed_sampler_result(&stored_span->tp);
            write_unsampled_go_span_context(
                span_context, &stored_span->tp, stored_span->tp.span_id);
            if (!publish_span_trace_parent(stored_span, &g_key, &s_key)) {
                poison_go_trace(&g_key);
            }
        } else {
            poison_go_trace(&g_key);
        }
        return 0;
    }

    sampled = stored_span->tp.flags & k_flag_sampled;
    if (bpf_probe_write_user(sampled_ptr, &sampled, sizeof(sampled)) != 0) {
        stored_span = lookup_active_span(&s_key);
        if (stored_span) {
            apply_fail_closed_sampler_result(&stored_span->tp);
            write_unsampled_go_span_context(
                span_context, &stored_span->tp, stored_span->tp.span_id);
            if (!publish_span_trace_parent(stored_span, &g_key, &s_key)) {
                poison_go_trace(&g_key);
            }
        } else {
            poison_go_trace(&g_key);
        }
    }
    return 0;
}

static __noinline void read_go_span_end_timestamp(struct pt_regs *ctx, otel_span_t *span) {
    void *opts_ptr = GO_PARAM2(ctx);
    u64 opts_len = (u64)GO_PARAM3(ctx);
    if (!opts_ptr || !opts_len) {
        return;
    }
    bpf_clamp_umax(opts_len, k_go_max_span_end_opts);

    const go_auto_sdk_type_info_t *type_info = go_auto_sdk_type_info();
    if (!type_info) {
        return;
    }
    const u64 timestamp_option_type = type_info->timestamp_option_type;
    if (!timestamp_option_type) {
        return;
    }

#pragma clang loop unroll(disable)
    for (u8 option_index = 0; option_index < k_go_max_span_end_opts; option_index++) {
        if (option_index >= opts_len) {
            break;
        }

        void *option = opts_ptr + (option_index * k_go_ptr_arr_size);
        void *type = 0;
        bpf_probe_read_user(&type, sizeof(type), option);
        if (!type) {
            continue;
        }

        void *itype = 0;
        bpf_probe_read_user(&itype, sizeof(itype), type + k_go_interface_type_offset);
        if ((u64)itype != timestamp_option_type) {
            continue;
        }

        span->end_time_wall = 0;
        void *option_data = 0;
        bpf_probe_read_user(&option_data, sizeof(option_data), option + sizeof(void *));
        u64 timestamp = 0;
        if (read_go_time_unix_nano(option_data, &timestamp)) {
            span->end_time = timestamp;
            span->end_time_wall = 1;
        }
    }
}

static __always_inline long submit_compact_go_span(otel_span_t *span) {
    if (!span) {
        return -1;
    }

    span->type = EVENT_GO_SPAN;
    if (!span->end_time_wall) {
        span->end_time = bpf_ktime_get_ns();
    }
    task_pid(&span->pid);
    return bpf_ringbuf_output(&events, span, sizeof(otel_span_t), get_flags());
}

static __always_inline otel_span_t *snapshot_active_span(const go_addr_key_t *s_key) {
    otel_span_t *active = lookup_active_span(s_key);
    if (!active) {
        return 0;
    }

    const u32 one = 1;
    if (bpf_map_update_elem(&span_mem, &one, active, BPF_ANY) != 0) {
        return 0;
    }
    return span_memory();
}

SEC("uprobe/nonRecordingSpan_End")
int obi_uprobe_nonRecordingSpan_End(struct pt_regs *ctx) {
    void *span_ptr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("=== uprobe/nonRecordingSpan_End ===");
    bpf_dbg_printk("goroutine_addr=%lx, span_ptr=%lx", (void *)GOROUTINE_PTR(ctx), span_ptr);

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);

    otel_span_t *span = snapshot_active_span(&s_key);
    if (!span) {
        return 0;
    }

    if (span->auto_span && (span->tp.flags & k_flag_sampled)) {
        return 0;
    }
    read_go_span_end_timestamp(ctx, span);
    if (delete_active_span(&s_key) != 0) {
        return 0;
    }
    retire_go_trace_owner(&s_key, &span->tp);
    submit_compact_go_span(span);
    bpf_dbg_printk("submitted manual span trace");

    return 0;
}

static __always_inline long submit_go_auto_span_json(struct pt_regs *ctx, u8 parent_remote) {
    u64 len = (u64)GO_PARAM3(ctx);
    if (len == 0 || len > k_go_auto_span_json_max_len) {
        return -1;
    }
    bpf_clamp_umax(len, k_go_auto_span_json_max_len);

    void *data_ptr = GO_PARAM2(ctx);
    if (!data_ptr) {
        return -1;
    }

    go_auto_span_buffer_t *event = go_auto_span_mem();
    if (!event) {
        return -1;
    }

    event->type = EVENT_GO_AUTO_SPAN;
    event->parent_remote = !!parent_remote;
    event->size = (u32)len;
    task_pid(&event->pid);
    if (bpf_probe_read_user(event->buf, len, data_ptr) != 0) {
        return -1;
    }

    const u64 event_size = __builtin_offsetof(go_auto_span_buffer_t, buf) + len;
    return bpf_ringbuf_output(&events, event, event_size, get_flags());
}

SEC("uprobe/auto_sdk_span_ended")
int obi_uprobe_auto_sdk_span_Ended(struct pt_regs *ctx) {
    void *span_ptr = (void *)GO_PARAM1(ctx);
    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);

    otel_span_t *span = snapshot_active_span(&s_key);
    if (!span || !span->auto_span) {
        return 0;
    }
    if (delete_active_span(&s_key) != 0) {
        return 0;
    }
    retire_go_trace_owner(&s_key, &span->tp);
    const u8 sampled = span->tp.flags & k_flag_sampled;
    if (!sampled || submit_go_auto_span_json(ctx, span->tp.parent_remote) != 0) {
        submit_compact_go_span(span);
    }
    return 0;
}

SEC("uprobe/span_SetStatus")
int obi_uprobe_SetStatus(struct pt_regs *ctx) {
    void *span_ptr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("=== uprobe/span_SetStatus ===");
    bpf_dbg_printk("goroutine_addr=%lx, span_ptr=%lx", (void *)GOROUTINE_PTR(ctx), span_ptr);

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);

    otel_span_t *span = lookup_active_span(&s_key);
    if (span == NULL) {
        return 0;
    }

    const u64 status_code = (u64)GO_PARAM2(ctx);
    span->status = (u32)status_code;
    __builtin_memset(span->span_description.buf, 0, sizeof(span->span_description.buf));

    void *description_ptr = GO_PARAM3(ctx);
    if (description_ptr == NULL) {
        return 0;
    }

    const u64 description_len = (u64)GO_PARAM4(ctx);
    const u64 description_size = min(k_max_status_description_len, description_len);
    bpf_probe_read_user(span->span_description.buf, description_size, description_ptr);

    return 0;
}

SEC("uprobe/span_SetAttributes")
int obi_uprobe_SetAttributes(struct pt_regs *ctx) {
    void *span_ptr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("=== uprobe/span_SetAttributes ===");
    bpf_dbg_printk("goroutine_addr=%lx, span_ptr=%lx", (void *)GOROUTINE_PTR(ctx), span_ptr);

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);

    otel_span_t *span = lookup_active_span(&s_key);
    if (span == NULL) {
        return 0;
    }

    void *attributes_usr_buf = GO_PARAM2(ctx);
    const u64 attributes_len = (u64)GO_PARAM3(ctx);
    go_span_set_attributes_state_t *state = go_span_set_attributes_mem();
    if (state && attributes_usr_buf && attributes_len) {
        __builtin_memset(state, 0, sizeof(*state));
        state->span_key = s_key;
        state->attrs_buf = (u64)attributes_usr_buf;
        state->attrs_len = attributes_len;
        state->attr_pos = (u8)min(attributes_len, (u64)k_go_otel_max_attribute_scan);
        bpf_tail_call_static(ctx, &jump_table, k_tail_go_span_set_attributes);
    }

    convert_go_otel_attributes(attributes_usr_buf, attributes_len, &span->span_attrs);

    return 0;
}

SEC("uprobe/go_span_set_attributes")
int obi_uprobe_go_span_set_attributes(struct pt_regs *ctx) {
    go_span_set_attributes_state_t *state = go_span_set_attributes_mem();
    if (!state) {
        return 0;
    }

    otel_span_t *span = lookup_active_span(&state->span_key);
    if (!span) {
        return 0;
    }

    const u8 required = required_go_otel_special_attrs(span->span_kind);
    go_otel_key_value_t *go_attrs = (void *)state->attrs_buf;
#pragma clang loop unroll(disable)
    for (u8 step = 0; step < k_go_span_start_route_scan_steps_per_tail; step++) {
        if (!state->attr_pos || (state->special_attrs_found & required) == required) {
            break;
        }

        u8 attr_index = state->attr_pos - 1;
        state->attr_pos = attr_index;
        bpf_clamp_umax(attr_index, k_go_otel_max_attribute_scan - 1);
        state->special_attrs_found |=
            capture_go_otel_special_attr(&go_attrs[attr_index], span, state->special_attrs_found);
    }

    if (state->attr_pos && (state->special_attrs_found & required) != required) {
        bpf_tail_call_static(ctx, &jump_table, k_tail_go_span_set_attributes);
    }
    convert_go_otel_attributes((void *)state->attrs_buf, state->attrs_len, &span->span_attrs);
    return 0;
}

SEC("uprobe/span_SetName")
int obi_uprobe_SetName(struct pt_regs *ctx) {
    void *span_ptr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("=== uprobe/span_SetName ===");
    bpf_dbg_printk("goroutine_addr=%lx, span_ptr=%lx", (void *)GOROUTINE_PTR(ctx), span_ptr);

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);

    otel_span_t *span = lookup_active_span(&s_key);
    if (span == NULL) {
        return 0;
    }

    void *span_name_ptr = GO_PARAM2(ctx);
    __builtin_memset(span->span_name.buf, 0, sizeof(span->span_name.buf));
    const u64 span_name_len = (u64)GO_PARAM3(ctx);
    if (!span_name_len) {
        return 0;
    }
    if (!span_name_ptr) {
        return 0;
    }

    read_span_name(span->span_name.buf, span_name_len, span_name_ptr);

    return 0;
}

static __always_inline void
read_go_span_event_attributes(otel_span_t *span, void *opts_ptr, u64 opts_len) {
    const go_auto_sdk_type_info_t *type_info = go_auto_sdk_type_info();
    if (!span || !opts_ptr || !opts_len || !type_info || !type_info->attribute_option_type) {
        return;
    }

    const u64 count = min(opts_len, (u64)k_go_max_event_opts);
#pragma clang loop unroll(disable)
    for (u8 option_index = 0; option_index < k_go_max_event_opts; option_index++) {
        if (option_index >= count) {
            break;
        }

        void *option = opts_ptr + (option_index * k_go_ptr_arr_size);
        void *type = 0;
        bpf_probe_read_user(&type, sizeof(type), option);
        if (!type) {
            continue;
        }

        void *itype = 0;
        bpf_probe_read_user(&itype, sizeof(itype), type + k_go_interface_type_offset);
        if ((u64)itype != type_info->attribute_option_type) {
            continue;
        }

        void *option_data = 0;
        bpf_probe_read_user(&option_data, sizeof(option_data), option + sizeof(void *));
        if (!option_data) {
            continue;
        }

        void *attributes_usr_buf = 0;
        u64 attributes_len = 0;
        bpf_probe_read_user(&attributes_usr_buf, sizeof(attributes_usr_buf), option_data);
        bpf_probe_read_user(&attributes_len, sizeof(attributes_len), option_data + sizeof(void *));
        convert_go_otel_attributes(attributes_usr_buf, attributes_len, &span->span_attrs);
    }
}

SEC("uprobe/span_RecordError")
int obi_uprobe_RecordError(struct pt_regs *ctx) {
    void *span_ptr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("=== uprobe/span_RecordError ===");
    bpf_dbg_printk("goroutine_addr=%lx, span_ptr=%lx", (void *)GOROUTINE_PTR(ctx), span_ptr);

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);

    otel_span_t *span = lookup_active_span(&s_key);
    if (span == NULL) {
        return 0;
    }

    read_go_span_event_attributes(span, (void *)GO_PARAM4(ctx), (u64)GO_PARAM5(ctx));

    void *err_type = (void *)GO_PARAM2(ctx);

    void *itype = 0;
    bpf_probe_read_user(&itype, sizeof(void *), err_type + k_go_interface_type_offset);
    bpf_dbg_printk("error, itype=%llx", itype);

    if (!itype) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();
    const u64 sym_addr = go_offset_of(ot, (go_offset){.v = _error_string_off});
    bpf_dbg_printk("err lookup off, sym_addr=%llx", sym_addr);

    if (!sym_addr) {
        return 0;
    }

    void *type_off = 0;
    bpf_probe_read_user(&type_off, sizeof(void *), (void *)sym_addr + k_go_interface_type_offset);

    if (!type_off) {
        return 0;
    }

    if (itype == type_off) {
        void *str_err = (void *)GO_PARAM3(ctx);
        bpf_dbg_printk("str_err=%llx", str_err);
        if (str_err) {
            struct go_string go_str = {0};
            bpf_probe_read_user(&go_str, sizeof(struct go_string), str_err);
            u8 valid_attrs = span->span_attrs.valid_attrs;
            bpf_dbg_printk("valid_attrs=%d, len=%d, str=%s", valid_attrs, go_str.len, go_str.str);

            if ((go_str.len < OTEL_ATTRIBUTE_KEY_MAX_LEN) &&
                (valid_attrs < OTEL_ATTRIBUTE_MAX_COUNT)) {
                __builtin_memcpy(
                    span->span_attrs.attrs[valid_attrs].key, ERROR_KEY, ERROR_KEY_SIZE);
                bpf_probe_read_user(span->span_attrs.attrs[valid_attrs].value,
                                    go_str.len & (OTEL_ATTRIBUTE_KEY_MAX_LEN - 1),
                                    go_str.str);
                span->span_attrs.attrs[valid_attrs].val_length = go_str.len;
                span->span_attrs.attrs[valid_attrs].vtype = attr_type_string;
                span->span_attrs.valid_attrs = valid_attrs + 1;
            }
        }
    }

    return 0;
}
