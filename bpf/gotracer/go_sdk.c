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
#include <common/http_types.h>
#include <common/map_sizing.h>
#include <common/ringbuf.h>
#include <common/scratch_mem.h>

#include <gotracer/go_common.h>

#include <gotracer/types/otel_types.h>
#include <pid/maps/map_sizing.h>

enum { k_go_interface_type_offset = 8 };
enum { k_go_ptr_arr_size = 16 };
enum { k_go_auto_activation_max_attempts = 3 };
enum { k_efault = 14 };

const char ERROR_KEY[] = "error message";
const u32 ERROR_KEY_SIZE = sizeof(ERROR_KEY) - 1;

typedef struct span_info {
    span_name_t name;
    u64 opts_ptr;
    u64 opts_len;
} span_info_t;

typedef struct go_auto_activation_attempt_key {
    u64 generation;
    u32 pid;
    u8 attempt;
    u8 _pad[3];
} go_auto_activation_attempt_key_t;

typedef struct go_auto_activation_event {
    u8 type;
    u8 _pad[3];
    u32 pid;
    u64 generation;
} go_auto_activation_event_t;

typedef struct go_auto_span_state {
    tp_info_t prev_tp;
    tp_info_t child_tp;
    u64 goroutine;
    u64 generation;
    u8 committed;
    u8 _pad[7];
} go_auto_span_state_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // goroutine
    __type(value, span_info_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} span_names SEC(".maps");

// this is a large value data structure, increase
// concurrent_custom_spans carefully.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, go_addr_key_t); // span pointer
    __type(value, otel_span_t);
    __uint(max_entries, MAX_CONCURRENT_CUSTOM_SPANS);
    __uint(pinning, OBI_PIN_INTERNAL);
} active_spans SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, go_auto_activation_attempt_key_t);
    __type(value, u8);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_auto_activation_attempts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, k_max_concurrent_pids);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_auto_targets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, go_addr_key_t); // span pointer
    __type(value, go_auto_span_state_t);
    __uint(max_entries, MAX_CONCURRENT_CUSTOM_SPANS);
    __uint(pinning, OBI_PIN_INTERNAL);
} active_go_auto_spans SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, otel_span_t);
    __uint(max_entries, 2);
} span_mem SEC(".maps");

SCRATCH_MEM_SIZED(go_auto_span_event, sizeof(go_auto_span_t) + k_go_auto_span_json_max_len);

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

static __always_inline u8 span_context_offsets_available() {
    off_table_t *ot = get_offsets_table();
    if (!ot) {
        return 0;
    }

    const u64 trace_id_pos = go_offset_of(ot, (go_offset){.v = _span_context_trace_id_pos});
    const u64 span_id_pos = go_offset_of(ot, (go_offset){.v = _span_context_span_id_pos});
    const u64 flags_pos = go_offset_of(ot, (go_offset){.v = _span_context_trace_flags_pos});
    const u64 auto_sdk_sc_pos = go_offset_of(ot, (go_offset){.v = _auto_sdk_span_context_pos});
    const u64 auto_sdk_supported =
        go_offset_of(ot, (go_offset){.v = _auto_sdk_activation_supported});

    return trace_id_pos != (u64)-1 && span_id_pos != (u64)-1 && flags_pos != (u64)-1 &&
           auto_sdk_sc_pos != (u64)-1 && auto_sdk_supported == 1;
}

static __always_inline u8 go_auto_target_generation(u64 *generation) {
    const u32 pid = pid_from_pid_tgid(bpf_get_current_pid_tgid());
    u64 *current = bpf_map_lookup_elem(&go_auto_targets, &pid);
    if (!current || !generation) {
        return 0;
    }

    *generation = *current;
    return *generation != 0;
}

static __always_inline u8 go_auto_target_matches(u64 generation) {
    u64 current = 0;
    return go_auto_target_generation(&current) && current == generation;
}

static __always_inline void notify_go_auto_activation(u64 generation) {
    go_auto_activation_event_t event = {
        .type = EVENT_GO_AUTO_ACTIVATED,
        .pid = pid_from_pid_tgid(bpf_get_current_pid_tgid()),
        .generation = generation,
    };
    bpf_ringbuf_output(&events, &event, sizeof(event), get_flags());
}

static __always_inline u8
reserve_go_auto_activation_attempt(u64 generation, go_auto_activation_attempt_key_t *reserved) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    go_auto_activation_attempt_key_t key = {
        .generation = generation,
        .pid = pid_from_pid_tgid(pid_tgid),
    };
    const u8 attempted = 1;

#pragma unroll
    for (u8 attempt = 0; attempt < k_go_auto_activation_max_attempts; attempt++) {
        key.attempt = attempt;
        if (bpf_map_update_elem(&go_auto_activation_attempts, &key, &attempted, BPF_NOEXIST) == 0) {
            *reserved = key;
            return 1;
        }
    }

    return 0;
}

static __always_inline long write_go_span_context(void *go_sc, const tp_info_t *tp) {
    if (!go_sc || !tp) {
        return -1;
    }

    off_table_t *ot = get_offsets_table();
    if (!ot) {
        return -1;
    }

    const u64 trace_id_pos = go_offset_of(ot, (go_offset){.v = _span_context_trace_id_pos});
    const u64 span_id_pos = go_offset_of(ot, (go_offset){.v = _span_context_span_id_pos});
    const u64 flags_pos = go_offset_of(ot, (go_offset){.v = _span_context_trace_flags_pos});
    if (trace_id_pos == (u64)-1 || span_id_pos == (u64)-1 || flags_pos == (u64)-1) {
        return -1;
    }

    unsigned char *sc = go_sc;
    long ret = bpf_probe_write_user(sc + trace_id_pos, tp->trace_id, sizeof(tp->trace_id));
    if (ret != 0) {
        return ret;
    }

    ret = bpf_probe_write_user(sc + span_id_pos, tp->span_id, sizeof(tp->span_id));
    if (ret != 0) {
        return ret;
    }

    return bpf_probe_write_user(sc + flags_pos, &tp->flags, sizeof(tp->flags));
}

static __always_inline u8 empty_span_context(const tp_info_t *tp) {
    return !valid_trace(tp->trace_id) && !valid_span(tp->span_id);
}

static __always_inline u8 same_go_auto_span_context(const tp_info_t *a, const tp_info_t *b) {
    if (!a || !b) {
        return 0;
    }

    return *((u64 *)a->span_id) == *((u64 *)b->span_id) &&
           *((u64 *)a->trace_id) == *((u64 *)b->trace_id) &&
           *((u64 *)(a->trace_id + 8)) == *((u64 *)(b->trace_id + 8)) && a->flags == b->flags;
}

static __always_inline void init_go_auto_span_context(go_auto_span_state_t *state,
                                                      tp_info_t *child,
                                                      go_addr_key_t *g_key,
                                                      void *goroutine_addr) {
    tp_info_t *parent = bpf_map_lookup_elem(&go_trace_map, g_key);
    if (parent) {
        __builtin_memcpy(&state->prev_tp, parent, sizeof(state->prev_tp));
        tp_from_parent(child, parent);
    } else {
        child->flags = k_flag_sampled;
        urand_bytes(child->trace_id, sizeof(child->trace_id));
        if (!valid_trace(child->trace_id)) {
            child->trace_id[0] = 1;
        }
    }

    state->goroutine = (u64)goroutine_addr;
    urand_bytes(child->span_id, sizeof(child->span_id));
    if (!valid_span(child->span_id)) {
        child->span_id[0] = 1;
    }
    child->ts = bpf_ktime_get_ns();
    __builtin_memcpy(&state->child_tp, child, sizeof(state->child_tp));
}

static __always_inline void restore_go_auto_span_context(const go_auto_span_state_t *state) {
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, (void *)state->goroutine);

    tp_info_t *current = bpf_map_lookup_elem(&go_trace_map, &g_key);
    if (!current || !same_go_auto_span_context(current, &state->child_tp)) {
        return;
    }

    if (empty_span_context(&state->prev_tp)) {
        bpf_map_delete_elem(&go_trace_map, &g_key);
        return;
    }

    bpf_map_update_elem(&go_trace_map, &g_key, &state->prev_tp, BPF_ANY);
}

static __always_inline u8 reclaim_go_auto_span_state(const go_addr_key_t *s_key) {
    go_auto_span_state_t *existing = bpf_map_lookup_elem(&active_go_auto_spans, s_key);
    if (!existing) {
        return 1;
    }

    go_auto_span_state_t stale = {};
    __builtin_memcpy(&stale, existing, sizeof(stale));
    if (bpf_map_delete_elem(&active_go_auto_spans, s_key) != 0) {
        return 0;
    }

    if (stale.committed) {
        restore_go_auto_span_context(&stale);
    }
    return 1;
}

static __always_inline long write_go_auto_parent_span_context(void *go_sc,
                                                              const go_auto_span_state_t *state) {
    if (empty_span_context(&state->prev_tp)) {
        return 0;
    }

    return write_go_span_context(go_sc, &state->prev_tp);
}

static __always_inline long write_go_auto_embedded_span_context(void *span_ptr,
                                                                const go_auto_span_state_t *state) {
    off_table_t *ot = get_offsets_table();
    if (!ot) {
        return -1;
    }

    const u64 span_context_pos = go_offset_of(ot, (go_offset){.v = _auto_sdk_span_context_pos});
    if (span_context_pos == (u64)-1) {
        return -1;
    }

    unsigned char *span = span_ptr;
    return write_go_span_context(span + span_context_pos, &state->child_tp);
}

static __always_inline void commit_go_auto_span_state(const go_addr_key_t *s_key,
                                                      go_auto_span_state_t *state) {
    if (!go_auto_target_matches(state->generation)) {
        bpf_map_delete_elem(&active_go_auto_spans, s_key);
        return;
    }

    state->committed = 1;
    if (bpf_map_update_elem(&active_go_auto_spans, s_key, state, BPF_EXIST) != 0) {
        bpf_map_delete_elem(&active_go_auto_spans, s_key);
        return;
    }

    if (!go_auto_target_matches(state->generation)) {
        bpf_map_delete_elem(&active_go_auto_spans, s_key);
        return;
    }

    go_addr_key_t active_g_key = {};
    go_addr_key_from_id(&active_g_key, (void *)state->goroutine);
    if (bpf_map_update_elem(&go_trace_map, &active_g_key, &state->child_tp, BPF_ANY) != 0) {
        bpf_map_delete_elem(&active_go_auto_spans, s_key);
        return;
    }

    if (!go_auto_target_matches(state->generation)) {
        restore_go_auto_span_context(state);
        bpf_map_delete_elem(&active_go_auto_spans, s_key);
    }
}

static __always_inline int tracer_start(struct pt_regs *ctx, u8 check_delegate) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);

    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);
    void *tracer_ptr = GO_PARAM1(ctx);
    if (check_delegate) {
        off_table_t *ot = get_offsets_table();

        void *delegate_ptr = NULL;
        bpf_probe_read_user(
            &delegate_ptr,
            sizeof(delegate_ptr),
            (void *)(tracer_ptr + go_offset_of(ot, (go_offset){.v = _tracer_delegate_pos})));
        if (delegate_ptr != NULL) {
            // Delegate is set, so we should not instrument this call
            return 0;
        }
    }
    span_info_t span_info = {0};

    // Getting span name
    void *span_name_ptr = GO_PARAM4(ctx);
    const u64 span_name_len = (u64)GO_PARAM5(ctx);
    read_span_name(span_info.name.buf, span_name_len, span_name_ptr);

    span_info.opts_ptr = (u64)GO_PARAM6(ctx);
    span_info.opts_len = (u64)GO_PARAM7(ctx);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    bpf_dbg_printk("span_info.name.buf=[%s]", span_info.name.buf);

    bpf_map_update_elem(&span_names, &g_key, &span_info, 0);
    return 0;
}

SEC("uprobe/tracer_Start")
int obi_uprobe_tracer_Start(struct pt_regs *ctx) {
    return tracer_start(ctx, 0);
}

SEC("uprobe/tracer_Start_global")
int obi_uprobe_tracer_Start_global(struct pt_regs *ctx) {
    return tracer_start(ctx, 1);
}

SEC("uprobe/tracer_new_span")
int obi_uprobe_tracer_NewSpan(struct pt_regs *ctx) {
    u64 generation = 0;
    if (!go_auto_target_generation(&generation) || !g_bpf_header_propagation ||
        !span_context_offsets_available()) {
        return 0;
    }

    bool *auto_span_ptr = GO_PARAM4(ctx);
    if (!auto_span_ptr) {
        return 0;
    }

    bool auto_span = false;
    if (bpf_probe_read_user(&auto_span, sizeof(auto_span), auto_span_ptr) != 0) {
        return 0;
    }
    if (auto_span) {
        notify_go_auto_activation(generation);
        return 0;
    }

    go_auto_activation_attempt_key_t attempt_key = {};
    if (!reserve_go_auto_activation_attempt(generation, &attempt_key)) {
        return 0;
    }
    if (!go_auto_target_matches(generation)) {
        bpf_map_delete_elem(&go_auto_activation_attempts, &attempt_key);
        return 0;
    }

    const bool activate = true;
    if (bpf_probe_write_user(auto_span_ptr, &activate, sizeof(activate)) != 0) {
        bpf_dbg_printk("failed to activate Go Auto SDK");
    } else {
        notify_go_auto_activation(generation);
    }

    return 0;
}

static __always_inline void read_attrs_from_opts(otel_span_t *span, void *opts_ptr, u64 len) {
    u64 count = len;
    bpf_clamp_umax(count, 5);
    off_table_t *ot = get_offsets_table();
    const u64 sym_addr = go_offset_of(ot, (go_offset){.v = _tracer_attribute_opt_off});
    bpf_dbg_printk("lookup type off sym_addr: %llx", sym_addr);

    if (!sym_addr) {
        return;
    }

    void *type_off = 0;
    bpf_probe_read_user(&type_off, sizeof(void *), (void *)sym_addr + k_go_interface_type_offset);

    if (!type_off) {
        return;
    }

    bpf_dbg_printk("lookup type_off: %llx", type_off);

    int read_from = -1;

    for (int i = 0; i < count; i++) {
        void *type = 0;
        bpf_probe_read_user(&type, sizeof(void *), opts_ptr + (i * k_go_ptr_arr_size));
        if (type) {
            void *itype = 0;
            bpf_probe_read_user(&itype, sizeof(void *), type + k_go_interface_type_offset);
            if (itype && (itype == type_off)) {
                read_from = i;
                break;
            }
        }
    }

    bpf_dbg_printk("read_from=%d", read_from);

    if (read_from >= 0) {
        void *attrs_arg = 0;
        bpf_probe_read_user(
            &attrs_arg, sizeof(void *), opts_ptr + (read_from * k_go_ptr_arr_size) + 8);

        if (attrs_arg) {
            void *attributes_usr_buf = 0;
            u64 attributes_len = 0;

            bpf_probe_read_user(&attributes_usr_buf, sizeof(void *), attrs_arg);
            bpf_probe_read_user(&attributes_len, sizeof(u64), attrs_arg + 8);

            bpf_dbg_printk(
                "attributes_usr_buf=%llx, attributes_len=%d", attributes_usr_buf, attributes_len);

            if (attributes_usr_buf && attributes_len && attributes_len < 100) {
                convert_go_otel_attributes(attributes_usr_buf, attributes_len, &span->span_attrs);
            }
        }
    }
}

// This instrumentation attaches uprobe to the following function:
// func (t *tracer) Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span)
// https://github.com/open-telemetry/opentelemetry-go/blob/98b32a6c3a87fbee5d34c063b9096f416b250897/internal/global/trace.go#L149
SEC("uprobe/tracer_Start_ret")
int obi_uprobe_tracer_Start_Returns(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    void *span_ptr = (void *)GO_PARAM4(ctx);
    bpf_dbg_printk("=== uprobe/tracer_Start_ret ===");
    bpf_dbg_printk("goroutine_addr=%lx, span_ptr=%lx", goroutine_addr, span_ptr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);

    go_auto_span_state_t *auto_state = bpf_map_lookup_elem(&active_go_auto_spans, &s_key);
    if (auto_state) {
        if (auto_state->committed) {
            bpf_map_delete_elem(&span_names, &g_key);
            return 0;
        }
        bpf_map_delete_elem(&active_go_auto_spans, &s_key);
    }

    span_info_t *span_info = bpf_map_lookup_elem(&span_names, &g_key);
    if (!span_info) {
        return 0;
    }

    otel_span_t *span = zero_initialised_span();

    if (!span) {
        bpf_map_delete_elem(&span_names, &g_key);
        return 0;
    }

    span->span_name = span_info->name;
    span->start_time = bpf_ktime_get_ns();
    span->tp.ts = bpf_ktime_get_ns();

    if (span_info->opts_ptr && span_info->opts_len) {
        read_attrs_from_opts(span, (void *)span_info->opts_ptr, span_info->opts_len);
    }

    unsigned char tp_buf[TP_MAX_VAL_LENGTH];
    tp_info_t *tp = tp_info_from_parent_go(&g_key, &span->parent_go);
    if (tp) {
        __builtin_memcpy(&span->prev_tp, tp, sizeof(tp_info_t));
        tp_from_parent(&span->tp, tp);
        span->tp.flags = tp->flags;
        urand_bytes(span->tp.span_id, SPAN_ID_SIZE_BYTES);
        encode_hex(tp_buf, span->tp.parent_id, SPAN_ID_SIZE_BYTES);

        if (span->parent_go) {
            go_addr_key_t gp_key = {};
            go_addr_key_from_id(&gp_key, (void *)span->parent_go);
            update_tp_parent_go(&gp_key, &span->tp);

            bpf_map_update_elem(&active_spans, &s_key, span, BPF_ANY);
        }
    }

    bpf_map_delete_elem(&span_names, &g_key);
    return 0;
}

SEC("uprobe/auto_sdk_tracer_start")
int obi_uprobe_auto_sdk_tracer_Start(struct pt_regs *ctx) {
    u64 generation = 0;
    if (!go_auto_target_generation(&generation) || !g_bpf_header_propagation ||
        !span_context_offsets_available()) {
        return 0;
    }

    void *span_ptr = GO_PARAM4(ctx);
    if (!span_ptr) {
        return 0;
    }

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);
    if (!reclaim_go_auto_span_state(&s_key)) {
        return 0;
    }

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    void *parent_span_context = GO_PARAM5(ctx);
    void *span_context = GO_PARAM7(ctx);
    go_auto_span_state_t state = {
        .generation = generation,
    };
    tp_info_t child = {};
    init_go_auto_span_context(&state, &child, &g_key, goroutine_addr);

    if (bpf_map_update_elem(&active_go_auto_spans, &s_key, &state, BPF_NOEXIST) != 0) {
        return 0;
    }

    long ret = write_go_auto_parent_span_context(parent_span_context, &state);
    if (ret != 0) {
        bpf_map_delete_elem(&active_go_auto_spans, &s_key);
        return 0;
    }

    ret = write_go_span_context(span_context, &state.child_tp);
    if (ret != 0) {
        if (ret != -k_efault) {
            bpf_map_delete_elem(&active_go_auto_spans, &s_key);
        }
        return 0;
    }

    commit_go_auto_span_state(&s_key, &state);
    return 0;
}

SEC("uprobe/auto_sdk_context_with_value")
int obi_uprobe_auto_sdk_context_WithValue(struct pt_regs *ctx) {
    if (!g_bpf_header_propagation) {
        return 0;
    }

    void *span_ptr = GO_PARAM6(ctx);
    if (!span_ptr) {
        return 0;
    }

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);

    go_auto_span_state_t *state_ptr = bpf_map_lookup_elem(&active_go_auto_spans, &s_key);
    if (!state_ptr || state_ptr->committed) {
        return 0;
    }

    go_auto_span_state_t state = {};
    __builtin_memcpy(&state, state_ptr, sizeof(state));
    if (!go_auto_target_matches(state.generation) ||
        write_go_auto_embedded_span_context(span_ptr, &state) != 0) {
        bpf_map_delete_elem(&active_go_auto_spans, &s_key);
        return 0;
    }

    bpf_dbg_printk("go auto SDK deferred context span=%lx", span_ptr);
    commit_go_auto_span_state(&s_key, &state);
    return 0;
}

SEC("uprobe/nonRecordingSpan_End")
int obi_uprobe_nonRecordingSpan_End(struct pt_regs *ctx) {
    void *span_ptr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("=== uprobe/nonRecordingSpan_End ===");
    bpf_dbg_printk("goroutine_addr=%lx, span_ptr=%lx", (void *)GOROUTINE_PTR(ctx), span_ptr);

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);

    go_auto_span_state_t *auto_state = bpf_map_lookup_elem(&active_go_auto_spans, &s_key);
    if (auto_state && auto_state->committed) {
        return 0;
    }

    otel_span_t *span = bpf_map_lookup_elem(&active_spans, &s_key);
    if (span == NULL) {
        return 0;
    }

    span->type = EVENT_GO_SPAN;
    span->end_time = bpf_ktime_get_ns();
    task_pid(&span->pid);

    if (span->parent_go) {
        go_addr_key_t gp_key = {};
        go_addr_key_from_id(&gp_key, (void *)span->parent_go);
        update_tp_parent_go(&gp_key, &span->prev_tp);
    }

    bpf_ringbuf_output(&events, span, sizeof(otel_span_t), get_flags());
    bpf_dbg_printk("submitted manual span trace");

    bpf_map_delete_elem(&active_spans, &s_key);

    return 0;
}

SEC("uprobe/auto_sdk_span_ended")
int obi_uprobe_auto_sdk_span_Ended(struct pt_regs *ctx) {
    void *span_ptr = GO_PARAM1(ctx);

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);

    go_auto_span_state_t *state_ptr = bpf_map_lookup_elem(&active_go_auto_spans, &s_key);
    if (!state_ptr) {
        return 0;
    }
    if (!state_ptr->committed) {
        bpf_map_delete_elem(&active_go_auto_spans, &s_key);
        return 0;
    }

    go_auto_span_state_t state = {};
    __builtin_memcpy(&state, state_ptr, sizeof(state));
    const long delete_ret = bpf_map_delete_elem(&active_go_auto_spans, &s_key);
    restore_go_auto_span_context(&state);
    if (delete_ret != 0) {
        return 0;
    }

    u64 len = (u64)GO_PARAM3(ctx);
    if (len == 0 || len > k_go_auto_span_json_max_len) {
        return 0;
    }
    bpf_clamp_umax(len, k_go_auto_span_json_max_len);

    void *data_ptr = GO_PARAM2(ctx);
    if (!data_ptr) {
        return 0;
    }

    go_auto_span_t *event = go_auto_span_event_mem();
    if (!event) {
        return 0;
    }

    __builtin_memset(event, 0, offsetof(go_auto_span_t, buf));
    event->type = EVENT_GO_AUTO_SPAN;
    event->size = (u32)len;
    task_pid(&event->pid);

    if (bpf_probe_read_user(event->buf, len, data_ptr) != 0) {
        return 0;
    }

    u64 total_size = offsetof(go_auto_span_t, buf) + len;
    bpf_clamp_umax(total_size, offsetof(go_auto_span_t, buf) + k_go_auto_span_json_max_len);
    bpf_ringbuf_output(&events, event, total_size, get_flags());

    return 0;
}

SEC("uprobe/span_SetStatus")
int obi_uprobe_SetStatus(struct pt_regs *ctx) {
    void *span_ptr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("=== uprobe/span_SetStatus ===");
    bpf_dbg_printk("goroutine_addr=%lx, span_ptr=%lx", (void *)GOROUTINE_PTR(ctx), span_ptr);

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);

    otel_span_t *span = (otel_span_t *)bpf_map_lookup_elem(&active_spans, &s_key);
    if (span == NULL) {
        return 0;
    }

    const u64 status_code = (u64)GO_PARAM2(ctx);

    void *description_ptr = GO_PARAM3(ctx);
    if (description_ptr == NULL) {
        return 0;
    }

    // Getting span description
    const u64 description_len = (u64)GO_PARAM4(ctx);
    const u64 description_size = min(k_max_status_description_len, description_len);
    bpf_probe_read_user(span->span_description.buf, description_size, description_ptr);

    span->status = (u32)status_code;

    return 0;
}

SEC("uprobe/span_SetAttributes")
int obi_uprobe_SetAttributes(struct pt_regs *ctx) {
    void *span_ptr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("=== uprobe/span_SetAttributes ===");
    bpf_dbg_printk("goroutine_addr=%lx, span_ptr=%lx", (void *)GOROUTINE_PTR(ctx), span_ptr);

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);

    otel_span_t *span = (otel_span_t *)bpf_map_lookup_elem(&active_spans, &s_key);
    if (span == NULL) {
        return 0;
    }

    void *attributes_usr_buf = GO_PARAM2(ctx);
    const u64 attributes_len = (u64)GO_PARAM3(ctx);
    convert_go_otel_attributes(attributes_usr_buf, attributes_len, &span->span_attrs);

    return 0;
}

SEC("uprobe/span_SetName")
int obi_uprobe_SetName(struct pt_regs *ctx) {
    void *span_ptr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("=== uprobe/span_SetName ===");
    bpf_dbg_printk("goroutine_addr=%lx, span_ptr=%lx", (void *)GOROUTINE_PTR(ctx), span_ptr);

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);

    otel_span_t *span = (otel_span_t *)bpf_map_lookup_elem(&active_spans, &s_key);
    if (span == NULL) {
        return 0;
    }

    void *span_name_ptr = GO_PARAM2(ctx);
    if (span_name_ptr == NULL) {
        return 0;
    }

    void *span_name_len_ptr = GO_PARAM3(ctx);
    if (span_name_len_ptr == NULL) {
        return 0;
    }

    const u64 span_name_len = (u64)span_name_len_ptr;

    read_span_name(span->span_name.buf, span_name_len, span_name_ptr);

    return 0;
}

SEC("uprobe/span_RecordError")
int obi_uprobe_RecordError(struct pt_regs *ctx) {
    void *span_ptr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("=== uprobe/span_RecordError ===");
    bpf_dbg_printk("goroutine_addr=%lx, span_ptr=%lx", (void *)GOROUTINE_PTR(ctx), span_ptr);

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);

    otel_span_t *span = (otel_span_t *)bpf_map_lookup_elem(&active_spans, &s_key);
    if (span == NULL) {
        return 0;
    }

    void *opts_ptr = (void *)GO_PARAM4(ctx);
    const u64 opts_len = (u64)GO_PARAM5(ctx);

    if (opts_ptr && opts_len) {
        read_attrs_from_opts(span, opts_ptr, opts_len);
    }

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
