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

#include <common/common.h>
#include <common/http_types.h>
#include <common/ringbuf.h>

#include <gotracer/go_common.h>

#include <gotracer/types/otel_types.h>

enum { k_go_interface_type_offset = 8 };
enum { k_go_ptr_arr_size = 16 };

const char ERROR_KEY[] = "error message";
const u32 ERROR_KEY_SIZE = sizeof(ERROR_KEY) - 1;

typedef struct span_info {
    span_name_t name;
    u64 opts_ptr;
    u64 opts_len;
} span_info_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // goroutine
    __type(value, span_info_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} span_names SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, go_addr_key_t); // span pointer
    __type(value, otel_span_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} active_spans SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, otel_span_t);
    __uint(max_entries, 2);
} span_mem SEC(".maps");

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
    const u64 span_name_size =
        MAX_SPAN_NAME_LEN < span_name_len ? MAX_SPAN_NAME_LEN : span_name_len;
    bpf_probe_read(buf, span_name_size, span_name_ptr);
}

static __always_inline int tracer_start(struct pt_regs *ctx, u8 check_delegate) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);

    bpf_dbg_printk("=== uprobe/tracer.Start [%lx]=== ", goroutine_addr);
    void *tracer_ptr = GO_PARAM1(ctx);
    if (check_delegate) {
        off_table_t *ot = get_offsets_table();

        void *delegate_ptr = NULL;
        bpf_probe_read(
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
    u64 span_name_len = (u64)GO_PARAM5(ctx);
    read_span_name(span_info.name.buf, span_name_len, span_name_ptr);

    span_info.opts_ptr = (u64)GO_PARAM6(ctx);
    span_info.opts_len = (u64)GO_PARAM7(ctx);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    bpf_dbg_printk("span name %s", span_info.name.buf);

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

static __always_inline void read_attrs_from_opts(otel_span_t *span, void *opts_ptr, u64 len) {
    u64 count = len;
    bpf_clamp_umax(count, 5);
    off_table_t *ot = get_offsets_table();
    u64 sym_addr = go_offset_of(ot, (go_offset){.v = _tracer_attribute_opt_off});
    bpf_dbg_printk("lookup type off %llx", sym_addr);

    if (!sym_addr) {
        return;
    }

    void *type_off = 0;
    bpf_probe_read_user(&type_off, sizeof(void *), (void *)sym_addr + k_go_interface_type_offset);

    if (!type_off) {
        return;
    }

    bpf_dbg_printk("lookup itype %llx", type_off);

    int read_from = -1;

    for (int i = 0; i < count; i++) {
        void *type = 0;
        bpf_probe_read(&type, sizeof(void *), opts_ptr + (i * k_go_ptr_arr_size));
        if (type) {
            void *itype = 0;
            bpf_probe_read(&itype, sizeof(void *), type + k_go_interface_type_offset);
            if (itype && (itype == type_off)) {
                read_from = i;
                break;
            }
        }
    }

    bpf_dbg_printk("read_from %d", read_from);

    if (read_from >= 0) {
        void *attrs_arg = 0;
        bpf_probe_read(&attrs_arg, sizeof(void *), opts_ptr + (read_from * k_go_ptr_arr_size) + 8);

        if (attrs_arg) {
            void *attributes_usr_buf = 0;
            u64 attributes_len = 0;

            bpf_probe_read(&attributes_usr_buf, sizeof(void *), attrs_arg);
            bpf_probe_read(&attributes_len, sizeof(u64), attrs_arg + 8);

            bpf_dbg_printk("attr_ptr %llx, attr_len %d", attributes_usr_buf, attributes_len);

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
    bpf_dbg_printk("=== uretprobe/tracer.Start [%lx] span %lx === ", goroutine_addr, span_ptr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    span_info_t *span_info = bpf_map_lookup_elem(&span_names, &g_key);
    if (!span_info) {
        return 0;
    }

    otel_span_t *span = zero_initialised_span();

    if (!span) {
        return 0;
    }

    span->span_name = span_info->name;
    span->start_time = bpf_ktime_get_ns();

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

            // reusing gp_key to save stack space
            go_addr_key_from_id(&gp_key, span_ptr);

            bpf_map_update_elem(&active_spans, &gp_key, span, BPF_ANY);
        }
    }

    bpf_map_delete_elem(&span_names, &g_key);
    return 0;
}

SEC("uprobe/nonRecordingSpan_End")
int obi_uprobe_nonRecordingSpan_End(struct pt_regs *ctx) {
    void *span_ptr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("=== uprobe/nonRecordingSpan.End [%lx] span %lx === ",
                   (void *)GOROUTINE_PTR(ctx),
                   span_ptr);

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);

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

SEC("uprobe/span_SetStatus")
int obi_uprobe_SetStatus(struct pt_regs *ctx) {
    void *span_ptr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk(
        "=== uprobe/span.SetStatus [%lx] span %lx === ", (void *)GOROUTINE_PTR(ctx), span_ptr);

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);

    otel_span_t *span = (otel_span_t *)bpf_map_lookup_elem(&active_spans, &s_key);
    if (span == NULL) {
        return 0;
    }

    u64 status_code = (u64)GO_PARAM2(ctx);

    void *description_ptr = GO_PARAM3(ctx);
    if (description_ptr == NULL) {
        return 0;
    }

    // Getting span description
    u64 description_len = (u64)GO_PARAM4(ctx);
    u64 description_size =
        MAX_STATUS_DESCRIPTION_LEN < description_len ? MAX_STATUS_DESCRIPTION_LEN : description_len;
    bpf_probe_read(span->span_description.buf, description_size, description_ptr);

    span->status = (u32)status_code;

    return 0;
}

SEC("uprobe/span_SetAttributes")
int obi_uprobe_SetAttributes(struct pt_regs *ctx) {
    void *span_ptr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk(
        "=== uprobe/span.SetAttributes [%lx] span %lx === ", (void *)GOROUTINE_PTR(ctx), span_ptr);

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);

    otel_span_t *span = (otel_span_t *)bpf_map_lookup_elem(&active_spans, &s_key);
    if (span == NULL) {
        return 0;
    }

    void *attributes_usr_buf = GO_PARAM2(ctx);
    u64 attributes_len = (u64)GO_PARAM3(ctx);
    convert_go_otel_attributes(attributes_usr_buf, attributes_len, &span->span_attrs);

    return 0;
}

SEC("uprobe/span_SetName")
int obi_uprobe_SetName(struct pt_regs *ctx) {
    void *span_ptr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk(
        "=== uprobe/span.SetName [%lx] span %lx === ", (void *)GOROUTINE_PTR(ctx), span_ptr);

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

    u64 span_name_len = (u64)span_name_len_ptr;

    read_span_name(span->span_name.buf, span_name_len, span_name_ptr);

    return 0;
}

SEC("uprobe/span_RecordError")
int obi_uprobe_RecordError(struct pt_regs *ctx) {
    void *span_ptr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk(
        "=== uprobe/span.RecordError [%lx] span %lx === ", (void *)GOROUTINE_PTR(ctx), span_ptr);

    go_addr_key_t s_key = {};
    go_addr_key_from_id(&s_key, span_ptr);

    otel_span_t *span = (otel_span_t *)bpf_map_lookup_elem(&active_spans, &s_key);
    if (span == NULL) {
        return 0;
    }

    void *opts_ptr = (void *)GO_PARAM4(ctx);
    u64 opts_len = (u64)GO_PARAM5(ctx);

    if (opts_ptr && opts_len) {
        read_attrs_from_opts(span, opts_ptr, opts_len);
    }

    void *err_type = (void *)GO_PARAM2(ctx);

    void *itype = 0;
    bpf_probe_read(&itype, sizeof(void *), err_type + k_go_interface_type_offset);
    bpf_dbg_printk("itype err %llx", itype);

    if (!itype) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();
    u64 sym_addr = go_offset_of(ot, (go_offset){.v = _error_string_off});
    bpf_dbg_printk("err lookup off %llx", sym_addr);

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
        bpf_dbg_printk("str_err %llx", str_err);
        if (str_err) {
            struct go_string go_str = {0};
            bpf_probe_read(&go_str, sizeof(struct go_string), str_err);
            u8 valid_attrs = span->span_attrs.valid_attrs;
            bpf_dbg_printk(
                "valid_attrs %d, len %d, go_str %s", valid_attrs, go_str.len, go_str.str);

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
