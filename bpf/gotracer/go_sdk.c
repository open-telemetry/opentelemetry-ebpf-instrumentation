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

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // goroutine
    __type(value, span_name_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} span_names SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, go_addr_key_t); // span pointer
    __type(value, otel_span_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} active_spans SEC(".maps");

static __always_inline void
read_span_name(unsigned char *buf, const u64 span_name_len, void *span_name_ptr) {
    const u64 span_name_size =
        MAX_SPAN_NAME_LEN < span_name_len ? MAX_SPAN_NAME_LEN : span_name_len;
    bpf_probe_read(buf, span_name_size, span_name_ptr);
}

SEC("uprobe/tracer_Start")
int beyla_uprobe_tracer_Start(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);

    bpf_dbg_printk("=== uprobe/tracer.Start [%lx]=== ", goroutine_addr);
    void *tracer_ptr = GO_PARAM1(ctx);
    void *delegate_ptr = NULL;
    bpf_probe_read(&delegate_ptr, sizeof(delegate_ptr), (void *)(tracer_ptr + 64));
    if (delegate_ptr != NULL) {
        // Delegate is set, so we should not instrument this call
        return 0;
    }
    span_name_t span_name = {0};

    // Getting span name
    void *span_name_ptr = GO_PARAM4(ctx);
    u64 span_name_len = (u64)GO_PARAM5(ctx);
    read_span_name(span_name.buf, span_name_len, span_name_ptr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    bpf_dbg_printk("span name %s", span_name.buf);

    bpf_map_update_elem(&span_names, &g_key, &span_name, 0);
    return 0;
}

// This instrumentation attaches uprobe to the following function:
// func (t *tracer) Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span)
// https://github.com/open-telemetry/opentelemetry-go/blob/98b32a6c3a87fbee5d34c063b9096f416b250897/internal/global/trace.go#L149
SEC("uprobe/tracer_Start_ret")
int beyla_uprobe_tracer_Start_Returns(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    void *span_ptr = (void *)GO_PARAM4(ctx);
    bpf_dbg_printk("=== uretprobe/tracer.Start [%lx] span %lx === ", goroutine_addr, span_ptr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    span_name_t *span_name = bpf_map_lookup_elem(&span_names, &g_key);
    if (!span_name) {
        return 0;
    }

    otel_span_t span = {0};
    span.span_name = *span_name;
    span.start_time = bpf_ktime_get_ns();

    unsigned char tp_buf[TP_MAX_VAL_LENGTH];
    tp_info_t *tp = tp_info_from_parent_go(&g_key, &span.parent_go);
    if (tp) {
        __builtin_memcpy(&span.prev_tp, tp, sizeof(tp_info_t));
        make_tp_string(tp_buf, &span.prev_tp);
        bpf_printk("prev tp: %s", tp_buf);

        tp_from_parent(&span.tp, tp);
        span.tp.flags = tp->flags;
        urand_bytes(span.tp.span_id, SPAN_ID_SIZE_BYTES);
        make_tp_string(tp_buf, &span.tp);
        bpf_printk("tp: %s", tp_buf);
        encode_hex(tp_buf, span.tp.parent_id, SPAN_ID_SIZE_BYTES);
        tp_buf[SPAN_ID_CHAR_LEN] = '\0';
        bpf_printk("parent: %s", tp_buf);

        if (span.parent_go) {
            go_addr_key_t gp_key = {};
            go_addr_key_from_id(&gp_key, (void *)span.parent_go);
            update_tp_parent_go(&gp_key, &span.tp);

            // reusing gp_key to save stack space
            go_addr_key_from_id(&gp_key, (void *)span_ptr);

            bpf_map_update_elem(&active_spans, &gp_key, &span, BPF_ANY);
        }
    }

    bpf_map_delete_elem(&span_names, &g_key);
    return 0;
}

SEC("uprobe/nonRecordingSpan_End")
int beyla_uprobe_nonRecordingSpan_End(struct pt_regs *ctx) {
    void *span_ptr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("=== uprobe/nonRecordingSpan.End [%lx] span %lx === ",
                   (void *)GOROUTINE_PTR(ctx),
                   span_ptr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, span_ptr);

    otel_span_t *span = bpf_map_lookup_elem(&active_spans, &g_key);
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

    otel_span_t *trace = bpf_ringbuf_reserve(&events, sizeof(otel_span_t), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        goto done;
    }

    __builtin_memcpy(trace, span, sizeof(otel_span_t));
    bpf_ringbuf_submit(trace, get_flags());
    bpf_dbg_printk("submitted manual span trace") done : bpf_map_delete_elem(&active_spans, &g_key);

    return 0;
}
