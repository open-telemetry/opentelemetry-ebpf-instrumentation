// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

#include <common/globals.h>
#include <common/tp_info.h>
#include <common/trace_util.h>
#include <common/tracing.h>

#include <logger/bpf_dbg.h>

volatile const u64 max_transaction_time;

// Traceparent format: Traceparent: ver (2 chars) - trace_id (32 chars) - span_id (16 chars) - flags (2 chars)
static __always_inline unsigned char *extract_trace_id(unsigned char *tp_start) {
    return tp_start + 13 + 2 + 1; // strlen("Traceparent: ") + strlen(ver) + strlen('-')
}

static __always_inline unsigned char *extract_span_id(unsigned char *tp_start) {
    // strlen("Traceparent: ") + strlen(ver) + strlen("-") + strlen(trace_id) + strlen("-")
    return tp_start + 13 + 2 + 1 + 32 + 1;
}

static __always_inline unsigned char *extract_flags(unsigned char *tp_start) {
    // strlen("Traceparent: ") + strlen(ver) + strlen("-") + strlen(trace_id) + strlen("-") + strlen(span_id) + strlen("-")
    return tp_start + 13 + 2 + 1 + 32 + 1 + 16 + 1;
}

static __always_inline u8 valid_span(const unsigned char *span_id) {
    return *((u64 *)span_id) != 0;
}

static __always_inline u8 valid_trace(const unsigned char *trace_id) {
    return *((u64 *)trace_id) != 0 || *((u64 *)(trace_id + 8)) != 0;
}

static __always_inline u8 should_be_in_same_transaction(const tp_info_t *parent_tp,
                                                        const tp_info_t *child_tp) {
    if (child_tp->ts < parent_tp->ts) {
        return 0;
    }

    const u64 diff = child_tp->ts - parent_tp->ts;

    return diff < max_transaction_time;
}

static __always_inline void init_new_trace(tp_info_t *tp) {
    bpf_d_printk("Generating new traceparent id [%s]", __FUNCTION__);
    new_trace_id(tp);
    urand_bytes(tp->span_id, SPAN_ID_SIZE_BYTES);
    __builtin_memset(tp->parent_id, 0, sizeof(tp->span_id));

    if (g_bpf_debug) {
        unsigned char tp_buf[TP_MAX_VAL_LENGTH];
        make_tp_string(tp_buf, tp);
        bpf_dbg_printk("tp_buf=[%s]", tp_buf);
    }
}
