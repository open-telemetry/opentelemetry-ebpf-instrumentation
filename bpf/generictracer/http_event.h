// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/http_info.h>
#include <common/ringbuf.h>
#include <logger/bpf_dbg.h>

static __always_inline void submit_http_event(http_info_t *info) {
    if (!http_info_emittable(info) || info->submitted) {
        return;
    }

    // This is already a map value; updating it persists the submitted flag.
    // Replacing the LRU entry would let another CPU recycle this pointer.
    info->submitted = 1;
    http_info_t *trace = events_ringbuf_reserve(sizeof(http_info_t), 0);
    if (trace) {
        bpf_dbg_printk("Sending trace %lx, response length %d", info, info->resp_len);

        __builtin_memcpy(trace, info, sizeof(http_info_t));
        trace->flags = k_event_type_k_http_request;
        bpf_ringbuf_submit(trace, get_flags());
    } else {
        bpf_dbg_printk("failed to reserve space in the ringbuf");
    }
}
