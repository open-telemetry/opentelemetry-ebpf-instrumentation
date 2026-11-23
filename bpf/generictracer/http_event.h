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
    info->flags = k_event_type_k_http_request;

    bpf_dbg_printk("Sending trace %lx, response length %d", info, info->resp_len);
    if (events_ringbuf_output(info, sizeof(*info)) != 0) {
        bpf_dbg_printk("failed to write the trace to the ringbuf");
    }
}
