// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>
#include <common/ringbuf_metrics.h>
#include <common/ringbuf_record.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
    __uint(pinning, OBI_PIN_INTERNAL);
} log_events SEC(".maps");

// log_events_flags is used with bpf_ringbuf_output, which reserves the record only after the
// flags are computed, so the record of the given size is added to the queued bytes.
static __always_inline long log_events_flags(u64 size) {
    const u64 sz = bpf_ringbuf_query(&log_events, BPF_RB_AVAIL_DATA) + ringbuf_record_size(size);
    return sz >= 4096 ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

static __always_inline long log_events_ringbuf_output(void *data, u64 size) {
    const long err = bpf_ringbuf_output(&log_events, data, size, log_events_flags(size));
    account_ringbuf_write(RINGBUF_LOG_EVENTS, err != 0);
    return err;
}
