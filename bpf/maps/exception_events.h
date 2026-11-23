// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>
#include <common/ringbuf_metrics.h>

// Exceptions are rare compared to requests, so they get their own ring and
// never compete with span events for space.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
    __uint(pinning, OBI_PIN_INTERNAL);
} exception_events SEC(".maps");

static __always_inline long exception_events_ringbuf_output(void *data, u64 size) {
    const long err = bpf_ringbuf_output(&exception_events, data, size, 0);
    account_ringbuf_write(RINGBUF_EXCEPTION_EVENTS, err != 0);
    return err;
}
