// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

enum ringbuf_id : u32 {
    RINGBUF_EVENTS,
    RINGBUF_GPU_EVENTS,
    RINGBUF_LOG_EVENTS,
    RINGBUF_COUNT,
};

typedef struct {
    u64 writes;
    u64 failures;
} ringbuf_write_stats_t;
