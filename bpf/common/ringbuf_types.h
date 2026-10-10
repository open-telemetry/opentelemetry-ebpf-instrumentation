// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

typedef struct {
    u64 writes;
    u64 failures;
} ringbuf_write_stats_t;
