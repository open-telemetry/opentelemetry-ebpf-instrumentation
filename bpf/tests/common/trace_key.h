// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

typedef struct trace_key {
    u64 extra_id;
    struct {
        u32 ns;
        u32 pid;
        u32 tid;
    } p_key;
} trace_key_t;
