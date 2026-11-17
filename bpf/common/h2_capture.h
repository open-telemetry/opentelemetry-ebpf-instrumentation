// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>
#include <bpfcore/bpf_helpers.h>

#include <common/algorithm.h>

static __always_inline long
h2_capture_bytes(void *destination, u32 capacity, const void *source, u32 available) {
    __builtin_memset(destination, 0, capacity);
    u32 size = min(available, capacity);
    bpf_clamp_umax(size, capacity);
    return size ? bpf_probe_read(destination, size, source) : 0;
}
