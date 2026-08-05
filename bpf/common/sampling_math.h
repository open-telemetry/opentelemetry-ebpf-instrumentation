// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

static __always_inline u64 sampler_trace_id_value(const unsigned char *trace_id) {
    return (((u64)trace_id[8] << 56) | ((u64)trace_id[9] << 48) | ((u64)trace_id[10] << 40) |
            ((u64)trace_id[11] << 32) | ((u64)trace_id[12] << 24) | ((u64)trace_id[13] << 16) |
            ((u64)trace_id[14] << 8) | (u64)trace_id[15]) >>
           1;
}

static __always_inline u8 sampler_trace_id_ratio(const unsigned char *trace_id,
                                                 u64 trace_id_upper_bound) {
    return sampler_trace_id_value(trace_id) < trace_id_upper_bound;
}
