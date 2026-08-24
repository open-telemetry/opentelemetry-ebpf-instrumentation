// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>

typedef struct go_h2_owned_stream_key {
    pid_connection_info_t p_conn;
    u32 process_start_lo;
    u32 process_start_hi;
    u32 stream_id;
} go_h2_owned_stream_key_t;

enum {
    k_go_h2_owned_stream_fresh_ns = 30ULL * 1000 * 1000 * 1000,
};

static __always_inline bool go_h2_owned_stream_is_fresh(u64 marked_ns, u64 now) {
    return marked_ns && now >= marked_ns && now - marked_ns <= k_go_h2_owned_stream_fresh_ns;
}
