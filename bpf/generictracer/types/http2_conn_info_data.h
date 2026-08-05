// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

typedef struct http2_conn_info_data {
    u64 id;
    u64 process_start_time;
    u64 connection_time;
    u8 flags;
    u8 _pad[3];
    // Monotonic generation-local tombstone. Keeping retirement on the raw
    // connection value makes it survive HPACK-state LRU eviction.
    u32 retired;
} http2_conn_info_data_t;

_Static_assert(sizeof(http2_conn_info_data_t) == 32,
               "shared HTTP/2 connection values must remain small");
