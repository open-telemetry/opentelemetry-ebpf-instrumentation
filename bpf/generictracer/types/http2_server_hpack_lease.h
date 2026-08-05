// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>

// The connection generation is part of the key so a delayed tail-call chain
// can never authorize mutation of a reused tuple.
typedef struct http2_server_hpack_lease_key {
    pid_connection_info_t pid_conn;
    u64 connection_id;
    u64 process_start_time;
    u64 connection_time;
} http2_server_hpack_lease_key_t;

typedef struct http2_server_hpack_lease {
    u64 token;
    u32 poisoned;
    u32 _pad;
} http2_server_hpack_lease_t;
