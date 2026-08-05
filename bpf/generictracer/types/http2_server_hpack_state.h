// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/h2_defs.h>
#include <common/hpack.h>

typedef struct http2_server_hpack_state {
    hpack_dynamic_name_state_t dynamic;
    h2_hpack_stream_state_t headers;
    h2_request_frame_cursor_t request_cursor;
    u32 desynced;
    u8 _pad[4];
} http2_server_hpack_state_t;

_Static_assert(sizeof(http2_server_hpack_state_t) <= 3072,
               "per-connection HPACK state exceeded its bounded map budget");
