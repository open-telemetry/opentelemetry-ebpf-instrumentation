// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

typedef struct http2_conn_info_data {
    u64 id;
    u32 req_seq; // allocation hint; racy reads only cost claim retries
    u8 flags;
    u8 _pad[3];
} http2_conn_info_data_t;
