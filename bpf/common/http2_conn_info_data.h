// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

typedef struct http2_conn_info_data {
    u64 id;
    u8 flags;
    u8 req_hpack_poisoned;
    u8 resp_hpack_poisoned;
    u8 _pad[5];
} http2_conn_info_data_t;
