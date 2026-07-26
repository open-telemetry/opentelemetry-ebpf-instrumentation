// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/tp_info.h>

typedef struct go_large_buffer_req {
    tp_info_t tp;
    u8 event_type;
    u8 _pad[7];
} go_large_buffer_req_t;
