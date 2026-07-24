// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/tp_info.h>
#include <common/connection_info.h>

typedef struct go_large_buffer_key {
    connection_info_t conn;
    u32 stream_id;
    u32 _pad;
} go_large_buffer_key_t;
