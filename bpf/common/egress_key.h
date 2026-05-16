// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

typedef struct egress_key {
    u16 s_port;
    u16 d_port;
    u32 stream_id; // HTTP/2 stream ID; 0 for HTTP/1.1 and non-H2 protocols
} egress_key_t;
