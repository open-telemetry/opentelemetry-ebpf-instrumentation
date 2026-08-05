// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/protocol_defs.h>

typedef struct egress_key {
    union {
        u8 s_addr[IP_V6_ADDR_LEN];
        u32 s_ip[IP_V6_ADDR_LEN_WORDS];
    };
    union {
        u8 d_addr[IP_V6_ADDR_LEN];
        u32 d_ip[IP_V6_ADDR_LEN_WORDS];
    };
    u32 pid;
    u32 stream_id; // HTTP/2 stream ID; 0 for HTTP/1.1 and non-H2 protocols
    u16 s_port;
    u16 d_port;
} egress_key_t;
