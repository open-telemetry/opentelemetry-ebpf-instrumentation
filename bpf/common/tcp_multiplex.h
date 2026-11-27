// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/common.h>

// A multiplexed record is a regular tcp_req_t followed by this header and
// count ranges into its first-direction inline and large buffers.
typedef struct tcp_multiplex_header {
    u64 previous_record;
    u32 response_len;
    u8 count;
    u8 _pad[3];
} tcp_multiplex_header_t;

typedef struct tcp_io_range {
    u64 timestamp;
    u32 len;
    u32 large_offset;
    u32 large_len;
    u16 inline_offset;
    u16 inline_len;
} tcp_io_range_t;

// A continuation carries the inline prefix of a socket operation observed after the parent record.
typedef struct tcp_multiplex_cont {
    u8 flags;
    u8 direction;
    bool is_server;
    enum event_source_type event_source;
    u32 len;
    u64 record_start;
    u64 observed;
    pid_info_t pid;
    connection_info_t conn_info;
    tp_info_t tp;
    u32 large_len;
    unsigned char buf[k_tcp_res_len];
    u8 _pad[4];
} tcp_multiplex_cont_t;
