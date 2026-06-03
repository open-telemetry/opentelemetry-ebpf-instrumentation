// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

enum { IP_V6_ADDR_LEN = 16 };

typedef struct connection_info {
    u8 s_addr[IP_V6_ADDR_LEN];
    u8 d_addr[IP_V6_ADDR_LEN];
    u16 s_port;
    u16 d_port;
} connection_info_t;

typedef struct http_pid_connection_info {
    connection_info_t conn;
    u32 pid;
} pid_connection_info_t;

typedef struct ssl_pid_connection_info {
    pid_connection_info_t p_conn;
    u16 orig_dport;
    u8 _pad[6];
} ssl_pid_connection_info_t;

static __always_inline void dbg_print_http_connection_info(const connection_info_t *info) {
    (void)info;
}
