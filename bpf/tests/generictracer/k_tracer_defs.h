// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>

extern int test_parser_call_count;
extern int test_last_parser_bytes_len;
extern u8 test_last_ssl;
extern u8 test_last_direction;
extern u16 test_last_orig_dport;

static __always_inline void handle_buf_with_connection(void *ctx,
                                                       pid_connection_info_t *pid_conn,
                                                       void *u_buf,
                                                       int bytes_len,
                                                       u8 ssl,
                                                       u8 direction,
                                                       u16 orig_dport) {
    (void)ctx;
    (void)pid_conn;
    (void)u_buf;

    test_parser_call_count++;
    test_last_parser_bytes_len = bytes_len;
    test_last_ssl = ssl;
    test_last_direction = direction;
    test_last_orig_dport = orig_dport;
}
