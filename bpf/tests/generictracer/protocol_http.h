// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stdbool.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>

enum { EVENT_HTTP_REQUEST = 1 };

typedef struct http_info {
    u8 type;
    u8 submitted;
    u64 extra_id;
    struct {
        u32 ns;
        u32 user_pid;
        u32 host_pid;
    } pid;
    u32 task_tid;
} http_info_t;

extern struct bpf_test_map ongoing_http;
extern int test_finish_http_count;
extern u8 test_http_will_complete;

static __always_inline u8 http_will_complete(http_info_t *info, unsigned char *buf, u32 len) {
    (void)info;
    (void)buf;
    (void)len;

    return test_http_will_complete;
}

static __always_inline u8 http_info_complete(http_info_t *info) {
    return info && info->submitted;
}

static __always_inline void finish_http(http_info_t *info, pid_connection_info_t *pid_conn) {
    (void)info;
    (void)pid_conn;

    test_finish_http_count++;
}
