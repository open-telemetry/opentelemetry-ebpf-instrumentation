// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>
#include <common/trace_key.h>

typedef struct http_info http_info_t;

static __always_inline void delete_server_trace(pid_connection_info_t *pid_conn, trace_key_t *key) {
    (void)pid_conn;
    (void)key;
}
