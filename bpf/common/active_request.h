// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/common.h>
#include <common/go_addr_key.h>

enum active_request_source : u8 {
    k_active_request_go = 1,
};

typedef struct active_request_key {
    enum active_request_source source;
    u8 _pad[7];
    union {
        go_addr_key_t go;
    } request;
} active_request_key_t;

typedef struct active_request {
    u64 start_monotime_ns;
    pid_info_t pid;
    connection_info_t conn;
    unsigned char path[k_path_max_len];
    unsigned char method[k_method_max_len];
    u8 is_tls;
    u8 _pad[4];
} active_request_t;
