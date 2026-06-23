// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/common.h>
#include <common/connection_info.h>
#include <common/http_info.h>

#include <pid/types/pid_info.h>
#include <pid/types/pid_key.h>

enum sk_type : u8 { sk_type_client, sk_type_server };

enum ssl_state : u8 { ssl_state_unknown, ssl_state_no, ssl_state_yes };

struct socket_data {
    u64 pid_tgid;
    u64 cookie;
    u64 accept_time;

    pid_info pid_info;

    u32 task_tid;

    union {
        u8 flags;
        http_info_t http;
        tcp_req_t tcp;
    } request;

    pid_key_t pid_key;

    connection_info_t conn;
    connection_info_t sorted_conn;

    enum sk_type sk_type;
    enum ssl_state ssl_state;

    u8 _pad[2];
};
