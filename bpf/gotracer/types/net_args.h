// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>

typedef struct net_args {
    u64 byte_ptr;
    pid_connection_info_t p_conn;
} net_args_t;
