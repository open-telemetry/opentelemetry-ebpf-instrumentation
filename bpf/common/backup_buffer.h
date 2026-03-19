// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

enum { k_backup_buffer_len = 256 };

typedef struct backup_buffer {
    unsigned char buf[k_backup_buffer_len];
    u32 tcp_seq;
} backup_buffer_t;
