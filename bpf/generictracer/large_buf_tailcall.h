// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/common.h>
#include <common/connection_info.h>
#include <common/scratch_mem.h>

enum { k_large_buf_max_batches = 4 };

typedef struct large_buf_emit_state {
    u64 u_buf;
    u32 remaining_bytes;
    pid_connection_info_t pid_conn;
    u8 batch_iter;
    u8 packet_type;
    u8 direction;
    enum large_buf_action action;
} large_buf_emit_state_t;

SCRATCH_MEM_TYPED(large_buf_emit_state, large_buf_emit_state_t)
