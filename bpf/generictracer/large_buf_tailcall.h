// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>
#include <common/scratch_mem.h>

// Maximum number of tail-call batches for large buffer emission (including the
// initial inline batch). Each batch emits up to k_large_buf_per_emit_max bytes.
enum { k_large_buf_max_batches = 4 };

// Per-CPU state for multi-batch large buffer emission via tail calls.
// Stored between tail call invocations to track emission progress.
typedef struct large_buf_emit_state {
    u64 u_buf;                      // user-space buffer address (advanced after each batch)
    u32 remaining_bytes;            // bytes remaining to emit
    pid_connection_info_t pid_conn; // key into ongoing_http for updating byte counters
    u8 batch_iter;                  // current batch index (1-based; batch 0 is inline)
    u8 packet_type;                 // PACKET_TYPE_REQUEST or PACKET_TYPE_RESPONSE
    u8 direction;                   // TCP_SEND or TCP_RECV
    u8 _pad;
} large_buf_emit_state_t;

SCRATCH_MEM_TYPED(large_buf_emit_state, large_buf_emit_state_t)
