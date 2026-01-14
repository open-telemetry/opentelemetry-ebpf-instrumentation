// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/scratch_mem.h>

volatile const u32 http_buffer_size = 0;
volatile const u32 mysql_buffer_size = 0;
volatile const u32 postgres_buffer_size = 0;
volatile const u32 kafka_buffer_size = 0;

enum {
    // This value represents a pessimistic guard for the maximum size
    // a large buffer event can take into the ring buffer.
    // The actual size is "event size + payload". Since the payload
    // is guaranteed to be a power of 2, we take the next power of 2
    // of the maximum payload size as a guard.
    k_large_buf_max_size = 1 << 14, // 16K
    k_large_buf_max_size_mask = k_large_buf_max_size - 1,

    // Maximum size for a large buffer payload.
    k_large_buf_payload_max_size = 1 << 13, // 8K
    k_large_buf_payload_max_size_mask = k_large_buf_payload_max_size - 1,
};

SCRATCH_MEM_SIZED(http_large_buffers, k_large_buf_max_size);
SCRATCH_MEM_SIZED(mysql_large_buffers, k_large_buf_max_size);
SCRATCH_MEM_SIZED(postgres_large_buffers, k_large_buf_max_size);
SCRATCH_MEM_SIZED(kafka_large_buffers, k_large_buf_max_size);
