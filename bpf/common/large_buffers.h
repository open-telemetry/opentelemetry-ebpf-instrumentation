// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/scratch_mem.h>

volatile const u32 http_max_captured_bytes = 0;
volatile const u32 mysql_max_captured_bytes = 0;
volatile const u32 postgres_max_captured_bytes = 0;
volatile const u32 kafka_max_captured_bytes = 0;

enum {
    // Maximum payload size per ring buffer chunk.
    k_large_buf_payload_max_size = 1 << 14, // 16K

    // Scratch memory size for a large buffer event: sizeof(tcp_large_buffer_t) + payload.
    // Rounded up to the next power of 2 above k_large_buf_payload_max_size to account
    // for the struct overhead.
    k_large_buf_max_size = 1 << 15, // 32K

    // Maximum valid value for each protocol's *_max_captured_bytes volatile variable.
    // These must equal the lte= validation values in EBPFBufferSizes (pkg/config/ebpf_tracer.go),
    // which enforces the same ceiling at configuration time.
    k_large_buf_max_http_captured_bytes = 1 << 16,
    k_large_buf_max_mysql_captured_bytes = 1 << 16,
    k_large_buf_max_postgres_captured_bytes = 1 << 16,
    k_large_buf_max_kafka_captured_bytes = 1 << 16,
};

SCRATCH_MEM_SIZED(tcp_large_buffers, k_large_buf_max_size);
