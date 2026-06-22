// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/scratch_mem.h>

volatile const u32 http_max_captured_bytes = 0;
volatile const u32 mysql_max_captured_bytes = 0;
volatile const u32 postgres_max_captured_bytes = 0;
volatile const u32 kafka_max_captured_bytes = 0;
volatile const u32 mssql_max_captured_bytes = 0;
volatile const u32 tcp_max_captured_bytes = 0;

enum {
    k_large_buf_payload_max_size = 1 << 14,            // 16 KB per chunk
    k_large_buf_max_size = 1 << 15,                    // 32 KB (header + payload)
    k_large_buf_per_emit_max = 1 << 16,                // 64 KB per single emission (verifier safe)
    k_large_buf_max_http_captured_bytes = 1 << 18,     // 256 KB per-syscall HTTP total
    k_large_buf_max_mysql_captured_bytes = 1 << 16,    // 64 KB
    k_large_buf_max_postgres_captured_bytes = 1 << 16, // 64 KB
    k_large_buf_max_kafka_captured_bytes = 1 << 16,    // 64 KB
    k_large_buf_max_mssql_captured_bytes = 1 << 16,    // 64 KB
    k_large_buf_max_tcp_captured_bytes = 1 << 16,      // 64 KB
};

SCRATCH_MEM_SIZED(tcp_large_buffers, k_large_buf_max_size);
