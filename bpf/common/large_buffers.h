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
    k_large_buf_payload_max_size = 1 << 14,
    k_large_buf_max_size = 1 << 15,
    k_large_buf_max_http_captured_bytes = 1 << 16,
    k_large_buf_max_mysql_captured_bytes = 1 << 16,
    k_large_buf_max_postgres_captured_bytes = 1 << 16,
    k_large_buf_max_kafka_captured_bytes = 1 << 16,
    k_large_buf_max_mssql_captured_bytes = 1 << 16,
    k_large_buf_max_tcp_captured_bytes = 1 << 16,
};

SCRATCH_MEM_SIZED(tcp_large_buffers, k_large_buf_max_size);
