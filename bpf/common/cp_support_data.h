// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/trace_key.h>

// Data structure to support context propagation for thread pools
typedef struct cp_support_data {
    trace_key_t t_key;
    u64 ts;
    u8 real_client;
    u8 established;
    u8 failed;
    u8 _pad[5];
} cp_support_data_t;
