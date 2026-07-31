// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

typedef struct python_addr_key {
    u64 pid;
    u64 addr;
} python_addr_key_t;
