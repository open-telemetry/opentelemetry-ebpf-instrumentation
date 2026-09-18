// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

typedef struct pid_data {
    u32 pid; // a pid to test against the filter (the process's own or its parent's), as seen inside its pid namespace
    u32 ns;  // pid namespace (inode) that pid belongs to
} pid_data_t;
