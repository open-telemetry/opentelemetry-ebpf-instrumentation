// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

typedef struct pid_key {
    u32 tid; // thread id as seen inside its pid namespace (for example, inside its container)
    u32 pid; // process id (tgid) owning that thread, as seen inside the same pid namespace
    u32 ns;  // pid namespace (inode) both ids belong to
} pid_key_t;
