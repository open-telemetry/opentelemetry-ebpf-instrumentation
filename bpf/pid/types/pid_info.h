// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

typedef struct pid_info {
    u32 host_pid; // process id (tgid) in the root pid namespace: what bpf_get_current_pid_tgid() >> 32 returns
    u32 user_pid; // process id as seen inside its own pid namespace (for example, inside its container)
    u32 ns;       // pid namespace (inode) user_pid belongs to
} pid_info;
