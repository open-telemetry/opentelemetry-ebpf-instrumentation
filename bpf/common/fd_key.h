// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

typedef struct fd_key_t {
    u64 pid_tgid;
    s32 fd;
    u8 _pad[4];
} fd_key;
