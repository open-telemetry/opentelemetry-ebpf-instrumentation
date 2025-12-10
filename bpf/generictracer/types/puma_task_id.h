// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

typedef struct puma_task_id {
    u64 item;
    u32 pid;
    u32 _pad1;
} puma_task_id_t;
