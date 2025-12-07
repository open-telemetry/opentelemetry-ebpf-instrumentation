// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

typedef struct puma_task_id {
    u64 ary;
    u64 item;
} puma_task_id_t;
