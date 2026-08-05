// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

typedef struct tracked_connection {
    u64 time;
    u32 netns;
    u8 direction;
    u8 _pad[3];
} tracked_connection_t;
