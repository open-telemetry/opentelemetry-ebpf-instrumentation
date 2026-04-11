// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

enum event_source_type : u8 {
    k_event_source_kprobes = 0,
    k_event_source_lw_thread = 1,
};