// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

typedef u64 lw_thread_t;

enum : lw_thread_t { k_lw_thread_none = 0 };
