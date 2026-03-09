// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

#include <common/scratch_mem.h>

#include <maps/tp_info_mem.h>

static __always_inline tp_info_pid_t *tp_buf() {
    return (tp_info_pid_t *)tp_info_mem_mem();
}
