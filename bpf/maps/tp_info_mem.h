// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

#include <common/scratch_mem.h>
#include <common/tp_info.h>

SCRATCH_MEM_TYPED(tp_info, tp_info_pid_t);
SCRATCH_MEM_TYPED(tp_info_backup, tp_info_pid_t);
