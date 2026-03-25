// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

#include <common/http_buf_size.h>
#include <common/scratch_mem.h>

SCRATCH_MEM_SIZED(tp_char_buf, TRACE_BUF_SIZE);
