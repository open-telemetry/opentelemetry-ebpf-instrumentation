// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

#include <common/http_types.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, unsigned char[TRACE_BUF_SIZE]);
    __uint(max_entries, 1);
} tp_char_buf_mem SEC(".maps");
