// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/tp_info.h>

typedef struct http_func_invocation {
    u64 start_monotime_ns;
    u64 request_ptr;
    tp_info_t tp;
} http_func_invocation_t;
