// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string.h>

static inline int bpf_memcmp(const void *a, const void *b, unsigned long long n) {
    return memcmp(a, b, (size_t)n);
}
