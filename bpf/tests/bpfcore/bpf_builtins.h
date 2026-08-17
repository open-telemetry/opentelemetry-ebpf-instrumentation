// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string.h>

static inline int bpf_memcmp(const void *a, const void *b, unsigned long long n) {
    return memcmp(a, b, (size_t)n);
}

static inline void bpf_memcpy(void *dst, const void *src, unsigned long long n) {
    memcpy(dst, src, (size_t)n);
}

static inline void bpf_memset(void *dst, int c, unsigned long long n) {
    memset(dst, c, (size_t)n);
}
