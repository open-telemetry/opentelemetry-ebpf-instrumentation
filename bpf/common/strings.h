// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

static __always_inline char lowercase(char c) {
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

static __always_inline bool stricmp(const char *s1, const char *s2, u8 n) {
    for (u8 i = 0; i < n && s1[i] && s2[i]; i++) {
        if (lowercase(s1[i]) != lowercase(s2[i])) {
            return false;
        }
    }
    return true;
}

static __always_inline int obi_bpf_memcmp(const char *s1, const char *s2, s32 size) {
    for (int i = 0; i < size; i++) {
        if (s1[i] != s2[i]) {
            return i + 1;
        }
    }

    return 0;
}
