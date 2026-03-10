// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#define bpf_clamp_umax(VAR, UMAX)                                                                  \
    do {                                                                                           \
        if ((VAR) > (UMAX))                                                                        \
            (VAR) = (UMAX);                                                                        \
    } while (0)

static __always_inline bool is_pow2(u32 n) {
    return n != 0 && (n & (n - 1)) == 0;
}
