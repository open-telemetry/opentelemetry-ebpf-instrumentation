// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stdint.h>

// Dispatch helpers: build the field-access chain as a C expression so that
// typeof() can infer the return type, mirroring the real BPF CO-RE macro.
#define ___bpf_concat(a, b) a##b
#define ___bpf_apply(fn, n) ___bpf_concat(fn, n)
#define ___bpf_nth(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, N, ...) N
#define ___bpf_narg(...) ___bpf_nth(_, ##__VA_ARGS__, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define ___bpf_arrow1(s, a) (s)->a
#define ___bpf_arrow2(s, a, b) (s)->a->b
#define ___bpf_arrow3(s, a, b, c) (s)->a->b->c
#define ___bpf_arrow4(s, a, b, c, d) (s)->a->b->c->d

// Returns a zero value of the correct field type; no runtime dereference.
#define BPF_CORE_READ(src, ...)                                                                    \
    ({                                                                                             \
        __typeof__(___bpf_apply(___bpf_arrow, ___bpf_narg(__VA_ARGS__))(src,                       \
                                                                        ##__VA_ARGS__)) __r = {};  \
        (void)(src);                                                                               \
        __r;                                                                                       \
    })

#define BPF_CORE_READ_STR_INTO(dst, src, ...) ((void)(src), 0)
#define bpf_core_field_exists(field) (0)
#define bpf_core_enum_value_exists(t, v) (0)
#define bpf_core_enum_value(t, v) (0)
#define BPF_SNPRINTF(out, n, fmt, ...) (0)
