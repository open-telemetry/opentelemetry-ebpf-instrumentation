// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

static __always_inline u8 min_u8(u8 a, u8 b) {
    return a < b ? a : b;
}

static __always_inline u16 min_u16(u16 a, u16 b) {
    return a < b ? a : b;
}

static __always_inline u32 min_u32(u32 a, u32 b) {
    return a < b ? a : b;
}

static __always_inline u64 min_u64(u64 a, u64 b) {
    return a < b ? a : b;
}

static __always_inline s8 min_s8(s8 a, s8 b) {
    return a < b ? a : b;
}

static __always_inline s16 min_s16(s16 a, s16 b) {
    return a < b ? a : b;
}

static __always_inline s32 min_s32(s32 a, s32 b) {
    return a < b ? a : b;
}

static __always_inline s64 min_s64(s64 a, s64 b) {
    return a < b ? a : b;
}

static __always_inline long min_long(long a, long b) {
    return a < b ? a : b;
}

static __always_inline unsigned long min_ulong(unsigned long a, unsigned long b) {
    return a < b ? a : b;
}

#ifdef min
#undef min
#endif

#define min(a, b)                                                                                  \
    _Generic((a),                                                                                  \
        u8: min_u8,                                                                                \
        u16: min_u16,                                                                              \
        u32: min_u32,                                                                              \
        u64: min_u64,                                                                              \
        s8: min_s8,                                                                                \
        s16: min_s16,                                                                              \
        s32: min_s32,                                                                              \
        s64: min_s64,                                                                              \
        long: min_long,                                                                            \
        unsigned long: min_ulong)(a, b)

static __always_inline u8 max_u8(u8 a, u8 b) {
    return a > b ? a : b;
}

static __always_inline u16 max_u16(u16 a, u16 b) {
    return a > b ? a : b;
}

static __always_inline u32 max_u32(u32 a, u32 b) {
    return a > b ? a : b;
}

static __always_inline u64 max_u64(u64 a, u64 b) {
    return a > b ? a : b;
}

static __always_inline s8 max_s8(s8 a, s8 b) {
    return a > b ? a : b;
}

static __always_inline s16 max_s16(s16 a, s16 b) {
    return a > b ? a : b;
}

static __always_inline s32 max_s32(s32 a, s32 b) {
    return a > b ? a : b;
}

static __always_inline s64 max_s64(s64 a, s64 b) {
    return a > b ? a : b;
}

static __always_inline long max_long(long a, long b) {
    return a > b ? a : b;
}

static __always_inline unsigned long max_ulong(unsigned long a, unsigned long b) {
    return a > b ? a : b;
}

#ifdef max
#undef max
#endif

#define max(a, b)                                                                                  \
    _Generic((a),                                                                                  \
        u8: max_u8,                                                                                \
        u16: max_u16,                                                                              \
        u32: max_u32,                                                                              \
        u64: max_u64,                                                                              \
        s8: max_s8,                                                                                \
        s16: max_s16,                                                                              \
        s32: max_s32,                                                                              \
        s64: max_s64,                                                                              \
        long: max_long,                                                                            \
        unsigned long: max_ulong)(a, b)
