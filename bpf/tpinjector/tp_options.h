// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/tp_info.h>

enum {
    // The historical layout implicitly represents a sampled context.
    // Keep sampled contexts on that layout so older OBI readers can propagate them.
    k_tcp_option_kind_otel = 25,
    k_tcp_option_otel_legacy_len = 26,
    k_tcp_option_otel_extended_len = 27,
};

typedef struct otel_tcp_option {
    u8 kind;
    u8 len;
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
} otel_tcp_option_t;

typedef struct otel_tcp_extended_option {
    otel_tcp_option_t legacy;
    u8 flags;
} otel_tcp_extended_option_t;

_Static_assert(sizeof(otel_tcp_option_t) == k_tcp_option_otel_legacy_len,
               "legacy OTel TCP option layout changed");
_Static_assert(sizeof(otel_tcp_extended_option_t) == k_tcp_option_otel_extended_len,
               "extended OTel TCP option layout changed");
_Static_assert(__builtin_offsetof(otel_tcp_extended_option_t, flags) ==
                   k_tcp_option_otel_legacy_len,
               "extended OTel TCP flags offset changed");

static __always_inline void make_otel_tcp_option(otel_tcp_option_t *option, const tp_info_t *tp) {
    option->kind = k_tcp_option_kind_otel;
    option->len = sizeof(*option);
    __builtin_memcpy(option->trace_id, tp->trace_id, sizeof(option->trace_id));
    __builtin_memcpy(option->span_id, tp->span_id, sizeof(option->span_id));
}

static __always_inline void make_otel_tcp_extended_option(otel_tcp_extended_option_t *option,
                                                          const tp_info_t *tp) {
    make_otel_tcp_option(&option->legacy, tp);
    option->legacy.len = sizeof(*option);
    option->flags = tp->flags & k_flag_mask;
}

static __always_inline bool use_otel_tcp_legacy_option(const tp_info_t *tp) {
    // The legacy format cannot carry the random bit, but old readers reject the
    // extended size. Preserve rolling compatibility whenever sampled is set.
    return tp->flags & k_flag_sampled;
}

static __always_inline u32 otel_tcp_option_wire_len(const tp_info_t *tp) {
    return use_otel_tcp_legacy_option(tp) ? k_tcp_option_otel_legacy_len
                                          : k_tcp_option_otel_extended_len;
}

static __always_inline bool valid_otel_tcp_legacy_option(const otel_tcp_option_t *option,
                                                         long loaded_len) {
    return loaded_len == sizeof(*option) && option->kind == k_tcp_option_kind_otel &&
           option->len == sizeof(*option);
}

static __always_inline bool valid_otel_tcp_extended_option(const otel_tcp_extended_option_t *option,
                                                           long loaded_len) {
    return loaded_len == sizeof(*option) && option->legacy.kind == k_tcp_option_kind_otel &&
           option->legacy.len == sizeof(*option);
}

static __always_inline bool valid_otel_tcp_option(const otel_tcp_extended_option_t *option,
                                                  long loaded_len) {
    return valid_otel_tcp_legacy_option(&option->legacy, loaded_len) ||
           valid_otel_tcp_extended_option(option, loaded_len);
}

static __always_inline u8 otel_tcp_flags(const otel_tcp_extended_option_t *option,
                                         long loaded_len) {
    return valid_otel_tcp_extended_option(option, loaded_len) ? option->flags & k_flag_mask
                                                              : k_flag_sampled;
}
