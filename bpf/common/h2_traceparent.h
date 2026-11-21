// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/h2_defs.h>
#include <common/tracing.h>

static __always_inline void make_h2_traceparent(unsigned char *header, const tp_info_t *wire) {
    header[0] = k_hpack_literal_no_index;
    header[1] = k_hpack_tp_name_len;
    __builtin_memcpy(header + 2, "traceparent", sizeof("traceparent") - 1);
    header[k_hpack_tp_val_offset - 1] = TP_MAX_VAL_LENGTH;
    make_tp_string(header + k_hpack_tp_val_offset, wire);
}
