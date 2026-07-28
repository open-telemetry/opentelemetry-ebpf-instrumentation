// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_builtins.h>

#include <common/h2_defs.h>
#include <common/tp_info.h>
#include <common/trace_util.h>

static __always_inline u8 try_parse_tp_value(const unsigned char *val, tp_info_t *tp) {
    if (val[k_tp_val_dash1] != '-' || val[k_tp_val_dash2] != '-' || val[k_tp_val_dash3] != '-') {
        return 0;
    }
    decode_hex(tp->trace_id, &val[k_tp_val_trace_id_start], TRACE_ID_SIZE_BYTES * 2);
    decode_hex(tp->parent_id, &val[k_tp_val_span_id_start], SPAN_ID_SIZE_BYTES * 2);
    tp->flags = 1;
    return 1;
}

static const u8 k_hex_chars[256] = {
    ['0' ... '9'] = 1,
    ['a' ... 'f'] = 1,
    ['A' ... 'F'] = 1,
};

// Recovers traceparent when the HPACK name reference is a dyn-table index
static __always_inline u8 find_hpack_traceparent_value(const unsigned char *data,
                                                       u32 data_len,
                                                       tp_info_t *tp) {
    if (data_len < (u32)k_hpack_value_len_tp + 1) {
        return 0;
    }
    const u32 max_pos = data_len - (u32)k_hpack_value_len_tp - 1;

    for (u16 i = 0; i < k_hpack_tp_max_scan && i <= max_pos; i++) {
        if (data[i] != k_hpack_value_len_tp) {
            continue;
        }
        const unsigned char *val = &data[i + 1];
        if (val[0] != '0' || val[1] != '0' || val[2] != '-') {
            continue;
        }
        if (val[k_tp_val_dash2] != '-' || val[k_tp_val_dash3] != '-') {
            continue;
        }
        // weak evidence without a name match — spot-check id edges for hex
        const u8 ok = k_hex_chars[val[k_tp_val_trace_id_start]] &
                      k_hex_chars[val[k_tp_val_trace_id_start + 1]] &
                      k_hex_chars[val[k_tp_val_dash2 - 2]] & k_hex_chars[val[k_tp_val_dash2 - 1]] &
                      k_hex_chars[val[k_tp_val_span_id_start]] &
                      k_hex_chars[val[k_tp_val_span_id_start + 1]] &
                      k_hex_chars[val[k_tp_val_dash3 - 2]] & k_hex_chars[val[k_tp_val_dash3 - 1]];
        if (!ok) {
            continue;
        }
        return try_parse_tp_value(val, tp);
    }
    return 0;
}

// Name-fingerprint scan (plain + huffman)
static __always_inline u8 parse_hpack_traceparent(const unsigned char *data,
                                                  u32 data_len,
                                                  tp_info_t *tp) {
    if (data_len >= k_h2_tp_hpack_huffman_size) {
        const u32 max_pos = data_len - k_h2_tp_hpack_huffman_size;

        for (u16 i = 0; i < k_hpack_tp_max_scan && i <= max_pos; i++) {
            // senders that index the name emit any of the three literal forms
            if (!h2_hpack_is_literal(data[i])) {
                continue;
            }

            const u8 name_len_byte = data[i + 1];

            if (name_len_byte == k_hpack_tp_name_len) {
                if (i + k_h2_tp_hpack_size > data_len) {
                    continue;
                }
                if (bpf_memcmp(&data[i + k_hpack_tp_name_offset],
                               k_hpack_tp_name,
                               k_hpack_tp_name_len) != 0) {
                    continue;
                }
                if (data[i + k_hpack_tp_name_offset + k_hpack_tp_name_len] !=
                    k_hpack_value_len_tp) {
                    continue;
                }
                return try_parse_tp_value(&data[i + k_hpack_tp_val_offset], tp);
            }

            if (name_len_byte == (k_hpack_tp_name_huffman_len | 0x80)) {
                if (bpf_memcmp(&data[i + k_hpack_tp_name_offset],
                               k_hpack_tp_huffman,
                               k_hpack_tp_name_huffman_len) != 0) {
                    continue;
                }
                if (data[i + k_hpack_tp_name_offset + k_hpack_tp_name_huffman_len] !=
                    k_hpack_value_len_tp) {
                    continue;
                }
                return try_parse_tp_value(&data[i + k_hpack_tp_val_offset_huffman], tp);
            }
        }
    }

    return 0;
}
