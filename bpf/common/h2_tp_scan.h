// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_builtins.h>

#include <common/h2_defs.h>

enum {
    k_h2_nlb_plain = k_hpack_tp_name_len,
    k_h2_nlb_huffman = k_hpack_tp_name_huffman_len | 0x80,
    // bytes needed to recognize each shape: a huffman value makes the field shorter
    // than a plain one, so the sizes cannot be collapsed into a single guard
    k_h2_tp_need_name_huffman = k_hpack_tp_name_offset + k_hpack_tp_name_huffman_len,
    k_h2_tp_need_name_plain = k_hpack_tp_name_offset + k_hpack_tp_name_len,
    k_h2_tp_need_indexed_value = 1 + k_hpack_value_len_tp,
};

// Name match only, any value encoding. Byte compares: packet offsets are unaligned.
static __always_inline bool h2_tp_match_name_plain(const unsigned char *p) {
    return bpf_memcmp(p + k_hpack_tp_name_offset, k_hpack_tp_name, k_hpack_tp_name_len) == 0;
}

static __always_inline bool h2_tp_match_name_huffman(const unsigned char *p) {
    return bpf_memcmp(
               p + k_hpack_tp_name_offset, k_hpack_tp_huffman, k_hpack_tp_name_huffman_len) == 0;
}

// name + plain 55-byte value: the only adoptable shape
static __always_inline bool h2_tp_match_plain(const unsigned char *p) {
    return h2_tp_match_name_plain(p) &&
           p[k_hpack_tp_name_offset + k_hpack_tp_name_len] == k_hpack_value_len_tp;
}

static __always_inline bool h2_tp_match_huffman(const unsigned char *p) {
    return h2_tp_match_name_huffman(p) &&
           p[k_hpack_tp_name_offset + k_hpack_tp_name_huffman_len] == k_hpack_value_len_tp;
}

// Indexed name: only the value is on the wire. Dashes at 35 and 52 exclude header values
// that merely contain "00-".
static __always_inline bool h2_tp_match_indexed_value(const unsigned char *p) {
    return p[0] == k_hpack_value_len_tp && p[1] == '0' && p[2] == '0' && p[3] == '-' &&
           p[1 + k_tp_val_dash2] == '-' && p[1 + k_tp_val_dash3] == '-';
}

// Per-position test used by find_first_h2_tp_candidate. Three bytes: two let every 11-byte
// header name through, and each false candidate costs a tail-call round trip.
static __always_inline bool h2_tp_is_candidate(u8 b0, u8 b1, u8 b2) {
    if (b0 == k_hpack_value_len_tp) {
        return b1 == '0' && b2 == '0';
    }
    if (!h2_hpack_is_literal(b0)) {
        return false;
    }
    if (b1 == k_h2_nlb_plain) {
        return b2 == k_hpack_tp_name[0];
    }

    return b1 == k_h2_nlb_huffman && b2 == k_hpack_tp_huffman[0];
}

typedef enum {
    k_h2_tp_none = 0,
    k_h2_tp_present,   // a traceparent OBI cannot read back
    k_h2_tp_adoptable, // name + plain value
} h2_tp_kind_t;

// Classifies a candidate. Needs k_h2_tp_need_name_huffman readable bytes. Bounds are proven by
// pointer comparison against end, which the verifier requires for packet memory; a plain
// buffer passes data + len.
static __always_inline h2_tp_kind_t h2_tp_classify(const unsigned char *p,
                                                   const unsigned char *end) {
    if ((void *)(p + k_h2_tp_need_name_huffman) > (void *)end) {
        return k_h2_tp_none;
    }

    if (p[0] == k_hpack_value_len_tp) {
        if ((void *)(p + k_h2_tp_need_indexed_value) <= (void *)end &&
            h2_tp_match_indexed_value(p)) {
            return k_h2_tp_present;
        }
        return k_h2_tp_none;
    }

    if (p[1] == k_h2_nlb_huffman) {
        if ((void *)(p + k_h2_tp_hpack_huffman_size) <= (void *)end && h2_tp_match_huffman(p)) {
            return k_h2_tp_adoptable;
        }
        return h2_tp_match_name_huffman(p) ? k_h2_tp_present : k_h2_tp_none;
    }

    if (p[1] == k_h2_nlb_plain && (void *)(p + k_h2_tp_need_name_plain) <= (void *)end) {
        if ((void *)(p + k_h2_tp_hpack_size) <= (void *)end && h2_tp_match_plain(p)) {
            return k_h2_tp_adoptable;
        }
        return h2_tp_match_name_plain(p) ? k_h2_tp_present : k_h2_tp_none;
    }

    return k_h2_tp_none;
}
