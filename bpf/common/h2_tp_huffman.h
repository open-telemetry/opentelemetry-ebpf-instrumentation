// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/h2_defs.h>

// Huffman traceparent values (RFC 7541 5.2), the encoding gRPC SDKs emit.
// Every [0-9a-f-] code is 5 or 6 bits, so six bits of lookahead name one character.
enum {
    // 55 characters at 5 bits, rounded up to octets
    k_h2_tp_huff_min = 35,
    // 55 characters at 6 bits, rounded up to octets
    k_h2_tp_huff_max = 42,
    // power of two to keep the index maskable; the zeroed tail keeps lookahead in range
    k_h2_tp_huff_window = 64,
    k_h2_tp_huff_mask = k_h2_tp_huff_window - 1,
    k_h2_tp_huff_lookahead = 6,
    // set in a table entry whose code is 6 bits wide
    k_h2_tp_huff_wide = 0x80,
    // smallest huffman field; scans bounded by the plain sizes would never reach one
    k_h2_tp_hpack_huff_min = k_hpack_tp_val_offset_huffman + k_h2_tp_huff_min,
    // widest value offset the scan can hand to the decode program
    k_h2_tp_huff_at_max = k_hpack_tp_max_scan + k_hpack_tp_val_offset,
};

// Decode table indexed by 6 bits of lookahead (RFC 7541 Appendix B). A 5-bit code fills
// two adjacent slots (one per value of the trailing don't-care bit) and stores its plain
// character; a 6-bit code fills one slot and is flagged k_h2_tp_huff_wide. 0 = no
// traceparent character starts with these bits; slot 0x3f is the EOS prefix, so EOS
// rejects here too.
static const u8 k_h2_tp_huff[64] = {
    0x30, 0x30, 0x31, 0x31, 0x32, 0x32, 0x61, 0x61, // '0' '1' '2' 'a'
    0x63, 0x63, 0x65, 0x65, 0x00, 0x00, 0x00, 0x00, // 'c' 'e'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xad, 0x00, // '-'
    0x00, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, // '3'..'9'
    0x00, 0x00, 0x00, 0xe2, 0xe4, 0xe6, 0x00, 0x00, // 'b' 'd' 'f'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Located but not decoded: the decode runs in its own tail-call program
enum {
    k_h2_huff_then_finalize = 0,
    k_h2_huff_then_commit = 1,
};

typedef struct h2_tp_huff_candidate {
    u16 at;  // offset of the value within the scanned block, bounded by k_hpack_tp_max_scan
    u8 len;  // encoded octets, 0 when the scan found none
    u8 next; // stage to resume, since both server scans can request a decode
} h2_tp_huff_candidate_t;

enum {
    // indexed fields commonly alias the plausible length range
    k_h2_tp_huff_max_candidates = 3,
};

typedef struct h2_tp_huff_scan {
    u16 at[k_h2_tp_huff_max_candidates];
    u8 len[k_h2_tp_huff_max_candidates];
    u8 count;
    u8 idx;
    u8 done;    // scan ran; retries walk the list
    u16 resume; // candidates at or before this offset were already rejected
    u8 _pad[2];
} h2_tp_huff_scan_t;

// True when a value length byte announces a huffman string that could hold a traceparent.
static __always_inline bool h2_tp_huff_len_plausible(u8 len_byte) {
    if (!(len_byte & k_hpack_huffman_flag)) {
        return false;
    }

    const u8 len = len_byte & (u8)~k_hpack_huffman_flag;

    return len >= k_h2_tp_huff_min && len <= k_h2_tp_huff_max;
}

// bpf_loop callback state; each step advances a data-dependent number of bits
typedef struct h2_huff_ctx {
    const unsigned char *w; // zeroed k_h2_tp_huff_window holding the encoded value
    unsigned char *out;     // receives one decoded character per step
    u32 bit;                // read cursor into w, in bits
    u32 invalid;            // count of lookups that named no traceparent character
} h2_huff_ctx_t;

// Decodes the i-th character: reads 6 bits at the cursor, looks up the character they
// name, and advances the cursor by the code's real width (5 bits, or 6 when the entry
// is flagged wide). Deliberately branch-free apart from the loop exit.
static int h2_huff_step(u32 i, void *vctx) {
    h2_huff_ctx_t *c = vctx;

    if (i >= k_hpack_value_len_tp) {
        return 1; // all 55 characters decoded, stop bpf_loop
    }

    // the 6 bits at the cursor straddle at most two bytes; the window is zero-padded
    // and mask-indexed, so reading past the encoded value is safe and yields zeros
    const u32 first_byte = (c->bit / 8) & k_h2_tp_huff_mask;
    const u32 bits_into_byte = c->bit % 8;
    const u32 two_bytes = ((u32)c->w[first_byte] << 8) | c->w[(first_byte + 1) & k_h2_tp_huff_mask];
    const u8 lookahead = (two_bytes >> (16 - k_h2_tp_huff_lookahead - bits_into_byte)) & 0x3f;

    const u8 entry = k_h2_tp_huff[lookahead];
    const u32 is_wide = (entry & k_h2_tp_huff_wide) != 0;

    c->out[i] = entry & (u8)~k_h2_tp_huff_wide;
    c->bit += 5U + is_wide;
    c->invalid += entry == 0;

    return 0;
}

// w is a zeroed k_h2_tp_huff_window holding len octets. Needs bpf_loop.
static __always_inline bool h2_huff_decode_tp(const unsigned char *w, u32 len, unsigned char *out) {
    if (len < k_h2_tp_huff_min || len > k_h2_tp_huff_max) {
        return false;
    }

    h2_huff_ctx_t c = {.w = w, .out = out, .bit = 0, .invalid = 0};
    bpf_loop(k_hpack_value_len_tp, h2_huff_step, &c, 0);

    if (c.invalid || (c.bit + 7) / 8 != len) {
        return false;
    }

    // RFC 7541 5.2: at most 7 bits of padding, carrying EOS's leading ones
    const u32 pad = len * 8 - c.bit;
    if (pad > 7) {
        return false;
    }
    if (pad) {
        const u8 pad_mask = (u8)((1U << pad) - 1);
        u32 last = len - 1;
        bpf_clamp_umax(last, k_h2_tp_huff_mask);
        if ((w[last] & pad_mask) != pad_mask) {
            return false;
        }
    }

    // the alphabet cannot produce a bad character, but it can produce a bad layout
    return out[0] == '0' && out[1] == '0' && out[k_tp_val_dash1] == '-' &&
           out[k_tp_val_dash2] == '-' && out[k_tp_val_dash3] == '-';
}
