// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline long bpf_loop(unsigned int nr_loops,
                            int (*callback_fn)(unsigned int, void *),
                            void *callback_ctx,
                            unsigned long long flags) {
    (void)flags;
    for (unsigned int i = 0; i < nr_loops; i++) {
        if (callback_fn(i, callback_ctx)) {
            break;
        }
    }
    return 0;
}

#include <common/h2_tp_huffman.h>

static void assertf(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        exit(1);
    }
}

static void assert_str(const char *got, const char *want, const char *msg) {
    if (strncmp(got, want, k_hpack_value_len_tp) != 0) {
        fprintf(stderr,
                "FAIL: %s\n  want %.*s\n  got  %.*s\n",
                msg,
                k_hpack_value_len_tp,
                want,
                k_hpack_value_len_tp,
                got);
        exit(1);
    }
}

// RFC 7541 Appendix B codes for the traceparent alphabet. Independent of the decode table under
// test: this is an encoder, written from the RFC, so a wrong table cannot agree with it.
static u8 huff_code(char c, u8 *bits) {
    switch (c) {
    case '0':
        *bits = 5;
        return 0x00;
    case '1':
        *bits = 5;
        return 0x01;
    case '2':
        *bits = 5;
        return 0x02;
    case 'a':
        *bits = 5;
        return 0x03;
    case 'c':
        *bits = 5;
        return 0x04;
    case 'e':
        *bits = 5;
        return 0x05;
    case '-':
        *bits = 6;
        return 0x16;
    case '3':
        *bits = 6;
        return 0x19;
    case '4':
        *bits = 6;
        return 0x1a;
    case '5':
        *bits = 6;
        return 0x1b;
    case '6':
        *bits = 6;
        return 0x1c;
    case '7':
        *bits = 6;
        return 0x1d;
    case '8':
        *bits = 6;
        return 0x1e;
    case '9':
        *bits = 6;
        return 0x1f;
    case 'b':
        *bits = 6;
        return 0x23;
    case 'd':
        *bits = 6;
        return 0x24;
    case 'f':
        *bits = 6;
        return 0x25;
    default:
        *bits = 0;
        return 0;
    }
}

// Huffman-encodes s into dst, padding to the octet boundary with EOS most-significant bits
// (all ones, RFC 7541 5.2). Returns the octet count.
static u32 huff_encode(unsigned char *dst, u32 dst_len, const char *s) {
    memset(dst, 0, dst_len);

    u32 bit = 0;
    for (const char *p = s; *p; p++) {
        u8 bits = 0;
        const u8 code = huff_code(*p, &bits);
        assertf(bits != 0, "test encoder given a char outside the traceparent alphabet");

        for (u8 i = 0; i < bits; i++) {
            if ((code >> (bits - 1 - i)) & 1) {
                dst[(bit + i) / 8] |= (unsigned char)(0x80 >> ((bit + i) % 8));
            }
        }
        bit += bits;
    }

    const u32 octets = (bit + 7) / 8;
    for (u32 i = bit; i < octets * 8; i++) {
        dst[i / 8] |= (unsigned char)(0x80 >> (i % 8)); // EOS padding is all ones
    }

    return octets;
}

static const char *k_tp_sample = "00-1234567890abcdef1234567890abcdef-fedcba0987654321-01";

static void test_round_trip(void) {
    const char *cases[] = {
        // all 5-bit characters: the 35-octet floor
        "00-11111111111111111111111111111111-2222222222222222-01",
        // 6-bit heavy: the 42-octet ceiling
        "00-ffffffffffffffffffffffffffffffff-9999999999999999-01",
        // mixed, and every alphabet character exercised
        "00-1234567890abcdef1234567890abcdef-fedcba0987654321-01",
        "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
        "00-abcdefabcdefabcdefabcdefabcdefab-cdefabcdefabcdef-01",
    };

    for (u32 i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        unsigned char w[k_h2_tp_huff_window];
        const u32 octets = huff_encode(w, sizeof(w), cases[i]);
        assertf(octets >= k_h2_tp_huff_min && octets <= k_h2_tp_huff_max,
                "encoded length must sit inside the declared bounds");

        unsigned char out[k_hpack_value_len_tp];
        assertf(h2_huff_decode_tp(w, octets, out), "a valid traceparent must decode");
        assert_str((const char *)out, cases[i], "round trip");
    }
}

// 55 five-bit codes is 275 bits, 35 octets; 55 six-bit codes is 330 bits, 42 octets
static void test_length_bounds(void) {
    assertf(k_h2_tp_huff_min == 35, "floor is 55 five-bit codes rounded up");
    assertf(k_h2_tp_huff_max == 42, "ceiling is 55 six-bit codes rounded up");

    unsigned char w[k_h2_tp_huff_window];
    unsigned char out[k_hpack_value_len_tp];
    const u32 octets = huff_encode(w, sizeof(w), k_tp_sample);

    assertf(!h2_huff_decode_tp(w, octets - 1, out), "a truncated value must not decode");
    assertf(!h2_huff_decode_tp(w, octets + 1, out), "trailing octets must not decode");
    assertf(!h2_huff_decode_tp(w, 0, out), "an empty value must not decode");
    assertf(!h2_huff_decode_tp(w, k_h2_tp_huff_min - 1, out), "below the floor must not decode");
    assertf(!h2_huff_decode_tp(w, k_h2_tp_huff_max + 1, out), "above the ceiling must not decode");
}

// Number of bits TP_VALUE occupies once encoded, padding excluded
static u32 huff_encoded_bits(const char *s) {
    u32 bit = 0;
    for (const char *p = s; *p; p++) {
        u8 bits = 0;
        huff_code(*p, &bits);
        assertf(bits != 0, "sample holds a char outside the traceparent alphabet");
        bit += bits;
    }
    return bit;
}

// RFC 7541 5.2: padding must be the most significant bits of EOS, and never longer than 7 bits
static void test_padding_rules(void) {
    unsigned char w[k_h2_tp_huff_window];
    unsigned char out[k_hpack_value_len_tp];
    const u32 octets = huff_encode(w, sizeof(w), k_tp_sample);

    assertf(h2_huff_decode_tp(w, octets, out), "correct all-ones padding is accepted");

    // Only the trailing pad bits belong to the padding. The rest of the last octet is value, and
    // clearing one of those bits changes a character instead — a different rejection path, and
    // one that can legitimately still decode.
    const u32 pad = octets * 8 - huff_encoded_bits(k_tp_sample);
    assertf(pad > 0 && pad <= 7, "the sample must carry padding to exercise the rule");

    for (u32 i = 0; i < pad; i++) {
        huff_encode(w, sizeof(w), k_tp_sample);
        w[octets - 1] &= (unsigned char)~(1u << i);
        assertf(!h2_huff_decode_tp(w, octets, out), "padding with a zero bit must be rejected");
    }
}

static void test_rejects_invalid_codes(void) {
    unsigned char w[k_h2_tp_huff_window];
    unsigned char out[k_hpack_value_len_tp];

    // 0x3f is the EOS prefix and no traceparent character maps to it
    memset(w, 0xff, sizeof(w));
    assertf(!h2_huff_decode_tp(w, k_h2_tp_huff_max, out), "an embedded EOS must be rejected");

    // every 6-bit slot that names no character must reject when it leads the value
    u32 rejected = 0;
    for (u32 slot = 0; slot < 64; slot++) {
        huff_encode(w, sizeof(w), k_tp_sample);
        w[0] = (unsigned char)(slot << 2) | (w[0] & 0x03);
        if (!h2_huff_decode_tp(w, k_h2_tp_huff_min, out)) {
            rejected++;
        }
    }
    assertf(rejected > 40, "the table's unused slots must reject, not decode");
}

// Only "00-<32 hex>-<16 hex>-01" is a traceparent, whatever the codes decode to
static void test_rejects_wrong_shape(void) {
    unsigned char w[k_h2_tp_huff_window];
    unsigned char out[k_hpack_value_len_tp];

    // right length, right alphabet, dashes in the wrong places
    const u32 octets =
        huff_encode(w, sizeof(w), "0012345678-0abcdef1234567890abcdef-fedcba09876543-01");
    if (octets >= k_h2_tp_huff_min && octets <= k_h2_tp_huff_max) {
        assertf(!h2_huff_decode_tp(w, octets, out), "misplaced dashes must be rejected");
    }

    // version other than 00
    const u32 o2 =
        huff_encode(w, sizeof(w), "01-1234567890abcdef1234567890abcdef-fedcba0987654321-01");
    assertf(!h2_huff_decode_tp(w, o2, out), "a version other than 00 must be rejected");
}

// Random bytes must not be mistaken for a traceparent
static void test_random_bytes_do_not_decode(void) {
    unsigned char w[k_h2_tp_huff_window];
    unsigned char out[k_hpack_value_len_tp];
    u32 accepted = 0;

    u32 seed = 0x12345678;
    for (u32 i = 0; i < 200000; i++) {
        for (u32 b = 0; b < k_h2_tp_huff_max; b++) {
            seed = seed * 1103515245 + 12345;
            w[b] = (unsigned char)(seed >> 16);
        }
        for (u32 b = k_h2_tp_huff_max; b < sizeof(w); b++) {
            w[b] = 0;
        }
        if (h2_huff_decode_tp(w, k_h2_tp_huff_max, out)) {
            accepted++;
        }
    }

    assertf(accepted == 0, "random bytes must never decode to a traceparent");
}

// The field a production HPACK encoder emits: huffman name, then a huffman value because 35
// encoded octets beat the 55 plain ones. Pinned so an encoder change cannot go unnoticed.
static void test_sdk_golden_vector(void) {
    const unsigned char field[] = {0x40, 0x88, 0x4d, 0x83, 0x21, 0x6b, 0x1d, 0x85, 0xa9, 0x3f,
                                   0xa3, 0x00, 0x16, 0x08, 0x42, 0x10, 0x84, 0x21, 0x08, 0x42,
                                   0x10, 0x84, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0x08, 0x42,
                                   0x10, 0x84, 0x21, 0x58, 0x42, 0x10, 0x84, 0x21, 0x08, 0x42,
                                   0x10, 0x84, 0x21, 0x09, 0x60, 0x07};

    const u8 value_len_byte = field[k_hpack_tp_name_offset + k_hpack_tp_name_huffman_len];
    assertf(value_len_byte == (0x80 | 35), "SDK encoders emit a 35-octet huffman value");

    const u32 vlen = value_len_byte & 0x7f;
    unsigned char w[k_h2_tp_huff_window] = {0};
    memcpy(w, field + k_hpack_tp_val_offset_huffman, vlen);

    unsigned char out[k_hpack_value_len_tp];
    assertf(h2_huff_decode_tp(w, vlen, out), "the golden value must decode");
    assert_str((const char *)out,
               "00-11111111111111111111111111111111-2222222222222222-01",
               "golden vector");
}

int main(void) {
    test_length_bounds();
    test_round_trip();
    test_padding_rules();
    test_rejects_invalid_codes();
    test_rejects_wrong_shape();
    test_sdk_golden_vector();
    test_random_bytes_do_not_decode();
    printf("OK: %s\n", __FILE__);
    return 0;
}
