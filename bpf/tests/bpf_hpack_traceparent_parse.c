// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline unsigned int bpf_get_prandom_u32(void) {
    return 0;
}

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

#include <generictracer/hpack_traceparent_parse.h>

// W3C v0 fixture value
static const unsigned char TP_VALUE[k_hpack_value_len_tp + 1] =
    "00-0123456789abcdeffedcba9876543210-89abcdef01234567-01";

static const unsigned char EXPECTED_TRACE_ID[TRACE_ID_SIZE_BYTES] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
static const unsigned char EXPECTED_PARENT_ID[SPAN_ID_SIZE_BYTES] = {
    0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67};

// decode scratch; the BPF program passes per-CPU map values here instead
static unsigned char HUFF_W[k_h2_tp_huff_window];
static unsigned char HUFF_OUT[k_hpack_value_len_tp];

static void assertf(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        exit(1);
    }
}

static void assert_tp_match(const tp_info_t *tp) {
    assertf(memcmp(tp->trace_id, EXPECTED_TRACE_ID, TRACE_ID_SIZE_BYTES) == 0, "trace_id mismatch");
    assertf(memcmp(tp->parent_id, EXPECTED_PARENT_ID, SPAN_ID_SIZE_BYTES) == 0,
            "parent_id mismatch");
    assertf(tp->flags == 1, "flags != 1");
}

// 0x00 + 0x0b + "traceparent" + 0x37 + value
static u32 build_plain_entry(unsigned char *dst) {
    dst[0] = k_hpack_literal_no_index;
    dst[1] = k_hpack_tp_name_len;
    memcpy(&dst[2], "traceparent", 11);
    dst[13] = k_hpack_value_len_tp;
    memcpy(&dst[14], TP_VALUE, k_hpack_value_len_tp);
    return k_h2_tp_hpack_size;
}

// 0x00 + 0x88 + huffman("traceparent") + 0x37 + value
static u32 build_huffman_entry(unsigned char *dst) {
    dst[0] = k_hpack_literal_no_index;
    dst[1] = (unsigned char)(k_hpack_tp_name_huffman_len | 0x80);
    memcpy(&dst[2], k_hpack_tp_huffman, k_hpack_tp_name_huffman_len);
    dst[10] = k_hpack_value_len_tp;
    memcpy(&dst[11], TP_VALUE, k_hpack_value_len_tp);
    return k_h2_tp_hpack_huffman_size;
}

// 0x37 + value only (as if HPACK name were emitted as a dyn-table index)
static u32 build_value_only(unsigned char *dst) {
    dst[0] = k_hpack_value_len_tp;
    memcpy(&dst[1], TP_VALUE, k_hpack_value_len_tp);
    return 1 + k_hpack_value_len_tp;
}

// Huffman-encodes TP_VALUE into dst per RFC 7541 5.2, all-ones EOS padding. Encoder written
// from Appendix B so it cannot agree with a wrong decode table.
static u32 huff_encode_tp_value(unsigned char *dst) {
    static const struct {
        char c;
        u8 code;
        u8 bits;
    } k_codes[] = {
        {'0', 0x00, 5},
        {'1', 0x01, 5},
        {'2', 0x02, 5},
        {'a', 0x03, 5},
        {'c', 0x04, 5},
        {'e', 0x05, 5},
        {'-', 0x16, 6},
        {'3', 0x19, 6},
        {'4', 0x1a, 6},
        {'5', 0x1b, 6},
        {'6', 0x1c, 6},
        {'7', 0x1d, 6},
        {'8', 0x1e, 6},
        {'9', 0x1f, 6},
        {'b', 0x23, 6},
        {'d', 0x24, 6},
        {'f', 0x25, 6},
    };

    u32 bit = 0;
    for (u32 i = 0; i < k_hpack_value_len_tp; i++) {
        u8 code = 0, bits = 0;
        for (u32 k = 0; k < sizeof(k_codes) / sizeof(k_codes[0]); k++) {
            if (k_codes[k].c == (char)TP_VALUE[i]) {
                code = k_codes[k].code;
                bits = k_codes[k].bits;
                break;
            }
        }
        assertf(bits != 0, "fixture holds a char outside the traceparent alphabet");

        for (u8 b = 0; b < bits; b++) {
            if ((code >> (bits - 1 - b)) & 1) {
                dst[(bit + b) / 8] |= (unsigned char)(0x80 >> ((bit + b) % 8));
            }
        }
        bit += bits;
    }

    const u32 octets = (bit + 7) / 8;
    for (u32 i = bit; i < octets * 8; i++) {
        dst[i / 8] |= (unsigned char)(0x80 >> (i % 8));
    }

    return octets;
}

// What gRPC SDKs emit: the value compresses below its 55 plain octets
static u32 build_plain_name_huffman_value(unsigned char *dst) {
    dst[0] = k_hpack_literal_no_index;
    dst[1] = k_hpack_tp_name_len;
    memcpy(&dst[2], "traceparent", 11);
    const u32 vlen = huff_encode_tp_value(&dst[14]);
    dst[13] = (unsigned char)(0x80 | vlen);
    return 14 + vlen;
}

static u32 build_huffman_name_huffman_value(unsigned char *dst) {
    dst[0] = k_hpack_literal_no_index;
    dst[1] = (unsigned char)(k_hpack_tp_name_huffman_len | 0x80);
    memcpy(&dst[2], k_hpack_tp_huffman, k_hpack_tp_name_huffman_len);
    const u32 vlen = huff_encode_tp_value(&dst[11]);
    dst[10] = (unsigned char)(0x80 | vlen);
    return 11 + vlen;
}

static void test_plain_name_huffman_value(void) {
    unsigned char buf[k_kprobes_http2_buf_size] = {0};
    const u32 len = build_plain_name_huffman_value(buf);
    tp_info_t tp = {0};
    h2_tp_huff_candidate_t huff = {0};
    assertf(parse_hpack_traceparent(buf, len, &tp, &huff) == 0, "scan reports, does not decode");
    assertf(huff.len != 0, "the scan must locate the compressed value");
    assertf(try_parse_tp_huffman_value(buf, len, &huff, HUFF_W, HUFF_OUT, &tp) == 1,
            "plain name, huffman value");
    assert_tp_match(&tp);
}

static void test_huffman_name_huffman_value(void) {
    unsigned char buf[k_kprobes_http2_buf_size] = {0};
    const u32 len = build_huffman_name_huffman_value(buf);
    tp_info_t tp = {0};
    h2_tp_huff_candidate_t huff = {0};
    assertf(parse_hpack_traceparent(buf, len, &tp, &huff) == 0, "scan reports, does not decode");
    assertf(huff.len != 0, "the scan must locate the compressed value");
    assertf(try_parse_tp_huffman_value(buf, len, &huff, HUFF_W, HUFF_OUT, &tp) == 1,
            "huffman name, huffman value");
    assert_tp_match(&tp);
}

// A huffman value the decoder rejects must not be reported as a traceparent. Padding rules have
// their own coverage in bpf_h2_tp_huffman; what matters here is that the failure propagates.
static void test_corrupt_huffman_value_rejected(void) {
    unsigned char buf[k_kprobes_http2_buf_size] = {0};
    const u32 len = build_huffman_name_huffman_value(buf);

    // six leading one-bits are the EOS prefix, which names no character
    buf[k_hpack_tp_val_offset_huffman] = 0xfc;

    tp_info_t tp = {0};
    h2_tp_huff_candidate_t huff = {0};
    assertf(parse_hpack_traceparent(buf, len, &tp, &huff) == 0, "scan reports the candidate");
    assertf(try_parse_tp_huffman_value(buf, len, &huff, HUFF_W, HUFF_OUT, &tp) == 0,
            "corrupt huffman value rejected");
}

// Every literal prefix, with the compressed value shape
static void test_huffman_value_every_prefix(void) {
    const unsigned char prefixes[] = {
        k_hpack_literal_no_index, k_hpack_literal_never_index, k_hpack_literal_incr_index};

    for (u32 i = 0; i < sizeof(prefixes); i++) {
        unsigned char buf[k_kprobes_http2_buf_size] = {0};
        const u32 len = build_huffman_name_huffman_value(buf);
        buf[0] = prefixes[i];

        tp_info_t tp = {0};
        h2_tp_huff_candidate_t huff = {0};
        assertf(parse_hpack_traceparent(buf, len, &tp, &huff) == 0, "scan reports the candidate");
        assertf(try_parse_tp_huffman_value(buf, len, &huff, HUFF_W, HUFF_OUT, &tp) == 1,
                "any literal prefix");
        assert_tp_match(&tp);
    }
}

static void test_plain_name_baseline(void) {
    unsigned char buf[k_kprobes_http2_buf_size] = {0};
    const u32 len = build_plain_entry(buf);
    tp_info_t tp = {0};
    h2_tp_huff_candidate_t huff = {0};
    assertf(parse_hpack_traceparent(buf, len, &tp, &huff) == 1, "plain name parse");
    assert_tp_match(&tp);
}

static void test_huffman_name_baseline(void) {
    unsigned char buf[k_kprobes_http2_buf_size] = {0};
    const u32 len = build_huffman_entry(buf);
    tp_info_t tp = {0};
    h2_tp_huff_candidate_t huff = {0};
    assertf(parse_hpack_traceparent(buf, len, &tp, &huff) == 1, "huffman name parse");
    assert_tp_match(&tp);
}

// senders that index the name they just sent, and never-indexed fields, both occur
static void test_every_literal_prefix(void) {
    const unsigned char prefixes[] = {
        k_hpack_literal_no_index, k_hpack_literal_never_index, k_hpack_literal_incr_index};

    for (u32 i = 0; i < sizeof(prefixes); i++) {
        unsigned char buf[k_kprobes_http2_buf_size] = {0};
        u32 len = build_plain_entry(buf);
        buf[0] = prefixes[i];
        tp_info_t tp = {0};
        h2_tp_huff_candidate_t huff = {0};
        assertf(parse_hpack_traceparent(buf, len, &tp, &huff) == 1,
                "plain name, any literal prefix");
        assert_tp_match(&tp);

        memset(buf, 0, sizeof(buf));
        len = build_huffman_entry(buf);
        buf[0] = prefixes[i];
        memset(&tp, 0, sizeof(tp));
        assertf(parse_hpack_traceparent(buf, len, &tp, &huff) == 1,
                "huffman name, any literal prefix");
        assert_tp_match(&tp);
    }
}

// Prefix mimicking an indexed-name-literal (no visible name literal on wire)
static void test_indexed_name_via_value_pattern(void) {
    unsigned char buf[k_kprobes_http2_buf_size] = {0};
    buf[0] = 0x1F;
    buf[1] = 0x2F;
    buf[2] = k_hpack_value_len_tp;
    memcpy(&buf[3], TP_VALUE, k_hpack_value_len_tp);
    tp_info_t tp = {0};
    assertf(find_hpack_traceparent_value(buf, 3 + k_hpack_value_len_tp, &tp) == 1,
            "indexed-name via value scan");
    assert_tp_match(&tp);
}

static void test_value_pattern_at_offset(void) {
    unsigned char buf[k_kprobes_http2_buf_size] = {0};
    for (u32 i = 0; i < 32; i++)
        buf[i] = (unsigned char)(i | 0x40);
    const u32 len = 32 + build_value_only(&buf[32]);
    tp_info_t tp = {0};
    assertf(find_hpack_traceparent_value(buf, len, &tp) == 1, "offset value scan");
    assert_tp_match(&tp);
}

static void test_no_false_positive_random(void) {
    unsigned char buf[k_kprobes_http2_buf_size];
    for (u32 i = 0; i < sizeof(buf); i++)
        buf[i] = (unsigned char)((i * 17) ^ 0x5A);
    tp_info_t tp = {0};
    assertf(find_hpack_traceparent_value(buf, sizeof(buf), &tp) == 0,
            "random buffer no false positive");
}

// Dashes at expected positions but "00-" version prefix fails — must reject via value scan
static void test_reject_dash_lookalike(void) {
    unsigned char buf[k_kprobes_http2_buf_size] = {0};
    buf[0] = k_hpack_value_len_tp;
    buf[1] = 'x';
    buf[2] = 'x';
    buf[3] = '-';
    for (u32 i = 0; i < 32; i++)
        buf[4 + i] = '0';
    buf[36] = '-';
    for (u32 i = 0; i < 16; i++)
        buf[37 + i] = '0';
    buf[53] = '-';
    buf[54] = 'z';
    buf[55] = 'z';
    tp_info_t tp = {0};
    assertf(find_hpack_traceparent_value(buf, 1 + k_hpack_value_len_tp, &tp) == 0,
            "dash-lookalike no false positive");
}

static void test_value_at_late_position(void) {
    unsigned char buf[k_kprobes_http2_buf_size] = {0};
    const u32 offset = k_kprobes_http2_buf_size - (1 + k_hpack_value_len_tp);
    for (u32 i = 0; i < offset; i++)
        buf[i] = (unsigned char)((i * 13) & 0x2F);
    const u32 len = offset + build_value_only(&buf[offset]);
    tp_info_t tp = {0};
    assertf(find_hpack_traceparent_value(buf, len, &tp) == 1,
            "traceparent at end of window parses");
    assert_tp_match(&tp);
}

// Correct length byte, "00-" prefix and dashes, but non-hex chars at spot-checked id edges
static void test_reject_non_hex_ids(void) {
    unsigned char buf[k_kprobes_http2_buf_size] = {0};
    buf[0] = k_hpack_value_len_tp;
    memcpy(&buf[1], TP_VALUE, k_hpack_value_len_tp);
    buf[1 + k_tp_val_trace_id_start] = 'g';
    tp_info_t tp = {0};
    assertf(find_hpack_traceparent_value(buf, 1 + k_hpack_value_len_tp, &tp) == 0,
            "non-hex trace id edge rejected");

    memcpy(&buf[1], TP_VALUE, k_hpack_value_len_tp);
    buf[1 + k_tp_val_dash3 - 1] = ' ';
    assertf(find_hpack_traceparent_value(buf, 1 + k_hpack_value_len_tp, &tp) == 0,
            "non-hex span id edge rejected");
}

// Decoy 0x37+"00-" hits with non-hex ids before the real value — scan must skip and continue
static void test_decoys_before_real_value(void) {
    unsigned char buf[k_kprobes_http2_buf_size] = {0};
    u32 off = 0;
    for (u32 d = 0; d < 3; d++) {
        buf[off] = k_hpack_value_len_tp;
        buf[off + 1] = '0';
        buf[off + 2] = '0';
        buf[off + 3] = '-';
        memset(&buf[off + 4], 'x', 8);
        off += 12;
    }
    const u32 len = off + build_value_only(&buf[off]);
    tp_info_t tp = {0};
    assertf(find_hpack_traceparent_value(buf, len, &tp) == 1, "real value found after decoys");
    assert_tp_match(&tp);
}

static void test_short_buffer(void) {
    unsigned char buf[k_h2_tp_hpack_huffman_size - 1] = {0};
    tp_info_t tp = {0};
    h2_tp_huff_candidate_t huff = {0};
    assertf(parse_hpack_traceparent(buf, sizeof(buf), &tp, &huff) == 0, "short buffer rejected");
}

// Requests 2+ on a persistent connection index the name, so a compressed value leaves nothing to
// fingerprint. The value-only scan reports it and the decode decides.
static void test_indexed_name_huffman_value(void) {
    unsigned char buf[k_kprobes_http2_buf_size] = {0};
    buf[0] = 0x5e; // literal, incremental indexing, name index 30
    const u32 vlen = huff_encode_tp_value(&buf[2]);
    buf[1] = (unsigned char)(0x80 | vlen);

    tp_info_t tp = {0};
    h2_tp_huff_scan_t scan = {0};
    assertf(find_hpack_traceparent_huffman(buf, 0, 2 + vlen, &scan) == 1, "sweep locates it");
    assertf(scan.count == 1, "one candidate");
    assertf(scan.len[0] == vlen, "the scan must locate the compressed value");

    h2_tp_huff_candidate_t huff = {.at = scan.at[0], .len = scan.len[0]};
    assertf(try_parse_tp_huffman_value(buf, 2 + vlen, &huff, HUFF_W, HUFF_OUT, &tp) == 1,
            "indexed name, huffman value");
    assert_tp_match(&tp);
}

// 0xa5 (indexed field, dyn index 37) aliases a plausible length before the real value
// Indexed fields like 0xa5 (dyn index 37) alias plausible length bytes. Three of
// them fill the candidate list, so reaching the real value needs a rescan past
// the rejected candidates, mirroring the tail-call retry loop
static void test_decoy_candidates_before_real_value(void) {
    unsigned char buf[k_kprobes_http2_buf_size] = {0};
    buf[0] = 0xa5;
    buf[1] = 0xa6;
    buf[2] = 0xa7;
    buf[40] = 0x5e;
    const u32 vlen = huff_encode_tp_value(&buf[42]);
    buf[41] = (unsigned char)(0x80 | vlen);
    const u32 total = 42 + vlen;

    tp_info_t tp = {0};
    h2_tp_huff_scan_t scan = {0};
    u8 decoded = 0;
    u8 rescans = 0;

    while (find_hpack_traceparent_huffman(buf, 0, total, &scan)) {
        for (u8 i = 0; i < scan.count && !decoded; i++) {
            h2_tp_huff_candidate_t huff = {.at = scan.at[i], .len = scan.len[i]};
            decoded = try_parse_tp_huffman_value(buf, total, &huff, HUFF_W, HUFF_OUT, &tp);
        }
        if (decoded || scan.count < k_h2_tp_huff_max_candidates) {
            break;
        }
        scan.resume = scan.at[k_h2_tp_huff_max_candidates - 1];
        rescans++;
    }

    assertf(rescans >= 1, "three decoys must force a rescan");
    assertf(decoded == 1, "the rescan must reach the real value");
    assert_tp_match(&tp);
}

// A plain traceparent must win even when a plausible huffman length byte sits earlier
static void test_plain_value_wins_over_huffman_lookalike(void) {
    unsigned char buf[k_kprobes_http2_buf_size] = {0};
    buf[0] = 0xa5; // plausible huffman length, but random bytes follow
    for (u32 i = 1; i < 40; i++) {
        buf[i] = (unsigned char)(i * 7);
    }
    const u32 n = 40 + build_value_only(&buf[40]);

    tp_info_t tp = {0};
    assertf(find_hpack_traceparent_value(buf, n, &tp) == 1, "plain value still found");
    assert_tp_match(&tp);
}

int main(void) {
    test_plain_name_baseline();
    test_huffman_name_baseline();
    test_plain_name_huffman_value();
    test_indexed_name_huffman_value();
    test_decoy_candidates_before_real_value();
    test_plain_value_wins_over_huffman_lookalike();
    test_huffman_name_huffman_value();
    test_huffman_value_every_prefix();
    test_corrupt_huffman_value_rejected();
    test_every_literal_prefix();
    test_indexed_name_via_value_pattern();
    test_value_pattern_at_offset();
    test_no_false_positive_random();
    test_reject_dash_lookalike();
    test_reject_non_hex_ids();
    test_decoys_before_real_value();
    test_value_at_late_position();
    test_short_buffer();
    printf("OK: %s\n", __FILE__);
    return 0;
}
