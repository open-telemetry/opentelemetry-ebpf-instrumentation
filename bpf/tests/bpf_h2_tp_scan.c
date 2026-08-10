// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/h2_tp_scan.h>

typedef struct h2_tp_scan_result {
    u32 offset;     // adoptable offset, or k_h2_max_hpack_scan
    bool present;   // a traceparent in an encoding OBI cannot adopt
    bool exhausted; // retry budget ran out before the block was fully walked
} h2_tp_scan_result_t;

// Mirrors the find_existing_h2_tp / validate_h2_tp tail-call ping-pong over a plain buffer.
// Models its retry cap too, or tests would pass for blocks where the real chain gives up and
// injects a duplicate.
static h2_tp_scan_result_t h2_tp_scan(const unsigned char *data, u32 len, u32 max_scan) {
    h2_tp_scan_result_t r = {.offset = max_scan};
    u32 start = 0;
    u32 retries = 0;

    for (;;) {
        u32 cand = max_scan;

        for (u32 i = start; i < max_scan; i++) {
            if (i + k_h2_tp_need_name_huffman > len) {
                break;
            }
            if (h2_tp_is_candidate(data[i], data[i + 1], data[i + 2])) {
                cand = i;
                break;
            }
        }

        if (cand >= max_scan) {
            return r;
        }

        const unsigned char *p = data + cand;
        const h2_tp_kind_t kind = h2_tp_classify(p, data + len);

        if (kind == k_h2_tp_adoptable) {
            r.offset = cand;
            return r;
        }
        if (kind == k_h2_tp_present) {
            r.present = true;
            return r;
        }

        const u32 next = cand + 1;
        if (next >= max_scan) {
            return r;
        }
        if (retries + 1 >= k_h2_max_tp_retries) {
            r.exhausted = true;
            return r;
        }

        retries++;
        start = next;
    }
}

static void assertf(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        exit(1);
    }
}

static const unsigned char k_tp_huffman_name[] = {0x4d, 0x83, 0x21, 0x6b, 0x1d, 0x85, 0xa9, 0x3f};

static const char k_tp_value[] = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

// Leading pseudo-headers, so the traceparent never sits at offset 0
static u32 preamble(unsigned char *dst) {
    const unsigned char bytes[] = {0x83, 0x86, 0x44, 0x04, '/', 'a', '/', 'b'};
    memcpy(dst, bytes, sizeof(bytes));
    return sizeof(bytes);
}

// literal(prefix) + plain name + plain value: what OBI writes
static u32 field_plain(unsigned char *dst, u32 off, u8 prefix) {
    dst[off++] = prefix;
    dst[off++] = k_hpack_tp_name_len;
    memcpy(dst + off, "traceparent", k_hpack_tp_name_len);
    off += k_hpack_tp_name_len;
    dst[off++] = k_hpack_value_len_tp;
    memcpy(dst + off, k_tp_value, k_hpack_value_len_tp);
    return off + k_hpack_value_len_tp;
}

// literal(prefix) + huffman name + huffman value
static u32 field_huffman_value(unsigned char *dst, u32 off, u8 prefix) {
    const u8 encoded_len = 37;
    dst[off++] = prefix;
    dst[off++] = k_h2_nlb_huffman;
    memcpy(dst + off, k_tp_huffman_name, sizeof(k_tp_huffman_name));
    off += sizeof(k_tp_huffman_name);
    dst[off++] = 0x80 | encoded_len;
    memset(dst + off, 0x63, encoded_len);
    return off + encoded_len;
}

// indexed name reference + plain value: requests 2+ once the name is in the dyn table
static u32 field_indexed_name(unsigned char *dst, u32 off) {
    dst[off++] = 0x5e; // literal, incremental indexing, name index 30
    dst[off++] = k_hpack_value_len_tp;
    memcpy(dst + off, k_tp_value, k_hpack_value_len_tp);
    return off + k_hpack_value_len_tp;
}

// indexed name reference + huffman value: nothing identifying is left on the wire
static u32 field_indexed_name_huffman_value(unsigned char *dst, u32 off) {
    const u8 encoded_len = 37;
    dst[off++] = 0x5e;
    dst[off++] = 0x80 | encoded_len;
    memset(dst + off, 0x63, encoded_len);
    return off + encoded_len;
}

// literal with a new name of the given length: a decoy for the candidate prefilter
static u32 field_named(unsigned char *dst, u32 off, const char *name, const char *value) {
    const u32 nlen = (u32)strlen(name);
    const u32 vlen = (u32)strlen(value);
    dst[off++] = k_hpack_literal_incr_index;
    dst[off++] = (u8)nlen;
    memcpy(dst + off, name, nlen);
    off += nlen;
    dst[off++] = (u8)vlen;
    memcpy(dst + off, value, vlen);
    return off + vlen;
}

static void test_adoptable(void) {
    unsigned char buf[512] = {0};

    u32 n = preamble(buf);
    const u32 at = n;
    n = field_plain(buf, n, k_hpack_literal_no_index);
    assertf(h2_tp_scan(buf, n, k_h2_max_hpack_scan).offset == at, "plain value adopted");

    for (u32 i = 0; i < 3; i++) {
        const u8 prefixes[] = {
            k_hpack_literal_no_index, k_hpack_literal_never_index, k_hpack_literal_incr_index};
        memset(buf, 0, sizeof(buf));
        n = field_plain(buf, preamble(buf), prefixes[i]);
        assertf(h2_tp_scan(buf, n, k_h2_max_hpack_scan).offset < k_h2_max_hpack_scan,
                "every literal prefix is adopted");
    }
}

static void test_present_but_not_adoptable(void) {
    unsigned char buf[512];
    u32 n;
    h2_tp_scan_result_t r;

    // grpc-js: incremental indexing, huffman name, huffman value
    memset(buf, 0, sizeof(buf));
    n = field_huffman_value(buf, preamble(buf), k_hpack_literal_incr_index);
    r = h2_tp_scan(buf, n, k_h2_max_hpack_scan);
    assertf(r.offset == k_h2_max_hpack_scan, "huffman value is not adoptable");
    assertf(r.present, "huffman value counts as present");

    // requests 2+ on a persistent conn: name comes from the dynamic table
    memset(buf, 0, sizeof(buf));
    n = field_indexed_name(buf, preamble(buf));
    r = h2_tp_scan(buf, n, k_h2_max_hpack_scan);
    assertf(r.offset == k_h2_max_hpack_scan, "indexed name is not adoptable");
    assertf(r.present, "indexed name counts as present");

    // Dyn-table name plus a compressed value leaves nothing to match, which is precisely why
    // the socket flag exists: the encoder could only build that index from a block whose name
    // was on the wire, and that block set the flag.
    memset(buf, 0, sizeof(buf));
    n = field_indexed_name_huffman_value(buf, preamble(buf));
    r = h2_tp_scan(buf, n, k_h2_max_hpack_scan);
    assertf(r.offset == k_h2_max_hpack_scan, "indexed name + huffman value is not adoptable");
    assertf(!r.present, "no content match is possible once both name and value are compressed");
}

// The exact field golang.org/x/net/http2/hpack emits for a traceparent: huffman name, then a
// huffman value, because the encoded value is shorter than the 55 plain bytes. Pinned as a
// golden vector so an encoder change cannot silently stop matching.
static void test_x_net_encoded_traceparent(void) {
    const unsigned char field[] = {0x40, 0x88, 0x4d, 0x83, 0x21, 0x6b, 0x1d, 0x85, 0xa9, 0x3f,
                                   0xa3, 0x00, 0x16, 0x08, 0x42, 0x10, 0x84, 0x21, 0x08, 0x42,
                                   0x10, 0x84, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0x08, 0x42,
                                   0x10, 0x84, 0x21, 0x58, 0x42, 0x10, 0x84, 0x21, 0x08, 0x42,
                                   0x10, 0x84, 0x21, 0x09, 0x60, 0x07};

    assertf(h2_tp_is_candidate(field[0], field[1], field[2]), "x/net field is a candidate");
    assertf(h2_tp_classify(field, field + sizeof(field)) == k_h2_tp_present,
            "x/net field is present but not adoptable");

    unsigned char buf[512] = {0};
    u32 n = preamble(buf);
    memcpy(buf + n, field, sizeof(field));
    n += sizeof(field);

    const h2_tp_scan_result_t r = h2_tp_scan(buf, n, k_h2_max_hpack_scan);
    assertf(r.offset == k_h2_max_hpack_scan, "a huffman value cannot be adopted");
    assertf(r.present, "the scan must still see it and suppress a second traceparent");
}

static void test_no_traceparent(void) {
    unsigned char buf[512];

    // ordinary gRPC headers, plus a value that merely contains "00-"
    const char *headers = "\x83\x86\x44\x04/a/b\x40\x0acustom-hdr\x0cx700-not-a-tp";
    const u32 n = 8 + 2 + 10 + 1 + 12;
    memcpy(buf, headers, n);
    const h2_tp_scan_result_t r = h2_tp_scan(buf, n, k_h2_max_hpack_scan);
    assertf(r.offset == k_h2_max_hpack_scan, "no traceparent found");
    assertf(!r.present, "lookalike value is not a traceparent");
    assertf(!r.exhausted, "plain headers do not burn the retry budget");
}

// Every 11-byte name matches a two-byte prefilter, and the retry budget is small: without a
// third byte a handful of ordinary metadata keys hides the traceparent behind them.
static void test_decoy_names_do_not_hide_the_traceparent(void) {
    unsigned char buf[512] = {0};

    u32 n = preamble(buf);
    n = field_named(buf, n, "x-b3-spanid", "0011223344556677");
    n = field_named(buf, n, "grpc-status", "0");
    n = field_named(buf, n, "retry-after", "12");
    n = field_named(buf, n, "x-tenant-id", "acme");
    const u32 at = n;
    n = field_plain(buf, n, k_hpack_literal_incr_index);

    const h2_tp_scan_result_t r = h2_tp_scan(buf, n, k_h2_max_hpack_scan);
    assertf(r.offset == at, "traceparent found behind same-length decoy names");
    assertf(!r.exhausted, "decoys do not exhaust the retry budget");
}

// RFC 7541 Appendix B, restricted to the characters a traceparent can hold. Codes 0x00-0x09
// are 5 bits, 0x14-0x2d are 6 bits.
static int huffman_code(char c, u32 *code) {
    static const struct {
        char c;
        u8 code;
        u8 bits;
    } table[] = {
        {'0', 0x00, 5}, {'1', 0x01, 5}, {'2', 0x02, 5}, {'a', 0x03, 5}, {'c', 0x04, 5},
        {'e', 0x05, 5}, {'i', 0x06, 5}, {'o', 0x07, 5}, {'s', 0x08, 5}, {'t', 0x09, 5},
        {'-', 0x16, 6}, {'3', 0x19, 6}, {'4', 0x1a, 6}, {'5', 0x1b, 6}, {'6', 0x1c, 6},
        {'7', 0x1d, 6}, {'8', 0x1e, 6}, {'9', 0x1f, 6}, {'b', 0x23, 6}, {'d', 0x24, 6},
        {'f', 0x25, 6}, {'n', 0x2a, 6}, {'p', 0x2b, 6}, {'r', 0x2c, 6},
    };

    for (u32 i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (table[i].c == c) {
            *code = table[i].code;
            return table[i].bits;
        }
    }

    return 0;
}

static u32 huffman_encode(const char *s, unsigned char *out, u32 out_len) {
    u64 acc = 0;
    u32 bits = 0;
    u32 n = 0;

    for (; *s; s++) {
        u32 code = 0;
        const int width = huffman_code(*s, &code);
        assertf(width != 0, "character is in the huffman table");
        acc = (acc << width) | code;
        bits += width;
        while (bits >= 8 && n < out_len) {
            out[n++] = (unsigned char)(acc >> (bits - 8));
            bits -= 8;
        }
    }
    if (bits && n < out_len) {
        out[n++] = (unsigned char)((acc << (8 - bits)) | ((1u << (8 - bits)) - 1));
    }

    return n;
}

// k_hpack_tp_huffman came from grpc-go; reproducing it from the RFC table proves the constant
// the huffman name match depends on.
static void test_huffman_name_constant(void) {
    unsigned char enc[64];

    u32 n = huffman_encode("traceparent", enc, sizeof(enc));
    assertf(n == sizeof(k_hpack_tp_huffman), "encoder reproduces the known name length");
    assertf(memcmp(enc, k_hpack_tp_huffman, n) == 0, "encoder reproduces the known name bytes");
}

int main(void) {
    test_huffman_name_constant();
    test_adoptable();
    test_present_but_not_adoptable();
    test_x_net_encoded_traceparent();
    test_no_traceparent();
    test_decoy_names_do_not_hide_the_traceparent();
    printf("OK: %s\n", __FILE__);
    return 0;
}
