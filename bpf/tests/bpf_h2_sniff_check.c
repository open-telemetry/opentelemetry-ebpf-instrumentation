// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/h2_defs.h>

static void assertf(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        exit(1);
    }
}

static void assert_byte(int cond, const char *msg, u8 b) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s (byte 0x%02x)\n", msg, b);
        exit(1);
    }
}

// Mirrors the walk in looks_like_http2_frames / sniff_http2_frames
static u8 tile(const unsigned char *buf, u32 len) {
    u32 pos = 0;
    h2_sniff_state_t st = {0};

    for (u8 i = 0; i < k_h2_sniff_max_frames && pos < len; i++) {
        if (pos + k_h2_frame_header_len > len) {
            return 0;
        }
        u32 frame_len;
        if (!h2_sniff_frame_header(&st, buf + pos, &frame_len)) {
            return 0;
        }
        pos += k_h2_frame_header_len + frame_len;
    }

    return h2_sniff_accept(&st, pos, len);
}

// Appends one frame header + zeroed payload, returns new write offset
static u32 frame(unsigned char *dst, u32 off, u32 len, u8 type, u8 flags, u32 stream_id) {
    dst[off] = (unsigned char)(len >> 16);
    dst[off + 1] = (unsigned char)(len >> 8);
    dst[off + 2] = (unsigned char)len;
    dst[off + 3] = type;
    dst[off + 4] = flags;
    dst[off + 5] = (unsigned char)(stream_id >> 24);
    dst[off + 6] = (unsigned char)(stream_id >> 16);
    dst[off + 7] = (unsigned char)(stream_id >> 8);
    dst[off + 8] = (unsigned char)stream_id;
    memset(dst + off + k_h2_frame_header_len, 0, len);
    return off + k_h2_frame_header_len + len;
}

static void test_accepts_real_shapes(void) {
    unsigned char buf[4096];
    u32 n;

    // unary gRPC client request: HEADERS(EH) + DATA(ES)
    n = frame(buf, 0, 20, k_h2_frame_headers, k_h2_flag_end_headers, 1);
    n = frame(buf, n, 5, k_h2_frame_data, k_h2_flag_end_stream, 1);
    assertf(tile(buf, n) == 1, "HEADERS+DATA accepted");

    // header block split into CONTINUATION
    n = frame(buf, 0, 16, k_h2_frame_headers, 0, 3);
    n = frame(buf, n, 8, k_h2_frame_continuation, k_h2_flag_end_headers, 3);
    assertf(tile(buf, n) == 1, "HEADERS+CONTINUATION accepted");

    // response tail: HEADERS(EH) + DATA + trailers HEADERS(EH|ES)
    n = frame(buf, 0, 12, k_h2_frame_headers, k_h2_flag_end_headers, 1);
    n = frame(buf, n, 30, k_h2_frame_data, 0, 1);
    n = frame(buf, n, 10, k_h2_frame_headers, k_h2_flag_end_headers | k_h2_flag_end_stream, 1);
    assertf(tile(buf, n) == 1, "response with trailers accepted");

    // control frames around a request
    n = frame(buf, 0, 4, k_h2_frame_window_update, 0, 0);
    n = frame(buf, n, 8, k_h2_frame_ping, 0, 0);
    n = frame(buf, n, 18, k_h2_frame_headers, k_h2_flag_end_headers, 5);
    assertf(tile(buf, n) == 1, "control frames + HEADERS accepted");

    // half-close
    n = frame(buf, 0, 20, k_h2_frame_headers, k_h2_flag_end_headers, 1);
    n = frame(buf, n, 5, k_h2_frame_data, 0, 1);
    n = frame(buf, n, 0, k_h2_frame_data, k_h2_flag_end_stream, 1);
    assertf(tile(buf, n) == 1, "empty END_STREAM DATA accepted");

    // zero-length SETTINGS ACK coalesced with a request
    n = frame(buf, 0, 0, k_h2_frame_settings, k_h2_flag_ack, 0);
    n = frame(buf, n, 18, k_h2_frame_headers, k_h2_flag_end_headers, 3);
    assertf(tile(buf, n) == 1, "SETTINGS ACK accepted");

    // padding is legal on both HEADERS and DATA
    n = frame(buf, 0, 20, k_h2_frame_headers, k_h2_flag_end_headers | k_h2_flag_padded, 1);
    n = frame(buf, n, 30, k_h2_frame_data, k_h2_flag_end_stream | k_h2_flag_padded, 1);
    assertf(tile(buf, n) == 1, "padded frames accepted");

    // extension frames, including the zero-length ORIGIN a server may send
    n = frame(buf, 0, 6, 0x10, 0, 0);
    n = frame(buf, n, 18, k_h2_frame_headers, k_h2_flag_end_headers, 7);
    assertf(tile(buf, n) == 1, "extension frame accepted");
    n = frame(buf, 0, 0, 0x0c, 0, 0);
    n = frame(buf, n, 18, k_h2_frame_headers, k_h2_flag_end_headers, 7);
    assertf(tile(buf, n) == 1, "empty extension frame accepted");

    // server push
    n = frame(buf, 0, 18, k_h2_frame_headers, k_h2_flag_end_headers, 1);
    n = frame(buf, n, 20, k_h2_frame_push_promise, k_h2_flag_end_headers, 1);
    assertf(tile(buf, n) == 1, "PUSH_PROMISE accepted");
}

static void test_rejects_structural(void) {
    unsigned char buf[4096];
    u32 n;

    // no HEADERS at all
    n = frame(buf, 0, 32, k_h2_frame_data, 0, 1);
    assertf(tile(buf, n) == 0, "DATA-only rejected");

    // bad tiling: one byte short
    n = frame(buf, 0, 20, k_h2_frame_headers, k_h2_flag_end_headers, 1);
    assertf(tile(buf, n - 1) == 0, "short tiling rejected");
    assertf(tile(buf, n + 1) == 0, "long tiling rejected");

    // HEADERS on even (server-initiated) stream
    n = frame(buf, 0, 20, k_h2_frame_headers, k_h2_flag_end_headers, 2);
    assertf(tile(buf, n) == 0, "even stream HEADERS rejected");

    // header block not continued: HEADERS w/o EH then DATA
    n = frame(buf, 0, 16, k_h2_frame_headers, 0, 3);
    n = frame(buf, n, 5, k_h2_frame_data, 0, 3);
    assertf(tile(buf, n) == 0, "broken continuation rejected");

    // header block left open at buffer end
    n = frame(buf, 0, 16, k_h2_frame_headers, 0, 3);
    assertf(tile(buf, n) == 0, "open header block rejected");

    // CONTINUATION without HEADERS
    n = frame(buf, 0, 8, k_h2_frame_continuation, k_h2_flag_end_headers, 3);
    n = frame(buf, n, 18, k_h2_frame_headers, k_h2_flag_end_headers, 5);
    assertf(tile(buf, n) == 0, "stray CONTINUATION rejected");

    // PUSH_PROMISE opens a header block too
    n = frame(buf, 0, 18, k_h2_frame_headers, k_h2_flag_end_headers, 1);
    n = frame(buf, n, 20, k_h2_frame_push_promise, 0, 1);
    n = frame(buf, n, 5, k_h2_frame_data, k_h2_flag_end_stream, 1);
    assertf(tile(buf, n) == 0, "PUSH_PROMISE without END_HEADERS rejected");

    // reserved bit set on stream id
    n = frame(buf, 0, 20, k_h2_frame_headers, k_h2_flag_end_headers, 1);
    buf[5] |= 0x80;
    assertf(tile(buf, n) == 0, "reserved bit rejected");
}

static void test_rejects_per_type_rules(void) {
    unsigned char buf[4096];
    u32 n;

    // undefined flag bits
    n = frame(buf, 0, 20, k_h2_frame_headers, k_h2_flag_end_headers | 0x40, 1);
    assertf(tile(buf, n) == 0, "undefined HEADERS flag rejected");

    // zero length needs the half-close flag
    n = frame(buf, 0, 20, k_h2_frame_headers, k_h2_flag_end_headers, 1);
    n = frame(buf, n, 0, k_h2_frame_data, 0, 1);
    assertf(tile(buf, n) == 0, "empty DATA without END_STREAM rejected");
    n = frame(buf, 0, 0, k_h2_frame_headers, k_h2_flag_end_headers, 1);
    assertf(tile(buf, n) == 0, "empty HEADERS rejected");

    // ACK must be empty
    n = frame(buf, 0, 6, k_h2_frame_settings, k_h2_flag_ack, 0);
    n = frame(buf, n, 18, k_h2_frame_headers, k_h2_flag_end_headers, 5);
    assertf(tile(buf, n) == 0, "non-empty SETTINGS ACK rejected");

    // only in-range unknown types are ignorable
    n = frame(buf, 0, 6, k_h2_max_extension_frame + 1, 0, 0);
    n = frame(buf, n, 18, k_h2_frame_headers, k_h2_flag_end_headers, 5);
    assertf(tile(buf, n) == 0, "out-of-range frame type rejected");

    // wrong fixed lengths
    n = frame(buf, 0, 6, k_h2_frame_priority, 0, 1);
    n = frame(buf, n, 18, k_h2_frame_headers, k_h2_flag_end_headers, 5);
    assertf(tile(buf, n) == 0, "bad PRIORITY length rejected");
    n = frame(buf, 0, 5, k_h2_frame_window_update, 0, 0);
    n = frame(buf, n, 18, k_h2_frame_headers, k_h2_flag_end_headers, 5);
    assertf(tile(buf, n) == 0, "bad WINDOW_UPDATE length rejected");

    // conn-level frames with a stream id
    n = frame(buf, 0, 6, k_h2_frame_settings, 0, 1);
    n = frame(buf, n, 18, k_h2_frame_headers, k_h2_flag_end_headers, 5);
    assertf(tile(buf, n) == 0, "SETTINGS with stream id rejected");
    n = frame(buf, 0, 8, k_h2_frame_ping, 0, 7);
    n = frame(buf, n, 18, k_h2_frame_headers, k_h2_flag_end_headers, 5);
    assertf(tile(buf, n) == 0, "PING with stream id rejected");

    // stream-level frames without one
    n = frame(buf, 0, 32, k_h2_frame_data, 0, 0);
    n = frame(buf, n, 18, k_h2_frame_headers, k_h2_flag_end_headers, 5);
    assertf(tile(buf, n) == 0, "DATA on stream 0 rejected");

    // oversized frame
    n = frame(buf, 0, 20, k_h2_frame_headers, k_h2_flag_end_headers, 1);
    buf[0] = 0x01; // length 0x01xxxx > k_h2_max_frame_len
    assertf(tile(buf, n) == 0, "oversized frame rejected");
}

static void test_rejects_lookalikes(void) {
    unsigned char buf[4096];

    // classic MySQL packet: 3-byte LE length + sequence id 1 ("HEADERS")
    const u32 payload = 60;
    memset(buf, 0xaa, sizeof(buf));
    buf[0] = (unsigned char)payload; // LE low byte first
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 1;
    assertf(tile(buf, 4 + payload) == 0, "MySQL-shaped packet rejected");

    // random-ish bytes
    unsigned int seed = 0x5eed;
    for (int round = 0; round < 100000; round++) {
        for (u32 i = 0; i < 64; i++) {
            seed = seed * 1103515245 + 12345;
            buf[i] = (unsigned char)(seed >> 16);
        }
        assertf(tile(buf, 64) == 0, "random buffer accepted");
    }
}

// Opener test: request vs response vs non-HPACK bytes. grpc-js and grpcio emit 0xc3 (dyn-table
// index 67) once their encoder is warm.
static void test_hpack_openers(void) {
    assertf(h2_hpack_opens_request(0x83), ":method POST accepted");
    assertf(h2_hpack_opens_request(0x84), ":path / accepted");
    assertf(h2_hpack_opens_request(0x41), ":authority literal accepted");
    assertf(h2_hpack_opens_request(0x04), ":path name reference accepted");
    assertf(h2_hpack_opens_request(0xc3), "warm dynamic-table entry accepted");
    assertf(h2_hpack_opens_request(0xbe), "first dynamic-table index accepted");

    assertf(!h2_hpack_opens_request(0x88), ":status 200 rejected");
    assertf(!h2_hpack_opens_request(0x8e), ":status 500 rejected");
    assertf(!h2_hpack_opens_request(0x48), ":status name reference rejected");
    assertf(!h2_hpack_opens_request(0x08), ":status without indexing rejected");
    assertf(!h2_hpack_opens_request(0x80), "index 0 rejected");
    assertf(!h2_hpack_opens_request(0x9f), "ordinary static entry rejected");
    assertf(!h2_hpack_opens_request(0x00), "literal new name rejected");
    // gRPC trailers open with a literal new name, "grpc-status"
    assertf(!h2_hpack_opens_request(0x40), "trailer block rejected");

    assertf(h2_hpack_opens_response(0x88), ":status 200 is a response");
    assertf(h2_hpack_opens_response(0x8e), ":status 504 is a response");
    assertf(h2_hpack_opens_response(0x48), ":status name ref is a response");
    // only 200, 204, 206, 304, 400, 404 and 500 have a static entry of their own
    assertf(h2_hpack_opens_response(0x4b), "name ref 11 is a response");
    assertf(h2_hpack_opens_response(0x4e), "name ref 14 is a response");
    assertf(h2_hpack_opens_response(0x0c), "name ref without indexing is a response");
    assertf(h2_hpack_opens_response(0x1c), "name ref never indexed is a response");
    assertf(!h2_hpack_opens_response(0x83), ":method is not a response");
    assertf(!h2_hpack_opens_response(0xc3), "dyn-table entry is not a response");
    assertf(!h2_hpack_opens_response(0x40), "trailer block is not a response");
    assertf(!h2_hpack_opens_response(0x4f), "index 15 is a varint continuation");
    // 0x50 is not a literal prefix, so its low bits are not a name index
    assertf(!h2_hpack_opens_response(0x5a), "0x5a is not a literal form");
}

// Representation of an HPACK first byte per RFC 7541 6.1-6.3: the static index it names, and
// whether it names one at all. Derived from the RFC, not from the predicates under test, so the
// two can disagree.
static u8 hpack_ref_index(u8 b, u8 *is_field, u8 *four_bit) {
    *is_field = 1;
    *four_bit = 0;

    if (b & 0x80) {
        return b & 0x7f; // 6.1 indexed header field
    }
    if ((b & 0xc0) == 0x40) {
        return b & 0x3f; // 6.2.1 literal with incremental indexing
    }
    if ((b & 0xe0) == 0x20) {
        *is_field = 0; // 6.3 dynamic table size update
        return 0;
    }

    *four_bit = 1; // 6.2.2 without indexing, 6.2.3 never indexed

    return b & 0x0f;
}

// Every byte, so no representation can be missed by an example-driven test.
static void test_hpack_openers_exhaustive(void) {
    enum {
        k_req_first = 1,
        k_req_last = 7,
        k_status_first = 8,
        k_status_last = 14,
        k_dyn_first = 62,
        // a 4-bit prefix cannot hold 15: it starts a varint instead of naming an entry
        k_varint_more = 15,
    };

    for (u32 v = 0; v < 256; v++) {
        const u8 b = (u8)v;
        u8 is_field, four_bit;
        const u8 idx = hpack_ref_index(b, &is_field, &four_bit);
        const u8 names_entry = is_field && !(four_bit && idx >= k_varint_more);

        const u8 want_resp = names_entry && idx >= k_status_first && idx <= k_status_last;
        const u8 want_req = (names_entry && idx >= k_req_first && idx <= k_req_last) ||
                            ((b & 0x80) && idx >= k_dyn_first);

        assert_byte(
            h2_hpack_opens_response(b) == want_resp, "opens_response disagrees with RFC", b);
        assert_byte(h2_hpack_opens_request(b) == want_req, "opens_request disagrees with RFC", b);
        assert_byte(!(h2_hpack_opens_response(b) && h2_hpack_opens_request(b)),
                    "a block cannot open both a request and a response",
                    b);
        assert_byte(
            h2_hpack_is_size_update(b) == !is_field, "is_size_update disagrees with RFC", b);
        assert_byte(h2_hpack_is_literal(b) ==
                        (u8)(b == k_hpack_literal_no_index || b == k_hpack_literal_never_index ||
                             b == k_hpack_literal_incr_index),
                    "is_literal must accept the new-name forms only",
                    b);
    }
}

// Openers golang.org/x/net/http2/hpack actually emits. It names :status through static entry
// 14, :method through 3, :path through 5 and :authority through 1, so a first non-static status
// opens with 0x4e and not 0x48.
static void test_hpack_real_encoder_openers(void) {
    for (u8 b = 0x88; b <= 0x8e; b++) {
        assert_byte(h2_hpack_opens_response(b), "static :status entry is a response", b);
    }

    assertf(h2_hpack_opens_response(0x4e), ":status 418 as x/net encodes it");
    assertf(h2_hpack_opens_response(0x1e), "a sensitive :status is never indexed");

    assertf(h2_hpack_opens_request(0x82), ":method GET is fully indexed");
    assertf(h2_hpack_opens_request(0x43), ":method PUT is a name ref");
    assertf(h2_hpack_opens_request(0x45), ":path /abc is a name ref");
    assertf(h2_hpack_opens_request(0x41), ":authority is a name ref");
    assertf(!h2_hpack_opens_response(0x43), ":method PUT is not a response");
    assertf(!h2_hpack_opens_response(0x45), ":path is not a response");
}

// RFC 7541 5.1 integer encoding of a size update value. Returns the encoded width.
static u32 encode_size_update(unsigned char *w, u32 size) {
    if (size < k_hpack_int_prefix5) {
        w[0] = (unsigned char)(k_hpack_size_update | size);
        return 1;
    }

    w[0] = (unsigned char)(k_hpack_size_update | k_hpack_int_prefix5);

    u32 n = 1;
    for (size -= k_hpack_int_prefix5; size >= 0x80; size >>= 7) {
        w[n++] = (unsigned char)((size & 0x7f) | k_hpack_int_more);
    }
    w[n++] = (unsigned char)size;

    return n;
}

// A misjudged update width makes the byte after it a varint octet rather than the opener, which
// silently misclassifies the block. Every width the encoding can produce has to be walked.
static void test_hpack_size_update_widths(void) {
    // 5.1 boundaries: prefix-only, prefix exhausted, and each further continuation octet
    const u32 sizes[] = {
        0, 30, 31, 32, 158, 159, 4096, 16384, 65536, 1u << 21, 1u << 28, 0xffffffffu};
    const u8 opener = 0x4e; // :status name ref 14

    for (u32 s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        unsigned char w[k_h2_hpack_opener_window] = {0};
        const u32 n = encode_size_update(w, sizes[s]);
        w[n] = opener;

        assertf(h2_hpack_size_update_len(w, 0, sizeof(w)) == n, "size update width");
        assertf(h2_hpack_skip_size_updates(w, sizeof(w)) == n, "opener sits past the update");
        assertf(h2_hpack_opens_response(w[h2_hpack_skip_size_updates(w, sizeof(w))]),
                "the byte past the update is the response opener");
    }

    unsigned char max[k_h2_hpack_opener_window] = {0};
    assertf(encode_size_update(max, 0xffffffffu) == 1 + k_hpack_int_max_octets,
            "a u32 update is a prefix plus five octets");

    // the window is sized for exactly this, so both must be walked
    unsigned char two[k_h2_hpack_opener_window] = {0};
    u32 off = encode_size_update(two, 0xffffffffu);
    off += encode_size_update(two + off, 0xffffffffu);
    two[off] = opener;
    assertf(off + 1 <= sizeof(two), "window holds two maximal updates and the opener");
    assertf(h2_hpack_skip_size_updates(two, sizeof(two)) == off, "both maximal updates skipped");
    assertf(h2_hpack_opens_response(two[off]), "the opener survives two maximal updates");

    // a window ending inside the varint must report past its end, so callers bail
    for (u32 cut = 1; cut < 1 + k_hpack_int_max_octets; cut++) {
        unsigned char t[k_h2_hpack_opener_window] = {0};
        encode_size_update(t, 0xffffffffu);
        assertf(h2_hpack_size_update_len(t, 0, cut) > cut, "a truncated update reports past have");
    }

    // A third update is past both the 4.2 idiom and what the window can hold. The byte taken as
    // the opener is then an update, which names no entry, so the block is classified as neither
    // and left alone rather than injected on a guess.
    unsigned char three[k_h2_hpack_opener_window] = {0x20, 0x20, 0x20, opener};
    const u32 skipped = h2_hpack_skip_size_updates(three, sizeof(three));
    assertf(skipped == 2, "only two updates are skipped");
    assertf(!h2_hpack_opens_response(three[skipped]) && !h2_hpack_opens_request(three[skipped]),
            "an unskipped update opens neither a request nor a response");
}

// RFC 7541 6.3: a peer that advertises SETTINGS_HEADER_TABLE_SIZE makes the encoder emit a
// size update ahead of the pseudo-headers. The opener is what follows it, not the update.
static void test_skips_dynamic_table_size_updates(void) {
    unsigned char w[k_h2_hpack_opener_window] = {0};

    w[0] = 0x83;
    assertf(h2_hpack_skip_size_updates(w, sizeof(w)) == 0, "no update to skip");

    // small size fits the 5-bit prefix
    w[0] = 0x20;
    w[1] = 0x83;
    assertf(h2_hpack_skip_size_updates(w, sizeof(w)) == 1, "one-byte size update skipped");

    // 4096 needs a continuation: 0x3f 0xe1 0x1f
    w[0] = 0x3f;
    w[1] = 0xe1;
    w[2] = 0x1f;
    w[3] = 0x83;
    assertf(h2_hpack_skip_size_updates(w, sizeof(w)) == 3, "multi-byte size update skipped");

    // RFC 7541 4.2 allows a shrink followed by a grow
    w[0] = 0x20;
    w[1] = 0x3f;
    w[2] = 0xe1;
    w[3] = 0x1f;
    w[4] = 0x83;
    assertf(h2_hpack_skip_size_updates(w, sizeof(w)) == 4, "two size updates skipped");

    memset(w, 0x3f, sizeof(w));
    assertf(h2_hpack_skip_size_updates(w, sizeof(w)) <= sizeof(w),
            "a window of update bytes stays in range");

    assertf(h2_hpack_is_size_update(0x20), "0x20 is a size update");
    assertf(h2_hpack_is_size_update(0x3f), "0x3f is a size update");
    assertf(!h2_hpack_is_size_update(0x40), "0x40 is a literal");
    assertf(!h2_hpack_is_size_update(0x83), "0x83 is an indexed field");
}

static void test_hpack_prefix_len(void) {
    assertf(h2_hpack_prefix_len(k_h2_flag_end_headers) == 0, "no prefix without flags");
    assertf(h2_hpack_prefix_len(k_h2_flag_padded) == 1, "padded costs the pad length byte");
    assertf(h2_hpack_prefix_len(k_h2_flag_priority) == k_h2_priority_prefix_len,
            "priority costs 5 bytes");
    assertf(h2_hpack_prefix_len(k_h2_flag_padded | k_h2_flag_priority) ==
                1 + k_h2_priority_prefix_len,
            "both prefixes add up");
}

int main(void) {
    test_hpack_openers();
    test_hpack_openers_exhaustive();
    test_hpack_real_encoder_openers();
    test_hpack_size_update_widths();
    test_skips_dynamic_table_size_updates();
    test_hpack_prefix_len();
    test_accepts_real_shapes();
    test_rejects_structural();
    test_rejects_per_type_rules();
    test_rejects_lookalikes();
    printf("OK: %s\n", __FILE__);
    return 0;
}
