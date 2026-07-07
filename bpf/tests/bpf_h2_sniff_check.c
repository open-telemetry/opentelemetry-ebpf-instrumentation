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

    // PUSH_PROMISE
    n = frame(buf, 0, 20, k_h2_frame_push_promise, k_h2_flag_end_headers, 2);
    n = frame(buf, n, 18, k_h2_frame_headers, k_h2_flag_end_headers, 5);
    assertf(tile(buf, n) == 0, "PUSH_PROMISE rejected");

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
    n = frame(buf, 0, 20, k_h2_frame_data, k_h2_flag_padded, 1);
    n = frame(buf, n, 18, k_h2_frame_headers, k_h2_flag_end_headers, 5);
    assertf(tile(buf, n) == 0, "padded DATA rejected");

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

int main(void) {
    test_accepts_real_shapes();
    test_rejects_structural();
    test_rejects_per_type_rules();
    test_rejects_lookalikes();
    printf("OK: %s\n", __FILE__);
    return 0;
}
