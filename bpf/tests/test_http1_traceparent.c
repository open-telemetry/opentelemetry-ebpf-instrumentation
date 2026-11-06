// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <assert.h>
#include <stdio.h>
#include <string.h>

static inline unsigned int bpf_get_prandom_u32(void) {
    return 0;
}

static inline long bpf_loop(unsigned int count,
                            int (*callback)(unsigned int, void *),
                            void *ctx,
                            unsigned long long flags) {
    (void)flags;
    for (unsigned int i = 0; i < count; i++) {
        if (callback(i, ctx)) {
            break;
        }
    }
    return 0;
}

#include <common/http1_traceparent.h>

static const unsigned char header[] =
    "Traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";

static unsigned char request[k_http1_max_header_bytes + sizeof(header) + 128];

static u32 request_with_traceparent(u32 offset) {
    const char prefix[] = "GET / HTTP/1.1\r\nX-Padding: ";
    assert(offset >= sizeof(prefix) + 1);
    memcpy(request, prefix, sizeof(prefix) - 1);
    memset(request + sizeof(prefix) - 1, 'a', offset - sizeof(prefix) - 1);
    memcpy(request + offset - 2, "\r\n", 2);
    memcpy(request + offset, header, sizeof(header) - 1);
    memcpy(request + offset + sizeof(header) - 1, "\r\n", 2);
    return offset + sizeof(header) + 1;
}

static void scan_in_chunks(http1_header_scan_t *scan, const unsigned char *buf, u32 len) {
    for (u32 pos = 0; pos < len; pos += k_http1_read_chunk_bytes) {
        const u32 remaining = len - pos;
        http1_scan_headers(scan,
                           buf + pos,
                           remaining < k_http1_read_chunk_bytes ? remaining
                                                                : k_http1_read_chunk_bytes);
    }
}

static void test_every_split(void) {
    const u32 len = request_with_traceparent(100);
    for (u32 split = 0; split <= len; split++) {
        http1_header_scan_t scan = {};
        http1_scan_headers(&scan, request, split);
        http1_scan_headers(&scan, request + split, len - split);
        assert(scan.present && scan.valid && scan.value_length == k_hpack_value_len_tp);
        const u32 value_offset = sizeof("traceparent: ") - 1;
        assert(memcmp(scan.header + value_offset, header + value_offset, k_hpack_value_len_tp) ==
               0);
    }
}

static void test_large_fragmented_headers(void) {
    const u32 offsets[] = {
        1000, 1020, 4090, 8190, k_http1_max_header_bytes - TRACE_PARENT_HEADER_LEN};
    for (u32 i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        const u32 len = request_with_traceparent(offsets[i]);
        http1_header_scan_t scan = {};
        for (u32 pos = 0; pos < len; pos++) {
            http1_scan_headers(&scan, request + pos, 1);
        }
        assert(scan.present && scan.valid);
        assert(scan.bytes == offsets[i] + TRACE_PARENT_HEADER_LEN);
    }
}

static void test_limit(void) {
    const u32 offsets[] = {k_http1_max_header_bytes - TRACE_PARENT_HEADER_LEN + 1,
                           k_http1_max_header_bytes};
    for (u32 i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        const u32 len = request_with_traceparent(offsets[i]);
        http1_header_scan_t scan = {};
        scan_in_chunks(&scan, request, 1000);
        scan_in_chunks(&scan, request + 1000, len - 1000);
        assert(!scan.valid);
        assert(scan.phase == k_http1_headers_done);
        assert(scan.bytes == k_http1_max_header_bytes);
    }
}

static void test_headers_only(void) {
    const unsigned char input[] = "GET / HTTP/1.1\r\nX-Value: Traceparent: bogus\r\n\r\n";
    const u32 len = sizeof(input) - 1;
    for (u32 split = 0; split <= len; split++) {
        http1_header_scan_t scan = {};
        http1_scan_headers(&scan, input, split);
        http1_scan_headers(&scan, input + split, len - split);
        http1_scan_headers(&scan, header, sizeof(header) - 1);
        assert(!scan.present && !scan.valid);
        assert(scan.bytes == len);
        assert(scan.phase == k_http1_headers_done);
    }
}

static void test_malformed_header_is_preserved(void) {
    const unsigned char *values[] = {
        (const unsigned char *)"traceparent: invalid\r\n",
        (const unsigned char
             *)"traceparent: 00-00000000000000000000000000000000-0123456789abcdef-01\r\n",
        (const unsigned char
             *)"traceparent: 00-0123456789abcdef0123456789abcdef-0000000000000000-01\r\n",
        (const unsigned char
             *)"traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdeg-01\r\n",
        (const unsigned char
             *)"traceparent: ff-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n",
    };
    for (u32 i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        http1_header_scan_t scan = {.phase = k_http1_header_name};
        http1_scan_headers(&scan, values[i], strlen((const char *)values[i]));
        assert(scan.present && !scan.valid);
        assert(scan.phase == k_http1_headers_done);
    }
}

static void test_header_name_and_spacing(void) {
    const unsigned char input[] =
        "tRaCePaReNt:\t00-0123456789abcdef0123456789abcdef-0123456789abcdef-00\r\n";
    http1_header_scan_t scan = {.phase = k_http1_header_name};
    http1_scan_headers(&scan, input, sizeof(input) - 1);
    assert(scan.present && scan.valid);
    assert(scan.header[TRACE_PARENT_HEADER_LEN - 1] == '0');
}

static void test_scan_is_bounded_by_chunk(void) {
    const u32 len = request_with_traceparent(k_http1_read_chunk_bytes + 100);
    http1_header_scan_t scan = {};
    http1_scan_headers(&scan, request, len);
    assert(scan.bytes == k_http1_read_chunk_bytes && !scan.present);
    scan_in_chunks(&scan, request + scan.bytes, len - scan.bytes);
    assert(scan.present && scan.valid);
}

static void test_request_line_end(void) {
    const unsigned char input[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    const u32 split = sizeof("GET /") - 1;
    http1_header_scan_t scan = {};
    http1_scan_headers(&scan, input, split);
    assert(scan.request_line_end == 0 && scan.phase == k_http1_request_line);
    http1_scan_headers(&scan, input + split, sizeof(input) - 1 - split);
    assert(scan.request_line_end == sizeof("GET / HTTP/1.1\r\n") - 1);
    assert(scan.phase == k_http1_headers_done && !scan.present);
}

int main(void) {
    test_every_split();
    test_large_fragmented_headers();
    test_limit();
    test_headers_only();
    test_malformed_header_is_preserved();
    test_header_name_and_spacing();
    test_scan_is_bounded_by_chunk();
    test_request_line_end();
    puts("HTTP/1 traceparent scan tests passed");
    return 0;
}
