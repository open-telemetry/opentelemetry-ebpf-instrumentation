// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

static long test_probe_read(void *dst, unsigned int size, const void *src);

#define bpf_probe_read test_probe_read
#include <common/http_types.h>
#undef bpf_probe_read

static unsigned int test_last_read_size;
static const char *test_src_base;
static unsigned int test_src_len;
static int test_read_faulted;
static unsigned char *test_scratch;

static long test_probe_read(void *dst, unsigned int size, const void *src) {
    test_last_read_size = size;
    if (src == test_scratch && size <= FULL_BUF_SIZE) {
        test_read_faulted = 0;
        memcpy(dst, src, size);
        return 0;
    }
    const unsigned int off = (unsigned int)((const char *)src - test_src_base);
    if (off + size > test_src_len) {
        test_read_faulted = 1;
        return -1;
    }
    test_read_faulted = 0;
    memcpy(dst, src, size);
    return 0;
}

static void copy_request_buffer(http_info_t *info, const call_protocol_args_t *args) {
    unsigned char scratch[FULL_BUF_SIZE] = {0};
    test_scratch = scratch;
    read_request_buf(info, args, scratch);
    for (unsigned int i = 0; i < FULL_BUF_SIZE; i++) {
        if (scratch[i] != 0) {
            fprintf(stderr, "FAIL: request scratch retains captured bytes\n");
            exit(1);
        }
    }
    test_scratch = NULL;
}

static void assert_true(int cond, const char *message) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void assert_uint_eq(unsigned int expected, unsigned int actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %u, got %u\n", message, expected, actual);
        exit(1);
    }
}

static call_protocol_args_t args_for(const char *payload, unsigned int readable, int bytes_len) {
    test_src_base = payload;
    test_src_len = readable;
    test_read_faulted = 0;
    test_last_read_size = 0;

    call_protocol_args_t args = {0};
    args.bytes_len = bytes_len;
    args.u_buf = (u64)(uintptr_t)payload;
    return args;
}

static void test_short_request_line_is_fully_copied(void) {
    const char payload[] = "GET /greeting HTTP/1.1\r\n";
    const unsigned int len = (unsigned int)strlen(payload);
    http_info_t info = {0};
    call_protocol_args_t args = args_for(payload, len, (int)len);

    copy_request_buffer(&info, &args);

    assert_uint_eq(len, test_last_read_size, "read is clamped down to the payload length");
    assert_true(!test_read_faulted, "clamped read stays within the payload and does not fault");
    assert_true(memcmp(info.buf, "GET ", 4) == 0, "method survives the copy");
}

static void test_unclamped_read_would_have_faulted(void) {
    const char payload[] = "GET /greeting HTTP/1.1\r\n";
    const unsigned int len = (unsigned int)strlen(payload);
    unsigned char dst[FULL_BUF_SIZE] = {0};
    test_src_base = payload;
    test_src_len = len;

    test_probe_read(dst, FULL_BUF_SIZE, payload);

    assert_true(test_read_faulted, "the pre-fix fixed-size read over-reads and faults");
}

static void test_oversized_payload_is_clamped_to_capacity(void) {
    char payload[FULL_BUF_SIZE * 4];
    memset(payload, 'a', sizeof(payload));
    http_info_t info = {0};
    call_protocol_args_t args = args_for(payload, sizeof(payload), (int)sizeof(payload));

    copy_request_buffer(&info, &args);

    assert_uint_eq(FULL_BUF_SIZE, test_last_read_size, "read never exceeds info->buf capacity");
    assert_true(!test_read_faulted, "capacity-clamped read does not fault");
}

static void test_complete_headers_exclude_body(void) {
    const char headers[] = "POST /api/flights/search HTTP/1.1\r\nHost: "
                           "airline.example:8080\r\nContent-Length: 13\r\n\r\n";
    const char payload[] = "POST /api/flights/search HTTP/1.1\r\nHost: "
                           "airline.example:8080\r\nContent-Length: 13\r\n\r\nbody-sentinel";
    const unsigned int header_len = (unsigned int)strlen(headers);
    http_info_t info = {0};
    call_protocol_args_t args =
        args_for(payload, (unsigned int)strlen(payload), (int)strlen(payload));

    copy_request_buffer(&info, &args);

    assert_true(memcmp(info.buf, headers, header_len) == 0,
                "method, path, and complete Host header survive");
    for (unsigned int i = header_len; i < FULL_BUF_SIZE; i++) {
        assert_true(info.buf[i] == 0, "metadata buffer contains no request body bytes");
    }
}

static void test_split_header_terminator_keeps_only_first_chunk(void) {
    const char payload[] = "POST /search HTTP/1.1\r\nHost: example.test\r\n\r\nbody-sentinel";
    const char *end = strstr(payload, "\r\n\r\n");
    assert_true(end != NULL, "request has an HTTP header terminator");
    const unsigned int boundary = (unsigned int)(end - payload);

    for (unsigned int split = boundary + 1; split < boundary + 4; split++) {
        http_info_t info = {0};
        call_protocol_args_t args = args_for(payload, split, (int)split);
        copy_request_buffer(&info, &args);
        assert_true(memcmp(info.buf, payload, split) == 0,
                    "a split terminator preserves the available header prefix");
        for (unsigned int i = split; i < FULL_BUF_SIZE; i++) {
            assert_true(info.buf[i] == 0, "the remaining metadata buffer is empty");
        }
    }
}

static void test_terminator_at_capacity_keeps_the_complete_prefix(void) {
    char payload[FULL_BUF_SIZE + 32] = "POST /search HTTP/1.1\r\nHost: example.test\r\nX-Pad: ";
    const unsigned int initial_len = (unsigned int)strlen(payload);
    memset(payload + initial_len, 'a', FULL_BUF_SIZE - 4 - initial_len);
    memcpy(payload + FULL_BUF_SIZE - 4, "\r\n\r\nbody-sentinel", 17);

    http_info_t info = {0};
    call_protocol_args_t args = args_for(payload, sizeof(payload), sizeof(payload));
    copy_request_buffer(&info, &args);

    assert_true(memcmp(info.buf, payload, FULL_BUF_SIZE) == 0,
                "a header ending at capacity is retained");
    assert_true(!test_read_faulted, "capacity boundary does not read past the request");
}

static void test_failed_input_read_does_not_publish_a_prefix(void) {
    const char payload[] = "POST /search HTTP/1.1\r\nHost: example.test\r\n\r\nbody-sentinel";
    const unsigned int len = (unsigned int)strlen(payload);
    http_info_t info = {0};
    call_protocol_args_t args = args_for(payload, len - 1, (int)len);

    copy_request_buffer(&info, &args);

    assert_true(test_read_faulted, "unreadable request bytes fail the input read");
    for (unsigned int i = 0; i < FULL_BUF_SIZE; i++) {
        assert_true(info.buf[i] == 0, "failed input read leaves no metadata prefix");
    }
}

int main(void) {
    test_short_request_line_is_fully_copied();
    test_unclamped_read_would_have_faulted();
    test_oversized_payload_is_clamped_to_capacity();
    test_complete_headers_exclude_body();
    test_split_header_terminator_keeps_only_first_chunk();
    test_terminator_at_capacity_keeps_the_complete_prefix();
    test_failed_input_read_does_not_publish_a_prefix();

    return 0;
}
