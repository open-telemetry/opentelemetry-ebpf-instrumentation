// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

enum { k_short_request_len = 74 };

static long test_probe_read(void *dst, unsigned int size, const void *src);

#define bpf_probe_read test_probe_read
#include <generictracer/http_request_buffer.h>
#undef bpf_probe_read

static unsigned int probe_read_size;
static unsigned int probe_read_source_size;
static int probe_read_failure;

static void assert_int_eq(int expected, int actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %d, got %d\n", message, expected, actual);
        exit(1);
    }
}

static void
assert_mem_eq(const void *expected, const void *actual, size_t size, const char *message) {
    if (memcmp(expected, actual, size) != 0) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static long test_probe_read(void *dst, unsigned int size, const void *src) {
    probe_read_size = size;
    if (probe_read_failure || size > probe_read_source_size) {
        memset(dst, 0, size);
        return -1;
    }

    memcpy(dst, src, size);
    return 0;
}

static call_protocol_args_t protocol_args_for(unsigned char *buf, int len) {
    probe_read_source_size = (unsigned int)len;

    call_protocol_args_t args = {
        .bytes_len = len,
        .u_buf = (u64)buf,
    };

    const size_t prefix_len =
        len < (int)sizeof(args.small_buf) ? (size_t)len : sizeof(args.small_buf);
    memcpy(args.small_buf, buf, prefix_len);

    return args;
}

static void reset(void) {
    probe_read_size = 0;
    probe_read_source_size = 0;
    probe_read_failure = 0;
}

static void test_short_request_uses_payload_length(void) {
    reset();
    unsigned char request[k_short_request_len] = "GET / HTTP/1.1\r\nHost: google.com\r\n";
    call_protocol_args_t args = protocol_args_for(request, sizeof(request));
    http_info_t info = {};

    const int err = capture_http_request_buffer(&info, &args);

    assert_int_eq(0, err, "short request capture succeeds");
    assert_int_eq(sizeof(request), probe_read_size, "short request read is bounded by payload");
    assert_mem_eq(request, info.buf, sizeof(request), "short request payload is preserved");
}

static void test_large_request_uses_destination_size(void) {
    reset();
    unsigned char request[FULL_BUF_SIZE + 1] = "GET / HTTP/1.1\r\n";
    call_protocol_args_t args = protocol_args_for(request, sizeof(request));
    http_info_t info = {};

    const int err = capture_http_request_buffer(&info, &args);

    assert_int_eq(0, err, "large request capture succeeds");
    assert_int_eq(FULL_BUF_SIZE, probe_read_size, "large request read is capped by destination");
    assert_mem_eq(request, info.buf, FULL_BUF_SIZE, "large request prefix is preserved");
}

static void test_failed_read_preserves_protocol_prefix(void) {
    reset();
    unsigned char request[k_short_request_len] = "GET / HTTP/1.1\r\nHost: google.com\r\n";
    call_protocol_args_t args = protocol_args_for(request, sizeof(request));
    http_info_t info = {};
    probe_read_failure = 1;

    const int err = capture_http_request_buffer(&info, &args);

    assert_int_eq(-1, err, "failed request capture returns the helper error");
    assert_int_eq(sizeof(request), probe_read_size, "failed request read remains bounded");
    assert_mem_eq(args.small_buf,
                  info.buf,
                  sizeof(args.small_buf),
                  "failed request capture preserves the protocol prefix");
}

int main(void) {
    test_short_request_uses_payload_length();
    test_large_request_uses_destination_size();
    test_failed_read_preserves_protocol_prefix();

    return 0;
}
