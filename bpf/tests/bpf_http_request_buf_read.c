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

static long test_probe_read(void *dst, unsigned int size, const void *src) {
    test_last_read_size = size;
    const unsigned int off = (unsigned int)((const char *)src - test_src_base);
    if (off + size > test_src_len) {
        test_read_faulted = 1;
        return -1;
    }
    test_read_faulted = 0;
    memcpy(dst, src, size);
    return 0;
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

    read_request_buf(&info, &args);

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

    read_request_buf(&info, &args);

    assert_uint_eq(FULL_BUF_SIZE, test_last_read_size, "read never exceeds info->buf capacity");
    assert_true(!test_read_faulted, "capacity-clamped read does not fault");
}

int main(void) {
    test_short_request_line_is_fully_copied();
    test_unclamped_read_would_have_faulted();
    test_oversized_payload_is_clamped_to_capacity();

    return 0;
}
