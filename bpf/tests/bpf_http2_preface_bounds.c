// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <generictracer/http2_grpc.h>

static void assert_int_eq(int expected, int actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %d, got %d\n", message, expected, actual);
        exit(1);
    }
}

static void assert_u64_eq(u64 expected, u64 actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr,
                "FAIL: %s\n  expected %llu, got %llu\n",
                message,
                (unsigned long long)expected,
                (unsigned long long)actual);
        exit(1);
    }
}

static call_protocol_args_t protocol_args_for(unsigned char *buf, int len) {
    call_protocol_args_t args = {
        .bytes_len = len,
        .u_buf = (u64)buf,
    };

    const size_t small_buf_len =
        len < (int)sizeof(args.small_buf) ? (size_t)len : sizeof(args.small_buf);
    __builtin_memcpy(args.small_buf, buf, small_buf_len);

    return args;
}

static void write_preface(unsigned char *buf) {
    __builtin_memcpy(buf, HTTP2_GRPC_PREFACE, MIN_HTTP2_SIZE);
}

static void test_short_buffer_keeps_original_bounds(void) {
    unsigned char buf[MIN_HTTP2_SIZE - 1] = {0};
    __builtin_memcpy(buf, HTTP2_GRPC_PREFACE, sizeof(buf));
    call_protocol_args_t args = protocol_args_for(buf, sizeof(buf));

    skip_http2_preface(&args);

    assert_u64_eq((u64)buf, args.u_buf, "short buffer keeps original pointer");
    assert_int_eq((int)sizeof(buf), args.bytes_len, "short buffer keeps original length");
}

static void test_non_preface_keeps_original_bounds(void) {
    unsigned char buf[MIN_HTTP2_SIZE + 1] = {0};
    call_protocol_args_t args = protocol_args_for(buf, sizeof(buf));

    skip_http2_preface(&args);

    assert_u64_eq((u64)buf, args.u_buf, "non-preface keeps original pointer");
    assert_int_eq((int)sizeof(buf), args.bytes_len, "non-preface keeps original length");
}

static void test_preface_only_leaves_empty_payload(void) {
    unsigned char buf[MIN_HTTP2_SIZE] = {0};
    write_preface(buf);
    call_protocol_args_t args = protocol_args_for(buf, sizeof(buf));

    skip_http2_preface(&args);

    assert_u64_eq((u64)(buf + MIN_HTTP2_SIZE), args.u_buf, "preface-only skips pointer");
    assert_int_eq(0, args.bytes_len, "preface-only leaves no payload bytes");
}

static void test_preface_short_payload_keeps_effective_length(void) {
    unsigned char buf[MIN_HTTP2_SIZE + 1] = {0};
    write_preface(buf);
    buf[MIN_HTTP2_SIZE] = 0xff;
    call_protocol_args_t args = protocol_args_for(buf, sizeof(buf));

    skip_http2_preface(&args);

    assert_u64_eq((u64)(buf + MIN_HTTP2_SIZE), args.u_buf, "short payload skips pointer");
    assert_int_eq(1, args.bytes_len, "short payload shrinks length with pointer");
}

int main(void) {
    test_short_buffer_keeps_original_bounds();
    test_non_preface_keeps_original_bounds();
    test_preface_only_leaves_empty_payload();
    test_preface_short_payload_keeps_effective_length();

    return 0;
}
