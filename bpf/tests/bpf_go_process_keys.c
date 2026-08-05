// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include <common/go_addr_key.h>

static unsigned int failures;

static void assert_distinct(const void *left, const void *right, size_t size, const char *message) {
    if (memcmp(left, right, size) != 0) {
        return;
    }
    fprintf(stderr, "%s\n", message);
    failures++;
}

static void assert_equal(const void *left, const void *right, size_t size, const char *message) {
    if (memcmp(left, right, size) == 0) {
        return;
    }
    fprintf(stderr, "%s\n", message);
    failures++;
}

static void test_identical_addresses_are_pid_scoped(void) {
    const go_exact_process_addr_key_t process_a = go_exact_process_addr_key(41, 700, 0x1234);
    const go_exact_process_addr_key_t process_b = go_exact_process_addr_key(42, 700, 0x1234);
    assert_distinct(&process_a,
                    &process_b,
                    sizeof(process_a),
                    "identical HTTP/1 header pointers in two PIDs must not alias");

    const go_exact_process_stream_key_t stream_a = go_exact_process_stream_key(41, 700, 0xbeef, 3);
    const go_exact_process_stream_key_t stream_b = go_exact_process_stream_key(42, 700, 0xbeef, 3);
    assert_distinct(&stream_a,
                    &stream_b,
                    sizeof(stream_a),
                    "identical HTTP/2 framer pointers and stream IDs in two PIDs must not alias");
}

static void test_pid_reuse_is_exact_start_scoped(void) {
    const go_exact_process_addr_key_t old_header = go_exact_process_addr_key(42, 700, 0x1234);
    const go_exact_process_addr_key_t new_header = go_exact_process_addr_key(42, 701, 0x1234);
    assert_distinct(&old_header,
                    &new_header,
                    sizeof(old_header),
                    "HTTP/1 header pointer reuse must not cross process incarnations");

    const go_exact_process_stream_key_t old_stream =
        go_exact_process_stream_key(42, 700, 0xbeef, 3);
    const go_exact_process_stream_key_t new_stream =
        go_exact_process_stream_key(42, 701, 0xbeef, 3);
    assert_distinct(&old_stream,
                    &new_stream,
                    sizeof(old_stream),
                    "HTTP/2 stream reuse must not cross process incarnations");

    const go_exact_process_stream_key_t same_stream =
        go_exact_process_stream_key(42, 700, 0xbeef, 3);
    assert_equal(&old_stream,
                 &same_stream,
                 sizeof(old_stream),
                 "same exact process stream identity must remain stable");
}

int main(void) {
    test_identical_addresses_are_pid_scoped();
    test_pid_reuse_is_exact_start_scoped();
    return failures ? 1 : 0;
}
