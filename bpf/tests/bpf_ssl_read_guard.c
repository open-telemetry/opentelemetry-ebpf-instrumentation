// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint64_t u64;

typedef struct ssl_args {
    u64 ssl;
    u64 buf;
    u64 len_ptr;
    u64 flags;
} ssl_args_t;

static int ssl_pid_tid_delete_count;
static int fake_conn_count;
static int parser_call_count;
static int last_parser_bytes_len;

static void reset(void) {
    ssl_pid_tid_delete_count = 0;
    fake_conn_count = 0;
    parser_call_count = 0;
    last_parser_bytes_len = 0;
}

static void assert_int_eq(int expected, int actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %d, got %d\n", message, expected, actual);
        exit(1);
    }
}

static void delete_ssl_to_pid_tid(const u64 *ssl_ptr) {
    if (*ssl_ptr != 0) {
        ssl_pid_tid_delete_count++;
    }
}

static void create_fake_connection(void) {
    fake_conn_count++;
}

static void handle_buf_with_connection(int bytes_len) {
    parser_call_count++;
    last_parser_bytes_len = bytes_len;
}

// Mirrors the cleanup, length guard, and parser call ordering in ssl_defs.h.
static void handle_ssl_buf_for_test(ssl_args_t *args, int bytes_len, int has_connection) {
    if (!args) {
        return;
    }

    const u64 ssl_ptr = args->ssl;
    delete_ssl_to_pid_tid(&ssl_ptr);

    if (bytes_len <= 0) {
        return;
    }

    if (!has_connection) {
        create_fake_connection();
    }

    handle_buf_with_connection(bytes_len);
}

static void test_failed_read_skips_parser_after_cleanup(void) {
    reset();
    ssl_args_t args = {.ssl = 0x1234};

    handle_ssl_buf_for_test(&args, -1, 1);

    assert_int_eq(1, ssl_pid_tid_delete_count, "ssl_to_pid_tid entry is deleted on error");
    assert_int_eq(0, fake_conn_count, "failed read does not create fake connection info");
    assert_int_eq(0, parser_call_count, "failed read does not enter protocol parsing");
}

static void test_eof_read_skips_parser_after_cleanup(void) {
    reset();
    ssl_args_t args = {.ssl = 0x1234};

    handle_ssl_buf_for_test(&args, 0, 1);

    assert_int_eq(1, ssl_pid_tid_delete_count, "ssl_to_pid_tid entry is deleted on EOF");
    assert_int_eq(0, fake_conn_count, "EOF read does not create fake connection info");
    assert_int_eq(0, parser_call_count, "EOF read does not enter protocol parsing");
}

static void test_successful_read_still_parses(void) {
    reset();
    ssl_args_t args = {.ssl = 0x1234};

    handle_ssl_buf_for_test(&args, 1, 1);

    assert_int_eq(1, ssl_pid_tid_delete_count, "ssl_to_pid_tid entry is deleted on success");
    assert_int_eq(0, fake_conn_count, "existing connection is reused");
    assert_int_eq(1, parser_call_count, "successful read enters protocol parsing");
    assert_int_eq(1, last_parser_bytes_len, "successful read forwards the read length");
}

static void test_successful_read_can_create_fake_connection(void) {
    reset();
    ssl_args_t args = {.ssl = 0x1234};

    handle_ssl_buf_for_test(&args, 128, 0);

    assert_int_eq(1, ssl_pid_tid_delete_count, "ssl_to_pid_tid entry is deleted");
    assert_int_eq(1, fake_conn_count, "positive read can create fake connection info");
    assert_int_eq(1, parser_call_count, "positive read enters protocol parsing");
    assert_int_eq(128, last_parser_bytes_len, "positive read forwards the read length");
}

static void test_missing_args_noops(void) {
    reset();

    handle_ssl_buf_for_test(NULL, 128, 1);

    assert_int_eq(0, ssl_pid_tid_delete_count, "missing args do not touch ssl_to_pid_tid");
    assert_int_eq(0, fake_conn_count, "missing args do not create fake connection info");
    assert_int_eq(0, parser_call_count, "missing args do not enter protocol parsing");
}

int main(void) {
    test_failed_read_skips_parser_after_cleanup();
    test_eof_read_skips_parser_after_cleanup();
    test_successful_read_still_parses();
    test_successful_read_can_create_fake_connection();
    test_missing_args_noops();

    return 0;
}
