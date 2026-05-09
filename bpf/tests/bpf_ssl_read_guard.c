// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * Tests for the SSL_read uretprobe return-value guard in
 * bpf/generictracer/libssl.c.
 *
 * SSL_read returns > 0 on success (bytes written to buf), 0 on EOF, and
 * < 0 on error.  In the EOF and error cases the application buffer has not
 * been touched, so forwarding its contents to the protocol parser would
 * expose stale data.  The uretprobe must bail out before calling
 * handle_ssl_buf whenever ret <= 0.
 *
 * The guard was absent after commit d1760a3b removed the bytes_len > 0
 * check from handle_ssl_buf (needed for large-payload connection tracking).
 * SSL_read_ex already guards with `ret != 1`; these tests cover the
 * equivalent guard that was added to SSL_read.
 *
 * Pattern mirrors bpf/tests/bpf_kafka_large_buffer.c: the BPF map helpers
 * and handle_ssl_buf are stubbed in userspace so the handler logic can be
 * exercised without a kernel.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint64_t u64;

#define TCP_RECV 0

// Matches ssl_args_t in bpf/common/ssl_args.h
typedef struct ssl_args {
    u64 ssl;
    u64 buf;
    u64 len_ptr;
    u64 flags;
} ssl_args_t;

// --- active_ssl_read_args map stub ---------------------------------------

#define MAP_SIZE 8

typedef struct {
    u64 key;
    ssl_args_t value;
    int used;
} ssl_read_args_entry_t;

static ssl_read_args_entry_t active_ssl_read_args[MAP_SIZE];

static ssl_args_t *ssl_read_args_lookup(u64 id) {
    for (int i = 0; i < MAP_SIZE; i++) {
        if (active_ssl_read_args[i].used && active_ssl_read_args[i].key == id) {
            return &active_ssl_read_args[i].value;
        }
    }
    return NULL;
}

static void ssl_read_args_update(u64 id, const ssl_args_t *val) {
    for (int i = 0; i < MAP_SIZE; i++) {
        if (!active_ssl_read_args[i].used) {
            active_ssl_read_args[i].used = 1;
            active_ssl_read_args[i].key = id;
            active_ssl_read_args[i].value = *val;
            return;
        }
    }
}

static int ssl_read_args_delete_count;

static void ssl_read_args_delete(u64 id) {
    for (int i = 0; i < MAP_SIZE; i++) {
        if (active_ssl_read_args[i].used && active_ssl_read_args[i].key == id) {
            active_ssl_read_args[i].used = 0;
            ssl_read_args_delete_count++;
            return;
        }
    }
}

// --- handle_ssl_buf stub -------------------------------------------------

static int handle_ssl_buf_call_count;
static int handle_ssl_buf_last_bytes_len;
static u8 handle_ssl_buf_last_direction;

static void handle_ssl_buf(u64 id, ssl_args_t *args, int bytes_len, u8 direction) {
    (void)id;
    (void)args;
    handle_ssl_buf_call_count++;
    handle_ssl_buf_last_bytes_len = bytes_len;
    handle_ssl_buf_last_direction = direction;
}

// --- Function under test -------------------------------------------------

// Mirrors obi_uretprobe_ssl_read in bpf/generictracer/libssl.c.
// valid_pid and bpf_dbg_printk are omitted; we test the ret <= 0 guard.
static void ssl_read_uretprobe(u64 id, int ret) {
    ssl_args_t *args = ssl_read_args_lookup(id);
    ssl_read_args_delete(id);

    if (ret <= 0) {
        return;
    }

    handle_ssl_buf(id, args, ret, TCP_RECV);
}

// --- Helpers -------------------------------------------------------------

static void assert_int_eq(int expected, int actual, const char *msg) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %d, got %d\n", msg, expected, actual);
        exit(1);
    }
}

static void reset(void) {
    memset(active_ssl_read_args, 0, sizeof(active_ssl_read_args));
    ssl_read_args_delete_count = 0;
    handle_ssl_buf_call_count = 0;
    handle_ssl_buf_last_bytes_len = 0;
    handle_ssl_buf_last_direction = 0;
}

static void seed_args(u64 id) {
    ssl_args_t args = {.ssl = 0xdeadbeef, .buf = 0xcafebabe, .len_ptr = 0, .flags = 0};
    ssl_read_args_update(id, &args);
}

// --- Tests ---------------------------------------------------------------

// SSL_read returned -1 (error): handle_ssl_buf must not be called.
static void test_error_skips_parsing(void) {
    printf("test_error_skips_parsing\n");
    reset();
    seed_args(1);
    ssl_read_uretprobe(1, -1);
    assert_int_eq(0,
                  handle_ssl_buf_call_count,
                  "handle_ssl_buf must not be called on SSL_read error (ret=-1)");
    assert_int_eq(1, ssl_read_args_delete_count, "args map entry must be deleted on error path");
}

// SSL_read returned 0 (EOF / clean shutdown): handle_ssl_buf must not be called.
static void test_eof_skips_parsing(void) {
    printf("test_eof_skips_parsing\n");
    reset();
    seed_args(2);
    ssl_read_uretprobe(2, 0);
    assert_int_eq(
        0, handle_ssl_buf_call_count, "handle_ssl_buf must not be called on SSL_read EOF (ret=0)");
    assert_int_eq(1, ssl_read_args_delete_count, "args map entry must be deleted on EOF path");
}

// SSL_read returned 1 (minimum valid read): handle_ssl_buf must be called.
static void test_one_byte_read_parses_buffer(void) {
    printf("test_one_byte_read_parses_buffer\n");
    reset();
    seed_args(3);
    ssl_read_uretprobe(3, 1);
    assert_int_eq(1, handle_ssl_buf_call_count, "handle_ssl_buf must be called for ret=1");
    assert_int_eq(
        1, handle_ssl_buf_last_bytes_len, "bytes_len passed to handle_ssl_buf must equal ret");
    assert_int_eq(TCP_RECV, (int)handle_ssl_buf_last_direction, "direction must be TCP_RECV");
    assert_int_eq(1, ssl_read_args_delete_count, "args map entry must be deleted on success path");
}

// SSL_read returned 128 bytes: bytes_len forwarded correctly.
static void test_normal_read_parses_buffer(void) {
    printf("test_normal_read_parses_buffer\n");
    reset();
    seed_args(4);
    ssl_read_uretprobe(4, 128);
    assert_int_eq(1, handle_ssl_buf_call_count, "handle_ssl_buf must be called for a normal read");
    assert_int_eq(128, handle_ssl_buf_last_bytes_len, "bytes_len must match SSL_read return value");
    assert_int_eq(1, ssl_read_args_delete_count, "args map entry must be deleted on success path");
}

int main(void) {
    test_error_skips_parsing();
    test_eof_skips_parsing();
    test_one_byte_read_parses_buffer();
    test_normal_read_parses_buffer();

    printf("\nAll tests PASSED!\n");
    return 0;
}
