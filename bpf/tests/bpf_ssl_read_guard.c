// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdbool.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;

#ifndef __always_inline
#define __always_inline inline
#endif
#ifndef SEC
#define SEC(name)
#endif
#ifndef __uint
#define __uint(name, val) int name
#endif
#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

#ifndef valid_pid
#define valid_pid(id) (1)
#endif
#ifndef pid_from_pid_tgid
#define pid_from_pid_tgid(id) ((u32)((id) >> 32))
#endif

struct bpf_test_map {
    int id;
};

static void *test_map_lookup(void *map, const void *key);
static long test_map_update(void *map, const void *key, const void *val, unsigned long long flags);
static long test_map_delete(void *map, const void *key);
static long test_probe_read(void *dst, unsigned int size, const void *src);

#define __BPF_HELPERS__
#define __BPF_HELPER_DEFS__
#define IP_V6_ADDR_LEN 16
#define IP_V6_ADDR_LEN_WORDS 4

#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete
#define bpf_probe_read test_probe_read

#include <generictracer/ssl_defs.h>

#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#undef bpf_map_delete_elem
#undef bpf_probe_read

struct bpf_test_map ssl_to_conn = {.id = 1};
struct bpf_test_map pid_tid_to_conn = {.id = 2};
struct bpf_test_map ssl_to_pid_tid = {.id = 3};
struct bpf_test_map ongoing_http = {.id = 4};

int test_parser_call_count;
int test_last_parser_bytes_len;
u8 test_last_ssl;
u8 test_last_direction;
u16 test_last_orig_dport;
int test_finish_http_count;
u8 test_http_will_complete;

static int ssl_pid_tid_delete_count;
static int pid_tid_delete_count;
static int ssl_to_conn_update_count;
static ssl_pid_connection_info_t test_ssl_conn;
static int test_ssl_conn_available;
static u64 test_ssl_ptr;
static u64 test_mapped_pid_tid;
static int test_mapped_pid_tid_available;

static void assert_int_eq(int expected, int actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %d, got %d\n", message, expected, actual);
        exit(1);
    }
}

static void assert_u16_eq(u16 expected, u16 actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %u, got %u\n", message, expected, actual);
        exit(1);
    }
}

static void *test_map_lookup(void *map, const void *key) {
    if (map == &ssl_to_conn) {
        const u64 ssl = (u64) * (void *const *)key;
        if (test_ssl_conn_available && ssl == test_ssl_ptr) {
            return &test_ssl_conn;
        }
        return NULL;
    }

    if (map == &pid_tid_to_conn) {
        const u64 pid_tid = *(const u64 *)key;
        if (test_mapped_pid_tid_available && pid_tid == test_mapped_pid_tid) {
            return &test_ssl_conn;
        }
        return NULL;
    }

    if (map == &ssl_to_pid_tid) {
        const u64 ssl = *(const u64 *)key;
        if (test_mapped_pid_tid_available && ssl == test_ssl_ptr) {
            return &test_mapped_pid_tid;
        }
        return NULL;
    }

    return NULL;
}

static long test_map_update(void *map, const void *key, const void *val, unsigned long long flags) {
    (void)key;
    (void)flags;

    if (map == &ssl_to_conn) {
        ssl_to_conn_update_count++;
        __builtin_memcpy(&test_ssl_conn, val, sizeof(test_ssl_conn));
        test_ssl_conn_available = 1;
    }

    return 0;
}

static long test_map_delete(void *map, const void *key) {
    (void)key;

    if (map == &ssl_to_pid_tid) {
        ssl_pid_tid_delete_count++;
    } else if (map == &pid_tid_to_conn) {
        pid_tid_delete_count++;
    }

    return 0;
}

static long test_probe_read(void *dst, unsigned int size, const void *src) {
    if (dst && src && size > 0) {
        __builtin_memcpy(dst, src, size);
    }
    return 0;
}

static void reset(void) {
    test_parser_call_count = 0;
    test_last_parser_bytes_len = 0;
    test_last_ssl = 0;
    test_last_direction = 0;
    test_last_orig_dport = 0;
    test_finish_http_count = 0;
    test_http_will_complete = 0;
    ssl_pid_tid_delete_count = 0;
    pid_tid_delete_count = 0;
    ssl_to_conn_update_count = 0;
    test_ssl_conn = (ssl_pid_connection_info_t){};
    test_ssl_conn_available = 0;
    test_ssl_ptr = 0x1234;
    test_mapped_pid_tid = 0;
    test_mapped_pid_tid_available = 0;
}

static ssl_args_t ssl_args(void) {
    return (ssl_args_t){.ssl = test_ssl_ptr, .buf = 0x4321};
}

static void seed_existing_ssl_connection(u16 orig_dport) {
    test_ssl_conn_available = 1;
    test_ssl_conn.orig_dport = orig_dport;
    test_ssl_conn.p_conn.pid = 42;
}

static void test_failed_read_skips_parser_after_cleanup(void) {
    reset();
    seed_existing_ssl_connection(443);
    ssl_args_t args = ssl_args();

    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, -1, TCP_RECV);

    assert_int_eq(1, ssl_pid_tid_delete_count, "ssl_to_pid_tid entry is deleted on error");
    assert_int_eq(0, ssl_to_conn_update_count, "failed read does not create connection info");
    assert_int_eq(0, test_parser_call_count, "failed read does not enter protocol parsing");
}

static void test_eof_read_skips_parser_after_cleanup(void) {
    reset();
    seed_existing_ssl_connection(443);
    ssl_args_t args = ssl_args();

    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 0, TCP_RECV);

    assert_int_eq(1, ssl_pid_tid_delete_count, "ssl_to_pid_tid entry is deleted on EOF");
    assert_int_eq(0, ssl_to_conn_update_count, "EOF read does not create connection info");
    assert_int_eq(0, test_parser_call_count, "EOF read does not enter protocol parsing");
}

static void test_successful_read_still_parses(void) {
    reset();
    seed_existing_ssl_connection(443);
    ssl_args_t args = ssl_args();

    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 1, TCP_RECV);

    assert_int_eq(1, ssl_pid_tid_delete_count, "ssl_to_pid_tid entry is deleted on success");
    assert_int_eq(0, ssl_to_conn_update_count, "existing connection is reused");
    assert_int_eq(1, test_parser_call_count, "successful read enters protocol parsing");
    assert_int_eq(1, test_last_parser_bytes_len, "successful read forwards the read length");
    assert_int_eq(WITH_SSL, test_last_ssl, "successful read is marked as SSL");
    assert_int_eq(TCP_RECV, test_last_direction, "successful read preserves direction");
    assert_u16_eq(443, test_last_orig_dport, "successful read preserves original dport");
}

static void test_failed_write_skips_parser_after_cleanup(void) {
    reset();
    seed_existing_ssl_connection(443);
    ssl_args_t args = ssl_args();

    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 0, TCP_SEND);

    assert_int_eq(1, ssl_pid_tid_delete_count, "ssl_to_pid_tid entry is deleted on failed write");
    assert_int_eq(0, ssl_to_conn_update_count, "failed write does not create connection info");
    assert_int_eq(0, test_parser_call_count, "failed write does not enter protocol parsing");
}

static void test_successful_write_still_parses(void) {
    reset();
    seed_existing_ssl_connection(443);
    ssl_args_t args = ssl_args();

    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 32, TCP_SEND);

    assert_int_eq(1, ssl_pid_tid_delete_count, "ssl_to_pid_tid entry is deleted on write success");
    assert_int_eq(0, ssl_to_conn_update_count, "existing connection is reused");
    assert_int_eq(1, test_parser_call_count, "successful write enters protocol parsing");
    assert_int_eq(32, test_last_parser_bytes_len, "successful write forwards the written length");
    assert_int_eq(WITH_SSL, test_last_ssl, "successful write is marked as SSL");
    assert_int_eq(TCP_SEND, test_last_direction, "successful write preserves direction");
    assert_u16_eq(443, test_last_orig_dport, "successful write preserves original dport");
}

static void test_successful_read_can_create_fake_connection(void) {
    reset();
    ssl_args_t args = ssl_args();

    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 128, TCP_RECV);

    assert_int_eq(1, ssl_pid_tid_delete_count, "ssl_to_pid_tid entry is deleted");
    assert_int_eq(1, ssl_to_conn_update_count, "positive read can create fake connection info");
    assert_int_eq(42, (int)test_ssl_conn.p_conn.pid, "fake connection uses current pid");
    assert_int_eq(1, test_parser_call_count, "positive read enters protocol parsing");
    assert_int_eq(128, test_last_parser_bytes_len, "positive read forwards the read length");
}

static void test_successful_read_can_reuse_mapped_pid_tid_connection(void) {
    reset();
    test_mapped_pid_tid = 0x2a00000002ULL;
    test_mapped_pid_tid_available = 1;
    test_ssl_conn.orig_dport = 8443;
    test_ssl_conn.p_conn.pid = 42;
    ssl_args_t args = ssl_args();

    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 64, TCP_RECV);

    assert_int_eq(1, ssl_pid_tid_delete_count, "ssl_to_pid_tid entry is deleted");
    assert_int_eq(1, pid_tid_delete_count, "current pid_tid mapping is removed after reuse");
    assert_int_eq(1, ssl_to_conn_update_count, "mapped pid_tid connection is cached by ssl");
    assert_int_eq(1, test_parser_call_count, "mapped pid_tid connection enters protocol parsing");
    assert_int_eq(64, test_last_parser_bytes_len, "mapped pid_tid read forwards the read length");
    assert_u16_eq(8443, test_last_orig_dport, "mapped pid_tid connection preserves original dport");
}

static void test_tentative_connection_is_reevaluated(void) {
    reset();
    seed_existing_ssl_connection(8080);
    test_ssl_conn.tentative = 1; // Mark existing as tentative guess

    test_mapped_pid_tid = 0x2a00000001ULL;
    test_mapped_pid_tid_available = 1;

    ssl_args_t args = ssl_args();
    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 64, TCP_RECV);

    assert_int_eq(1, ssl_to_conn_update_count, "tentative connection is re-evaluated and updated");
    assert_int_eq(1, (int)test_ssl_conn.tentative, "updated fallback connection remains marked tentative");
}

static void test_confirmed_connection_is_not_overwritten(void) {
    reset();
    seed_existing_ssl_connection(6379);
    test_ssl_conn.tentative = 0; // Mark existing as confirmed socket connection

    test_mapped_pid_tid = 0x2a00000001ULL;
    test_mapped_pid_tid_available = 1;

    ssl_args_t args = ssl_args();
    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 64, TCP_RECV);

    assert_int_eq(0, ssl_to_conn_update_count, "confirmed connection is preserved and not overwritten");
    assert_u16_eq(6379, test_last_orig_dport, "confirmed connection dport is preserved");
}

static void test_missing_args_noops(void) {
    reset();

    handle_ssl_buf(NULL, 0x2a00000001ULL, NULL, 128, TCP_RECV);

    assert_int_eq(0, ssl_pid_tid_delete_count, "missing args do not touch ssl_to_pid_tid");
    assert_int_eq(0, ssl_to_conn_update_count, "missing args do not create connection info");
    assert_int_eq(0, test_parser_call_count, "missing args do not enter protocol parsing");
}

int main(void) {
    test_failed_read_skips_parser_after_cleanup();
    test_eof_read_skips_parser_after_cleanup();
    test_successful_read_still_parses();
    test_failed_write_skips_parser_after_cleanup();
    test_successful_write_still_parses();
    test_successful_read_can_create_fake_connection();
    test_successful_read_can_reuse_mapped_pid_tid_connection();
    test_tentative_connection_is_reevaluated();
    test_confirmed_connection_is_not_overwritten();
    test_missing_args_noops();

    return 0;
}
