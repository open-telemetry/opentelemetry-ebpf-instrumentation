// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run from repo root:
//   make -C bpf/tests test_send_buffer_socket && bpf/tests/test_send_buffer_socket
// Run from bpf/tests:
//   make test_send_buffer_socket && ./test_send_buffer_socket

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

enum { BPF_ANY = 0, BPF_NOEXIST = 1 };

struct bpf_test_map {
    int id;
};

static void *test_map_lookup(void *map, const void *key);
static long test_map_delete(void *map, const void *key);

#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_delete_elem test_map_delete

#include <generictracer/send_buffer.h>

#undef bpf_map_lookup_elem
#undef bpf_map_delete_elem

struct bpf_test_map active_send_args = {.id = 1};
struct bpf_test_map sock_filter_buffers = {.id = 2};

int test_parser_call_count;
int test_last_parser_bytes_len;
u8 test_last_ssl;
u8 test_last_direction;
u16 test_last_orig_dport;
void *test_last_sock;

static backup_buffer_t test_backup;
static int test_backup_present;
static int test_send_args_deleted;

static void *test_map_lookup(void *map, const void *key) {
    (void)key;
    if (map == &sock_filter_buffers) {
        return test_backup_present ? &test_backup : NULL;
    }
    return NULL;
}

static long test_map_delete(void *map, const void *key) {
    (void)key;
    if (map == &active_send_args) {
        test_send_args_deleted++;
    }
    return 0;
}

static int failures;

static void assert_true(int cond, const char *what) {
    if (cond) {
        printf("PASS: %s\n", what);
        return;
    }
    printf("FAIL: %s\n", what);
    failures++;
}

static void reset(void) {
    test_backup_present = 1;
    test_send_args_deleted = 0;
    // Seed non-null so an assertion of null is a claim rather than an artefact of
    // the stub never having been called.
    test_last_sock = (void *)0xdeadbeef;
    test_parser_call_count = 0;
}

// The kretprobe has no socket of its own, so the one recorded by the entry kprobe is
// what reaches the parser. Without it every record finished on this path keeps a zero
// baseline, reads the connection's whole history as an advance, and never reports that
// nothing came back.
static void test_recorded_socket_reaches_the_parser(void) {
    reset();

    struct sock *const recorded = (struct sock *)0x1234;
    send_args_t s_args = {
        .size = 64,
        .orig_dport = 8080,
        .buffer_read = 0,
        .sock_ptr = (u64)recorded,
    };

    flush_backup_send_buffer(NULL, 42, &s_args);

    assert_true(test_parser_call_count == 1, "a captured buffer is handed to the parser");
    assert_true(test_last_sock == (void *)recorded,
                "the parser gets the socket the kprobe recorded");
    assert_true(test_send_args_deleted == 1, "the send args are consumed");
}

// A send whose buffer was already read inline needs no flush, and must not consume the
// send args a later probe still depends on.
static void test_buffer_already_read_is_not_flushed(void) {
    reset();

    send_args_t s_args = {.size = 64, .buffer_read = 1, .sock_ptr = 0x1234};

    flush_backup_send_buffer(NULL, 42, &s_args);

    assert_true(test_parser_call_count == 0, "an already-read buffer is not flushed again");
    assert_true(test_send_args_deleted == 0, "the send args survive");
}

// Nothing was captured for this connection, so there is nothing to hand over.
static void test_absent_backup_is_not_flushed(void) {
    reset();
    test_backup_present = 0;

    send_args_t s_args = {.size = 64, .buffer_read = 0, .sock_ptr = 0x1234};

    flush_backup_send_buffer(NULL, 42, &s_args);

    assert_true(test_parser_call_count == 0, "no captured buffer means no parser call");
    assert_true(test_send_args_deleted == 0, "the send args survive");
}

int main(void) {
    test_recorded_socket_reaches_the_parser();
    test_buffer_already_read_is_not_flushed();
    test_absent_backup_is_not_flushed();

    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }

    printf("all assertions passed\n");
    return 0;
}
