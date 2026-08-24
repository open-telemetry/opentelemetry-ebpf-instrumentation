// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// DNS header extraction in handle_dns_buf (generictracer/dns.h). The buffer it
// parses is scratch memory from iovec_memory(), which is a BPF map, so reading
// it needs the kernel probe helper: a user read fails, silently zeroing the
// header, which loses the transaction id and makes every record look like a
// query.
//
// Run from repo root:
//   make -C bpf/tests bpf_dns_header && bpf/tests/bpf_dns_header

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
// included ahead of the override below, so the include chain does not redefine it
#include <bpfcore/bpf_core_read.h>

// Called by the dns.h include chain, omitted by the shared stub
#define BPF_ANY 0

static inline u32 bpf_get_prandom_u32(void) {
    return 0;
}

static inline long bpf_loop(u32 nr_loops, void *cb, void *ctx, u64 flags) {
    return 0;
}

static inline long bpf_skb_load_bytes(const void *skb, u32 offset, void *to, u32 len) {
    return 0;
}

// The shared stubs no-op every read and map lookup, so live mocks are supplied
// below and macro-shadowed over the include.

// Host-resident structs, so a direct field access stands in for the CO-RE read.
// The shared stub copies a zero value instead.
#undef BPF_CORE_READ_INTO
#define BPF_CORE_READ_INTO(dst, src, field) (*(dst) = (src)->field)

static long test_probe_read_kernel(void *dst, u32 size, const void *src) {
    if (!src) {
        return -1;
    }
    memcpy(dst, src, size);
    return 0;
}

// Mirrors a user read of kernel memory: it fails and zeroes the destination.
// Unused while the code reads correctly; kept so a regression to
// bpf_probe_read_user fails deterministically rather than on uninitialized stack.
__attribute__((unused)) static long test_probe_read_user(void *dst, u32 size, const void *src) {
    (void)src;
    memset(dst, 0, size);
    return -1;
}

// handle_dns_buf bails unless sock_pids resolves the connection
static void *test_sock_pids_map;
static unsigned char test_conn_pid[128];

static void *test_map_lookup(void *map, const void *key) {
    (void)key;
    if (test_sock_pids_map != NULL && map == test_sock_pids_map) {
        return test_conn_pid;
    }
    return NULL;
}

// Captures the record handle_dns_buf reserves, so the test can inspect it
static unsigned char test_record[4096];
static bool test_record_submitted;

static void *test_ringbuf_reserve(void *rb, u64 size, u64 flags) {
    (void)rb;
    (void)flags;
    if (size > sizeof(test_record)) {
        return NULL;
    }
    memset(test_record, 0, sizeof(test_record));
    return test_record;
}

static void test_ringbuf_submit(void *data, u64 flags) {
    (void)data;
    (void)flags;
    test_record_submitted = true;
}

#define bpf_probe_read_kernel test_probe_read_kernel
#define bpf_probe_read_user test_probe_read_user
#define bpf_map_lookup_elem test_map_lookup
#define bpf_ringbuf_reserve test_ringbuf_reserve
#define bpf_ringbuf_submit test_ringbuf_submit

#include <generictracer/dns.h>

#undef bpf_probe_read_kernel
#undef bpf_probe_read_user
#undef bpf_map_lookup_elem
#undef bpf_ringbuf_reserve
#undef bpf_ringbuf_submit

// Test harness

static int failures = 0;

static void check_u16(const char *name, u16 expected, u16 actual) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %u, got %u\n", name, expected, actual);
        failures++;
        return;
    }
    printf("ok: %s\n", name);
}

static void check_u8(const char *name, u8 expected, u8 actual) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %u, got %u\n", name, expected, actual);
        failures++;
        return;
    }
    printf("ok: %s\n", name);
}

// Header plus one question for "a.example.com"
static int build_dns_message(unsigned char *buf, u16 id, u16 flags) {
    static const unsigned char question[] = "\x01"
                                            "a"
                                            "\x07"
                                            "example"
                                            "\x03"
                                            "com"
                                            "\x00"
                                            "\x00\x01"
                                            "\x00\x01";
    int off = 0;
    buf[off++] = (unsigned char)(id >> 8);
    buf[off++] = (unsigned char)(id & 0xff);
    buf[off++] = (unsigned char)(flags >> 8);
    buf[off++] = (unsigned char)(flags & 0xff);
    buf[off++] = 0;
    buf[off++] = 1;          // qdcount
    memset(buf + off, 0, 6); // ancount, nscount, arcount
    off += 6;
    memcpy(buf + off, question, sizeof(question) - 1);
    return off + (int)(sizeof(question) - 1);
}

static dns_req_t *run_handle_dns_buf(u16 id, u16 flags) {
    unsigned char buf[512] = {0};
    const int len = build_dns_message(buf, id, flags);

    pid_connection_info_t p_conn = {0};
    p_conn.conn.s_port = 40100;
    p_conn.conn.d_port = 53;

    test_record_submitted = false;
    handle_dns_buf(buf, len, &p_conn, 53);

    return test_record_submitted ? (dns_req_t *)test_record : NULL;
}

static void test_query_id_is_extracted(void) {
    dns_req_t *req = run_handle_dns_buf(3178, 0x0100);

    check_u8("a query is recorded", 1, req != NULL);
    if (req) {
        check_u16("the wire transaction id survives extraction", 3178, req->id);
        check_u8("a query is recorded as a query", k_dns_qr_query, req->dns_q);
    }
}

static void test_answer_id_is_extracted(void) {
    dns_req_t *req = run_handle_dns_buf(3178, 0x8180);

    check_u8("an answer is recorded", 1, req != NULL);
    if (req) {
        check_u16("the answer carries the same transaction id", 3178, req->id);
        check_u8("an answer is recorded as an answer", k_dns_qr_resp, req->dns_q);
    }
}

// Pairing keys on the id, so distinct transactions must not collapse onto one
static void test_ids_are_distinct(void) {
    dns_req_t *first = run_handle_dns_buf(3178, 0x0100);
    u16 first_id = first ? first->id : 0;
    dns_req_t *second = run_handle_dns_buf(4242, 0x0100);
    u16 second_id = second ? second->id : 0;

    check_u8("two transactions yield different ids", 1, first_id != second_id);
}

int main(void) {
    test_sock_pids_map = &sock_pids;

    test_query_id_is_extracted();
    test_answer_id_is_extracted();
    test_ids_are_distinct();

    if (failures > 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("all DNS header extraction tests passed\n");
    return 0;
}
