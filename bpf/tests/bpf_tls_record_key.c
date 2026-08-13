// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Framing rules for the ciphertext correlation key.
//
// Both ends derive the same key from the same record. The clamp to the TLS
// record length is what delivers that, and an unclamped reader still produces a
// key, so the agreement is worth asserting directly.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <common/tls_record.h>

static int failures;

static void check(int ok, const char *message) {
    if (!ok) {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

// A TLS record header declaring `fragment_len` bytes of payload.
static void put_hdr(unsigned char *buf, unsigned char content_type, unsigned int fragment_len) {
    buf[0] = content_type;
    buf[1] = 0x03;
    buf[2] = 0x03;
    buf[3] = (unsigned char)(fragment_len >> 8);
    buf[4] = (unsigned char)(fragment_len & 0xff);
}

static void test_rejects_non_tls(void) {
    unsigned char buf[64] = {0};

    memcpy(buf, "GET /health HTTP/1.1\r\n", 22);
    check(tls_record_key_len(buf, 22) == 0, "plaintext HTTP is not mistaken for a TLS record");

    put_hdr(buf, 0x99, 100);
    check(tls_record_key_len(buf, 64) == 0, "an unknown content type is rejected");

    put_hdr(buf, k_tls_ct_app_data, 100);
    buf[1] = 0x02;
    check(tls_record_key_len(buf, 64) == 0, "a non 0x03 version major is rejected");

    put_hdr(buf, k_tls_ct_app_data, 0);
    check(tls_record_key_len(buf, 64) == 0, "an empty fragment is rejected");

    put_hdr(buf, k_tls_ct_app_data, 100);
    check(tls_record_key_len(buf, 4) == 0, "a buffer shorter than the header is rejected");
}

// A ClientHello, whose record is far longer than the key width.
// The cheap gate the socket send path runs before building a key. It must agree
// with tls_record_key_len about what is not a TLS record, or plaintext sends
// would still pay for a key and a map lookup.
static void test_plausible_start_gate(void) {
    unsigned char buf[64] = {0};

    memcpy(buf, "GET /health HTTP/1.1\r\n", 22);
    check(!tls_record_plausible_start(buf, 22), "plaintext HTTP does not pass the gate");

    put_hdr(buf, 0x99, 100);
    check(!tls_record_plausible_start(buf, 64), "an unknown content type does not pass the gate");

    put_hdr(buf, k_tls_ct_app_data, 100);
    buf[1] = 0x02;
    check(!tls_record_plausible_start(buf, 64), "a non 0x03 version major does not pass the gate");

    put_hdr(buf, k_tls_ct_app_data, 100);
    check(tls_record_plausible_start(buf, 64), "an application data record passes the gate");
    check(tls_record_plausible_start(buf, 4) == 0, "a buffer shorter than the header is rejected");
}

static void test_client_hello(void) {
    unsigned char buf[64] = {0};

    put_hdr(buf, k_tls_ct_handshake, 0x0640);
    check(tls_record_key_len(buf, 1605) == k_tls_prefix_max,
          "a full ClientHello yields a full width key");
}

// The case the clamp exists for. The BIO sees one record; the socket sees that
// record with more behind it. Both must derive the same bytes.
static void test_coalesced_socket_write_matches_the_single_record(void) {
    unsigned char record[64] = {0};
    unsigned char coalesced[256] = {0};

    // A short application data record: 5 byte header + 1 content type + 16 byte
    // AEAD tag + 9 bytes of Redis command.
    const unsigned int fragment = 26;

    put_hdr(record, k_tls_ct_app_data, fragment);
    for (unsigned int i = 0; i < fragment; i++) {
        record[k_tls_hdr_len + i] = (unsigned char)(0xa0 + i);
    }

    const unsigned int record_len = k_tls_hdr_len + fragment;

    memcpy(coalesced, record, record_len);
    put_hdr(coalesced + record_len, k_tls_ct_app_data, 200);
    memset(coalesced + record_len + k_tls_hdr_len, 0x5c, 200);

    tls_prefix_key_t from_bio;
    tls_prefix_key_t from_socket;

    // The BIO side sees exactly the record.
    check(tls_prefix_key_from_buf(&from_bio, record, record_len, record_len) == record_len,
          "the BIO side keys the whole short record");

    // The socket side sees the record plus 205 more bytes behind it.
    check(tls_prefix_key_from_buf(&from_socket, coalesced, sizeof(coalesced), record_len + 205) ==
              record_len,
          "the socket side stops at the record boundary");

    check(memcmp(&from_bio, &from_socket, sizeof(from_bio)) == 0,
          "a coalesced socket write derives the same key as the single record");

    // Without the clamp the socket side would have read k_tls_prefix_max bytes
    // and run into the second record, so the keys would differ. Assert that the
    // bytes past the record really are different, which is what gives the
    // agreement above its meaning.
    check(coalesced[record_len] != 0, "the coalesced buffer really does carry a second record");
    check(record_len < k_tls_prefix_max,
          "the record is shorter than the key width, so an unclamped reader would overrun");
}

static void test_partial_write_of_a_long_record(void) {
    unsigned char buf[64] = {0};

    put_hdr(buf, k_tls_ct_app_data, 4000);

    // Both ends cap at the key width long before the record ends, so a socket
    // that only carried part of a long record still derives the same key.
    check(tls_record_key_len(buf, 4005) == k_tls_prefix_max, "full send of a long record");
    check(tls_record_key_len(buf, 500) == k_tls_prefix_max, "partial send of a long record");
}

static void test_key_is_fully_initialised(void) {
    unsigned char buf[64];
    tls_prefix_key_t key;

    memset(buf, 0xff, sizeof(buf));
    put_hdr(buf, k_tls_ct_app_data, 10);

    memset(&key, 0xaa, sizeof(key));

    const unsigned int key_len = tls_prefix_key_from_buf(&key, buf, 15, 15);

    check(key_len == 15, "a short record keys at its own length");
    check(key.len == 15, "the key records its length");

    for (unsigned int i = key_len; i < k_tls_prefix_max; i++) {
        check(key.bytes[i] == 0, "bytes past the record are zeroed");
    }

    for (unsigned int i = 0; i < sizeof(key._pad); i++) {
        check(key._pad[i] == 0, "padding is zeroed so map lookups compare equal");
    }
}

// A key must not be derivable from fewer bytes than it claims, or the two ends
// would key different amounts of the same record.
static void test_refuses_to_key_more_than_was_copied(void) {
    unsigned char buf[8] = {0};
    tls_prefix_key_t key;

    put_hdr(buf, k_tls_ct_app_data, 100);

    check(tls_prefix_key_from_buf(&key, buf, 6, 105) == 0,
          "a key wider than the copied bytes is refused");
}

// The copy loop is unrolled over a constant width, so a per-byte predicate on
// its own still leaves the tail free to load. Place a record shorter than the
// key width right against an unmapped page, so any fixed-width read of the
// source faults.
static void test_never_reads_past_the_copied_bytes(void) {
    const long page = sysconf(_SC_PAGESIZE);
    unsigned char *region =
        mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (region == MAP_FAILED) {
        check(0, "guard page mapping");
        return;
    }

    // Second page unmapped, so the first page's last byte is the last readable
    // byte in the region.
    mprotect(region + page, page, PROT_NONE);

    const unsigned int fragment = 10;
    const unsigned int record_len = k_tls_hdr_len + fragment;
    unsigned char *record = region + page - record_len;

    put_hdr(record, k_tls_ct_app_data, fragment);
    for (unsigned int i = 0; i < fragment; i++) {
        record[k_tls_hdr_len + i] = (unsigned char)(0xc0 + i);
    }

    tls_prefix_key_t key;

    check(tls_prefix_key_from_buf(&key, record, record_len, record_len) == record_len,
          "a record ending at a page boundary is keyed without reading past it");
    check(memcmp(key.bytes, record, record_len) == 0, "the key holds the record's bytes");

    munmap(region, page * 2);
}

int main(void) {
    test_rejects_non_tls();
    test_plausible_start_gate();
    test_client_hello();
    test_coalesced_socket_write_matches_the_single_record();
    test_partial_write_of_a_long_record();
    test_key_is_fully_initialised();
    test_refuses_to_key_more_than_was_copied();
    test_never_reads_past_the_copied_bytes();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }

    printf("bpf_tls_record_key: all checks passed\n");
    return 0;
}
