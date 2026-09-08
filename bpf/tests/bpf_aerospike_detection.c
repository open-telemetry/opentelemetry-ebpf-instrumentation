// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The following code is copied from bpf/generictracer/protocol_aerospike.h and
 * adapted to run as a host unit test. The functions under test are:
 *
 *   static __always_inline u64 aerospike_body_len(const unsigned char *hdr);
 *   static __always_inline u8 is_aerospike(connection_info_t *conn_info,
 *                                          const unsigned char *data,
 *                                          u32 data_len,
 *                                          enum protocol_type *protocol_type);
 *
 * The BPF-only helpers (bpf_probe_read, bpf_map_update_elem and the
 * protocol_cache map) are mocked below. The real header cannot be #included
 * directly on a non-BPF target because its map definitions use SEC(".maps").
 *
 * These tests pin down the classification signature: only type-3 AS_MSG frames
 * with the proto version, the fixed as_msg header size, and a sane body length
 * may classify a connection, while info/security/compressed frames and split
 * header-only reads must be left unclassified.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

// Mocks for the BPF runtime helpers used by is_aerospike.
typedef struct connection_info {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
} connection_info_t;

enum protocol_type {
    k_protocol_type_unknown = 0,
    k_protocol_type_mysql = 1,
    k_protocol_type_aerospike = 10,
};

#define BPF_ANY 0

#ifndef __always_inline
#define __always_inline inline
#endif

static int bpf_probe_read(void *dst, u32 size, const void *src) {
    memcpy(dst, src, size);
    return 0;
}

// Discard the formatted debug output, mirroring bpf_dbg_printk when BPF debug
// is disabled.
#define bpf_dbg_printk(...) ((void)0)

// The protocol_cache map is reduced to a single slot that records the last
// written protocol so the tests can assert the classification side effect.
static int protocol_cache;
static enum protocol_type cached_protocol = k_protocol_type_unknown;

static long bpf_map_update_elem(void *map, const void *key, const void *value, u64 flags) {
    (void)map;
    (void)key;
    (void)flags;
    cached_protocol = *(const enum protocol_type *)value;
    return 0;
}

// Code under test (copied verbatim from protocol_aerospike.h).

enum {
    k_aerospike_proto_header_len = 8,
    k_aerospike_proto_version = 2,
    k_aerospike_msg_type_as_msg = 3,
    k_aerospike_as_msg_header_len = 22,
    // largest declared proto body we treat as plausibly Aerospike;
    // matches asMaxBodyLen in the userspace parser
    k_aerospike_max_body_len = 128 * 1024 * 1024,
};

static __always_inline u64 aerospike_body_len(const unsigned char *hdr) {
    return ((u64)hdr[2] << 40) | ((u64)hdr[3] << 32) | ((u64)hdr[4] << 24) | ((u64)hdr[5] << 16) |
           ((u64)hdr[6] << 8) | (u64)hdr[7];
}

static __always_inline u8 is_aerospike(connection_info_t *conn_info,
                                       const unsigned char *data,
                                       u32 data_len,
                                       enum protocol_type *protocol_type) {
    if (*protocol_type == k_protocol_type_aerospike) {
        return 1;
    }
    if (*protocol_type != k_protocol_type_unknown) {
        return 0;
    }

    // require the full proto + as_msg headers so the signature check below is meaningful
    if (data_len < k_aerospike_proto_header_len + k_aerospike_as_msg_header_len) {
        return 0;
    }

    unsigned char hdr[k_aerospike_proto_header_len + 1];
    if (bpf_probe_read(hdr, sizeof(hdr), data) != 0) {
        return 0;
    }

    if (hdr[0] != k_aerospike_proto_version || hdr[1] != k_aerospike_msg_type_as_msg ||
        hdr[8] != k_aerospike_as_msg_header_len) {
        return 0;
    }

    const u64 body_len = aerospike_body_len(hdr);
    if (body_len < k_aerospike_as_msg_header_len || body_len > k_aerospike_max_body_len) {
        return 0;
    }

    *protocol_type = k_protocol_type_aerospike;
    bpf_map_update_elem(&protocol_cache, conn_info, protocol_type, BPF_ANY);
    return 1;
}

// Test harness

static int failures = 0;

static void check(const char *name, u8 expected, u8 actual) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected is_aerospike=%u, got %u\n", name, expected, actual);
        failures++;
    } else {
        printf("ok: %s\n", name);
    }
}

static void check_u64(const char *name, u64 expected, u64 actual) {
    if (expected != actual) {
        fprintf(stderr,
                "FAIL: %s\n  expected %llu, got %llu\n",
                name,
                (unsigned long long)expected,
                (unsigned long long)actual);
        failures++;
    } else {
        printf("ok: %s\n", name);
    }
}

// Writes an 8-byte proto header (version, type, 48-bit big-endian body length)
// followed by the first as_msg header byte (header_sz). The rest of the buffer
// is left as-is; is_aerospike never reads past byte 8.
static void put_frame(unsigned char *buf, u8 version, u8 type, u64 body_len, u8 header_sz) {
    buf[0] = version;
    buf[1] = type;
    for (int i = 0; i < 6; i++) {
        buf[2 + i] = (unsigned char)(body_len >> (8 * (5 - i)));
    }
    buf[8] = header_sz;
}

static u8 classify(const unsigned char *data, u32 len) {
    connection_info_t conn = {0};
    enum protocol_type pt = k_protocol_type_unknown;
    cached_protocol = k_protocol_type_unknown;
    return is_aerospike(&conn, data, len, &pt);
}

static void test_valid_as_msg_frame(void) {
    unsigned char buf[64] = {0};
    put_frame(buf, 2, 3, 56, 22); // 56-byte body: as_msg header + a namespace field

    connection_info_t conn = {0};
    enum protocol_type pt = k_protocol_type_unknown;
    cached_protocol = k_protocol_type_unknown;

    check("valid type-3 AS_MSG frame", 1, is_aerospike(&conn, buf, sizeof(buf), &pt));
    check("classification sets protocol_type", k_protocol_type_aerospike, (u8)pt);
    check("classification updates protocol_cache", k_protocol_type_aerospike, (u8)cached_protocol);
}

static void test_minimum_length_frame(void) {
    unsigned char buf[30] = {0}; // exactly proto header + as_msg header
    put_frame(buf, 2, 3, 22, 22);
    check("30-byte frame (headers only)", 1, classify(buf, sizeof(buf)));
}

static void test_already_classified_aerospike(void) {
    // Garbage bytes: an already classified connection short-circuits before parsing.
    unsigned char buf[8] = {0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0};
    connection_info_t conn = {0};
    enum protocol_type pt = k_protocol_type_aerospike;
    check(
        "already classified aerospike, any buffer", 1, is_aerospike(&conn, buf, sizeof(buf), &pt));
}

static void test_classified_as_other_protocol(void) {
    unsigned char buf[64] = {0};
    put_frame(buf, 2, 3, 56, 22); // valid aerospike bytes

    connection_info_t conn = {0};
    enum protocol_type pt = k_protocol_type_mysql;
    check(
        "connection classified as another protocol", 0, is_aerospike(&conn, buf, sizeof(buf), &pt));
}

static void test_info_frame_rejected(void) {
    // Type-1 info (tend) frame as captured on the wire: "node\t..." ASCII body.
    unsigned char buf[71] = {0};
    put_frame(buf, 2, 1, 63, 'n'); // byte 8 is the first body byte 'n' of "node"
    memcpy(buf + 9, "ode\tBB9146B478C3844\n", 20);
    check("type-1 info (tend) frame", 0, classify(buf, sizeof(buf)));
}

static void test_security_frame_rejected(void) {
    unsigned char buf[64] = {0};
    put_frame(buf, 2, 2, 56, 22);
    check("type-2 security frame", 0, classify(buf, sizeof(buf)));
}

static void test_compressed_frame_rejected(void) {
    unsigned char buf[64] = {0};
    put_frame(buf, 2, 4, 56, 22);
    check("type-4 compressed frame", 0, classify(buf, sizeof(buf)));
}

static void test_wrong_version_rejected(void) {
    unsigned char buf[64] = {0};
    put_frame(buf, 3, 3, 56, 22);
    check("proto version other than 2", 0, classify(buf, sizeof(buf)));
}

static void test_wrong_as_msg_header_size_rejected(void) {
    unsigned char buf[64] = {0};
    put_frame(buf, 2, 3, 56, 30);
    check("as_msg header_sz other than 22", 0, classify(buf, sizeof(buf)));
}

static void test_body_shorter_than_as_msg_header_rejected(void) {
    unsigned char buf[64] = {0};
    put_frame(buf, 2, 3, 8, 22); // declared body cannot hold the 22-byte as_msg header
    check("declared body shorter than as_msg header", 0, classify(buf, sizeof(buf)));
}

static void test_body_over_max_rejected(void) {
    unsigned char buf[64] = {0};
    put_frame(buf, 2, 3, (u64)k_aerospike_max_body_len + 1, 22);
    check("declared body over 128MB cap", 0, classify(buf, sizeof(buf)));
}

static void test_split_header_only_read_rejected(void) {
    // A client reading the 8-byte proto header separately (split read) must not
    // be classified from the header alone.
    unsigned char buf[9] = {0}; // room for put_frame's header_sz byte; only 8 bytes are passed
    put_frame(buf, 2, 3, 56, 22);
    check("8-byte header-only read", 0, classify(buf, 8));
}

static void test_one_byte_short_of_minimum_rejected(void) {
    unsigned char buf[29] = {0};
    put_frame(buf, 2, 3, 22, 22);
    check("29-byte frame (one short of headers)", 0, classify(buf, sizeof(buf)));
}

static void test_body_len_decoding(void) {
    unsigned char buf[9] = {0};
    put_frame(buf, 2, 3, 0x0000AABBCCDDEEFF & 0xFFFFFFFFFFFF, 22);
    check_u64("48-bit big-endian body length decoding",
              0x0000AABBCCDDEEFF & 0xFFFFFFFFFFFF,
              aerospike_body_len(buf));
}

int main(void) {
    test_valid_as_msg_frame();
    test_minimum_length_frame();
    test_already_classified_aerospike();
    test_classified_as_other_protocol();
    test_info_frame_rejected();
    test_security_frame_rejected();
    test_compressed_frame_rejected();
    test_wrong_version_rejected();
    test_wrong_as_msg_header_size_rejected();
    test_body_shorter_than_as_msg_header_rejected();
    test_body_over_max_rejected();
    test_split_header_only_read_rejected();
    test_one_byte_short_of_minimum_rejected();
    test_body_len_decoding();

    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }

    printf("all aerospike detection tests passed\n");
    return 0;
}
