// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The following parsing helpers are copied from bpf/generictracer/nodejs.c and
 * adapted to run as a host unit test. The functions under test are:
 *
 *   static __always_inline int nodejs_parse_hex_u64(const unsigned char *buf,
 *                                                   u64 *out);
 *   static __always_inline int nodejs_v8_parse_gc(const unsigned char *payload,
 *                                                 u64 len,
 *                                                 u8 *kind,
 *                                                 u64 *duration_ns);
 *   static __always_inline int nodejs_v8_parse_numbers_name(
 *       const unsigned char *payload, u64 len, u64 *vals, u8 num_fields,
 *       u8 *name_len);
 *
 * The payload is what bpf_probe_read_user_str() returns for the path bytes
 * after "/dev/null/obi-v8/<kind char>": len includes the terminating NUL.
 *
 * These tests pin the wire format of the v8js record kinds:
 *   g: <kind:1 hex><duration_ns:16 hex>                       (exact length)
 *   h: <4 x u64 as 16 hex><space name, 1..32 bytes, to NUL>   (name LAST)
 *   a: <count:16 hex><resource type, 1..32 bytes, to NUL>     (name LAST)
 * Any non-hex digit, wrong length, empty name or missing NUL must reject;
 * a zero count is valid (the vanished-type explicit zero).
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

#ifndef __always_inline
#define __always_inline inline
#endif

enum {
    k_rt_field_hex_len = 16,
    k_nodejs_heap_space_name_max = 32,
    k_nodejs_resource_type_max = 32,
};

enum {
    // g payload: 1 kind char + 16 hex duration chars (+ NUL when read)
    k_v8_gc_payload_len = 1 + k_rt_field_hex_len,
    k_v8_heap_num_fields = 4,
    k_v8_heap_numbers_len = k_v8_heap_num_fields * k_rt_field_hex_len,
    k_v8_resource_num_fields = 1,
    k_v8_resource_numbers_len = k_v8_resource_num_fields * k_rt_field_hex_len,
    // shared trailing-name cap of the numbers+name records ('h', 'a')
    k_v8_name_max = k_nodejs_heap_space_name_max,
    // h payload upper bound: numbers + name + NUL (the longest v8 record)
    k_v8_heap_payload_read_len = k_v8_heap_numbers_len + k_nodejs_heap_space_name_max + 1,
};

_Static_assert(k_nodejs_heap_space_name_max == k_nodejs_resource_type_max,
               "v8 records with a trailing name share one parser and one name cap");

// --- code under test (keep in sync with bpf/generictracer/nodejs.c) ---

static __always_inline int nodejs_parse_hex_u64(const unsigned char *buf, u64 *out) {
    u64 v = 0;
    for (u8 i = 0; i < k_rt_field_hex_len; ++i) {
        const unsigned char c = buf[i];
        u8 digit;
        if (c >= '0' && c <= '9') {
            digit = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            digit = c - 'a' + 10;
        } else {
            return -1;
        }
        v = (v << 4) | digit;
    }
    *out = v;
    return 0;
}

static __always_inline int
nodejs_v8_parse_gc(const unsigned char *payload, u64 len, u8 *kind, u64 *duration_ns) {
    // len counts the NUL: the payload must be exactly kind + duration
    if (len != k_v8_gc_payload_len + 1) {
        return -1;
    }
    const unsigned char c = payload[0];
    if (c >= '0' && c <= '9') {
        *kind = c - '0';
    } else if (c >= 'a' && c <= 'f') {
        *kind = c - 'a' + 10;
    } else {
        return -1;
    }
    return nodejs_parse_hex_u64(payload + 1, duration_ns);
}

// Parses the numbers+name records ('h': 4 numbers, 'a': 1): num_fields
// fixed-width u64s at fixed offsets, then a 1..k_v8_name_max byte name ended
// by the NUL that len counts.
static __always_inline int nodejs_v8_parse_numbers_name(
    const unsigned char *payload, u64 len, u64 *vals, u8 num_fields, u8 *name_len) {
    const u32 numbers_len = (u32)num_fields * k_rt_field_hex_len;
    // len counts the NUL: at least one name byte, at most the name cap
    if (len < numbers_len + 1 + 1 || len > numbers_len + k_v8_name_max + 1) {
        return -1;
    }
    for (u8 f = 0; f < num_fields; ++f) {
        if (nodejs_parse_hex_u64(payload + (u32)f * k_rt_field_hex_len, &vals[f]) != 0) {
            return -1;
        }
    }
    *name_len = (u8)(len - 1 - numbers_len);
    return 0;
}

// --- test helpers ---

static int failures = 0;

static void check(const char *name, int expected, int actual) {
    if (expected != actual) {
        fprintf(stderr, "FAIL %s: expected %d, got %d\n", name, expected, actual);
        failures++;
    }
}

static void check_u64(const char *name, u64 expected, u64 actual) {
    if (expected != actual) {
        fprintf(stderr,
                "FAIL %s: expected %llu, got %llu\n",
                name,
                (unsigned long long)expected,
                (unsigned long long)actual);
        failures++;
    }
}

static void put_hex16(unsigned char *dst, u64 v) {
    static const char digits[] = "0123456789abcdef";
    for (int i = 15; i >= 0; --i) {
        dst[i] = digits[v & 0xF];
        v >>= 4;
    }
}

// builds a g payload as bpf_probe_read_user_str would deliver it; returns len
// including the NUL
static u64 put_gc(unsigned char *dst, char kind, u64 duration_ns) {
    dst[0] = kind;
    put_hex16(dst + 1, duration_ns);
    dst[k_v8_gc_payload_len] = '\0';
    return k_v8_gc_payload_len + 1;
}

// builds an h payload; returns len including the NUL
static u64 put_heap(unsigned char *dst, const u64 vals[4], const char *name) {
    for (int f = 0; f < 4; ++f) {
        put_hex16(dst + f * k_rt_field_hex_len, vals[f]);
    }
    const u64 name_len = strlen(name);
    memcpy(dst + k_v8_heap_numbers_len, name, name_len);
    dst[k_v8_heap_numbers_len + name_len] = '\0';
    return k_v8_heap_numbers_len + name_len + 1;
}

// --- tests ---

static void test_gc_valid(void) {
    unsigned char buf[64];
    const u64 len = put_gc(buf, '2', 350000000ULL); // 350ms major GC
    u8 kind = 0;
    u64 duration = 0;
    check("valid gc record parses", 0, nodejs_v8_parse_gc(buf, len, &kind, &duration));
    check("gc kind decodes", 2, kind);
    check_u64("gc duration decodes", 350000000ULL, duration);
}

static void test_gc_non_hex_kind_rejected(void) {
    unsigned char buf[64];
    const u64 len = put_gc(buf, 'x', 1000);
    u8 kind;
    u64 duration;
    check("non-hex gc kind", -1, nodejs_v8_parse_gc(buf, len, &kind, &duration));
}

static void test_gc_non_hex_duration_rejected(void) {
    unsigned char buf[64];
    const u64 len = put_gc(buf, '1', 1000);
    buf[5] = 'Z';
    u8 kind;
    u64 duration;
    check("non-hex gc duration digit", -1, nodejs_v8_parse_gc(buf, len, &kind, &duration));
}

static void test_gc_wrong_length_rejected(void) {
    unsigned char buf[64];
    u64 len = put_gc(buf, '1', 1000);
    u8 kind;
    u64 duration;
    check("gc payload one byte short", -1, nodejs_v8_parse_gc(buf, len - 1, &kind, &duration));
    check("gc payload one byte long", -1, nodejs_v8_parse_gc(buf, len + 1, &kind, &duration));
}

static void test_heap_valid(void) {
    unsigned char buf[128];
    const u64 in[4] = {200ULL << 20, 150ULL << 20, 30ULL << 20, 200ULL << 20};
    const u64 len = put_heap(buf, in, "old_space");
    u64 out[4] = {0};
    u8 name_len = 0;
    check("valid heap record parses",
          0,
          nodejs_v8_parse_numbers_name(buf, len, out, k_v8_heap_num_fields, &name_len));
    check_u64("heap space_size", in[0], out[0]);
    check_u64("heap space_used_size", in[1], out[1]);
    check_u64("heap space_available_size", in[2], out[2]);
    check_u64("heap physical_space_size", in[3], out[3]);
    check("heap name length", (int)strlen("old_space"), name_len);
}

static void test_heap_max_name_accepted(void) {
    unsigned char buf[128];
    const u64 in[4] = {1, 2, 3, 4};
    const char name[] = "abcdefghijklmnopqrstuvwxyz_01234"; // 32 bytes
    const u64 len = put_heap(buf, in, name);
    u64 out[4];
    u8 name_len;
    check("32-byte name accepted",
          0,
          nodejs_v8_parse_numbers_name(buf, len, out, k_v8_heap_num_fields, &name_len));
    check("32-byte name length", k_nodejs_heap_space_name_max, name_len);
}

static void test_heap_empty_name_rejected(void) {
    unsigned char buf[128];
    const u64 in[4] = {1, 2, 3, 4};
    const u64 len = put_heap(buf, in, "");
    u64 out[4];
    u8 name_len;
    check("empty heap space name",
          -1,
          nodejs_v8_parse_numbers_name(buf, len, out, k_v8_heap_num_fields, &name_len));
}

static void test_heap_name_over_cap_rejected(void) {
    unsigned char buf[160];
    const u64 in[4] = {1, 2, 3, 4};
    const char name[] = "abcdefghijklmnopqrstuvwxyz_012345"; // 33 bytes
    const u64 len = put_heap(buf, in, name);
    u64 out[4];
    u8 name_len;
    check("33-byte heap space name",
          -1,
          nodejs_v8_parse_numbers_name(buf, len, out, k_v8_heap_num_fields, &name_len));
}

static void test_heap_non_hex_number_rejected(void) {
    unsigned char buf[128];
    const u64 in[4] = {1, 2, 3, 4};
    const u64 len = put_heap(buf, in, "old_space");
    buf[40] = 'g'; // inside the third number
    u64 out[4];
    u8 name_len;
    check("non-hex heap number digit",
          -1,
          nodejs_v8_parse_numbers_name(buf, len, out, k_v8_heap_num_fields, &name_len));
}

static void test_heap_numbers_only_rejected(void) {
    // a path that ends right after the numbers (NUL where the name starts)
    unsigned char buf[128];
    const u64 in[4] = {1, 2, 3, 4};
    put_heap(buf, in, "x");
    buf[k_v8_heap_numbers_len] = '\0';
    u64 out[4];
    u8 name_len;
    check("numbers-only heap payload",
          -1,
          nodejs_v8_parse_numbers_name(
              buf, k_v8_heap_numbers_len + 1, out, k_v8_heap_num_fields, &name_len));
}

// builds an a payload; returns len including the NUL
static u64 put_resource(unsigned char *dst, u64 count, const char *name) {
    put_hex16(dst, count);
    const u64 name_len = strlen(name);
    memcpy(dst + k_v8_resource_numbers_len, name, name_len);
    dst[k_v8_resource_numbers_len + name_len] = '\0';
    return k_v8_resource_numbers_len + name_len + 1;
}

static void test_resource_valid(void) {
    unsigned char buf[64];
    const u64 len = put_resource(buf, 5, "Timeout");
    u64 count = 0;
    u8 name_len = 0;
    check("valid resource record parses",
          0,
          nodejs_v8_parse_numbers_name(buf, len, &count, k_v8_resource_num_fields, &name_len));
    check_u64("resource count decodes", 5, count);
    check("resource type length", (int)strlen("Timeout"), name_len);
}

static void test_resource_zero_count_accepted(void) {
    // count 0 is the vanished-type explicit zero, not a malformed record
    unsigned char buf[64];
    const u64 len = put_resource(buf, 0, "Timeout");
    u64 count = 1;
    u8 name_len = 0;
    check("zero-count resource record parses",
          0,
          nodejs_v8_parse_numbers_name(buf, len, &count, k_v8_resource_num_fields, &name_len));
    check_u64("resource zero count decodes", 0, count);
}

static void test_resource_empty_name_rejected(void) {
    unsigned char buf[64];
    const u64 len = put_resource(buf, 1, "");
    u64 count;
    u8 name_len;
    check("empty resource type name",
          -1,
          nodejs_v8_parse_numbers_name(buf, len, &count, k_v8_resource_num_fields, &name_len));
}

static void test_resource_name_over_cap_rejected(void) {
    unsigned char buf[64];
    const char name[] = "abcdefghijklmnopqrstuvwxyz_012345"; // 33 bytes
    const u64 len = put_resource(buf, 1, name);
    u64 count;
    u8 name_len;
    check("33-byte resource type name",
          -1,
          nodejs_v8_parse_numbers_name(buf, len, &count, k_v8_resource_num_fields, &name_len));
}

static void test_resource_non_hex_count_rejected(void) {
    unsigned char buf[64];
    const u64 len = put_resource(buf, 1, "Timeout");
    buf[7] = 'T'; // inside the count
    u64 count;
    u8 name_len;
    check("non-hex resource count digit",
          -1,
          nodejs_v8_parse_numbers_name(buf, len, &count, k_v8_resource_num_fields, &name_len));
}

int main(void) {
    test_gc_valid();
    test_gc_non_hex_kind_rejected();
    test_gc_non_hex_duration_rejected();
    test_gc_wrong_length_rejected();
    test_heap_valid();
    test_heap_max_name_accepted();
    test_heap_empty_name_rejected();
    test_heap_name_over_cap_rejected();
    test_heap_non_hex_number_rejected();
    test_heap_numbers_only_rejected();
    test_resource_valid();
    test_resource_zero_count_accepted();
    test_resource_empty_name_rejected();
    test_resource_name_over_cap_rejected();
    test_resource_non_hex_count_rejected();

    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }

    printf("all nodejs v8 record parsing tests passed\n");
    return 0;
}
