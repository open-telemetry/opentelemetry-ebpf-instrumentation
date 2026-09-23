// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The following parsing helpers are copied from bpf/generictracer/nodejs.c and
 * adapted to run as a host unit test. The functions under test are:
 *
 *   static __always_inline int nodejs_parse_fd(const unsigned char *digits, u32 *fd);
 *   static __always_inline int nodejs_span_fd_variant(const unsigned char *variant,
 *                                                     u32 *fd);
 *
 * The variant input is the 7 bytes read at offset 18 of the sentinel path:
 *   /dev/null/obi-spanfd/<4-digit fd><json>  ->  "fd/NNNN"   (fd variant, 1)
 *   /dev/null/obi-span/<json>                ->  "/{...."    (plain variant, 0)
 * An fd marker followed by anything but four decimal digits is malformed (-1):
 * the span keeps its payload offset but gets no parent.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8;
typedef uint32_t u32;

#ifndef __always_inline
#define __always_inline inline
#endif

enum {
    k_max_fd_digits = 4,
    k_span_fd_variant_offset = 18,
    k_span_fd_marker_len = 3,
    k_span_fd_payload_offset = k_span_fd_variant_offset + k_span_fd_marker_len + k_max_fd_digits,
    k_span_payload_offset = 19,
};

// --- code under test (keep in sync with bpf/generictracer/nodejs.c) ---

static __always_inline int nodejs_parse_fd(const unsigned char *digits, u32 *fd) {
    u32 v = 0;
    for (u8 i = 0; i < k_max_fd_digits; ++i) {
        const unsigned char c = digits[i];
        if (c < '0' || c > '9') {
            return -1;
        }
        v = v * 10 + (u32)(c - '0');
    }
    *fd = v;
    return 0;
}

static __always_inline int nodejs_span_fd_variant(const unsigned char *variant, u32 *fd) {
    if (variant[0] != 'f' || variant[1] != 'd' || variant[2] != '/') {
        return 0;
    }
    return nodejs_parse_fd(variant + k_span_fd_marker_len, fd) == 0 ? 1 : -1;
}

// --- end of code under test ---

static int failures = 0;

static void check(const char *name, long expected, long actual) {
    if (expected != actual) {
        fprintf(stderr, "FAIL %s: expected %ld, got %ld\n", name, expected, actual);
        failures++;
    }
}

static int variant_of(const char *path, u32 *fd) {
    return nodejs_span_fd_variant((const unsigned char *)path + k_span_fd_variant_offset, fd);
}

static void test_offsets_match_prefixes(void) {
    check("fd variant offset", k_span_fd_variant_offset, (long)strlen("/dev/null/obi-span"));
    check("fd payload offset", k_span_fd_payload_offset, (long)strlen("/dev/null/obi-spanfd/0000"));
    check("plain payload offset", k_span_payload_offset, (long)strlen("/dev/null/obi-span/"));
}

static void test_fd_variant(void) {
    u32 fd = 0;
    check("fd variant detected", 1, variant_of("/dev/null/obi-spanfd/0042{\"v\":1}", &fd));
    check("fd decodes", 42, fd);
    check("max fd detected", 1, variant_of("/dev/null/obi-spanfd/9999{}", &fd));
    check("max fd decodes", 9999, fd);
    check("zero fd detected", 1, variant_of("/dev/null/obi-spanfd/0000{}", &fd));
    check("zero fd decodes", 0, fd);
}

static void test_plain_variant(void) {
    u32 fd = 7;
    check("plain variant", 0, variant_of("/dev/null/obi-span/{\"v\":1,\"name\":\"x\"}", &fd));
    check("plain leaves fd untouched", 7, fd);
    check("plain payload starting with fd", 0, variant_of("/dev/null/obi-span/fd/0001", &fd));
}

static void test_malformed_fd(void) {
    u32 fd = 7;
    check("non-digit fd", -1, variant_of("/dev/null/obi-spanfd/12a4{}", &fd));
    check("short fd before payload", -1, variant_of("/dev/null/obi-spanfd/12{}", &fd));
    check("malformed leaves fd untouched", 7, fd);
}

static void test_ctx_fd_digits(void) {
    u32 fd = 0;
    check("ctx fd parses", 0, nodejs_parse_fd((const unsigned char *)"0020", &fd));
    check("ctx fd decodes", 20, fd);
    check("ctx fd rejects garbage", -1, nodejs_parse_fd((const unsigned char *)"00-1", &fd));
}

int main(void) {
    test_offsets_match_prefixes();
    test_fd_variant();
    test_plain_variant();
    test_malformed_fd();
    test_ctx_fd_digits();

    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }

    printf("all nodejs span fd sentinel parsing tests passed\n");
    return 0;
}
