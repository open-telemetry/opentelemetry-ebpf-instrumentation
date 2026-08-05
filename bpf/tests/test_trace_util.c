// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

static inline unsigned int bpf_get_prandom_u32(void) {
    return 0;
}

static inline long bpf_loop(unsigned int nr_loops,
                            int (*callback_fn)(unsigned int, void *),
                            void *callback_ctx,
                            unsigned long long flags) {
    (void)flags;

    for (unsigned int i = 0; i < nr_loops; i++) {
        if (callback_fn(i, callback_ctx)) {
            break;
        }
    }

    return 0;
}

static long test_probe_read(void *dst, unsigned int size, const void *src) {
    memcpy(dst, src, size);
    return 0;
}

#define bpf_probe_read test_probe_read
#include <common/trace_util.h>
#undef bpf_probe_read

static void assert_match_pos(u32 want, u32 got, const char *name) {
    if (want != got) {
        fprintf(stderr, "%s: got pos %u, want %u\n", name, got, want);
        exit(1);
    }
}

static void test_traceparent_byte_validation(void) {
    unsigned char value[TRACE_ID_SIZE_BYTES * 2] = {};

    for (u16 candidate = 0; candidate <= UINT8_MAX; candidate++) {
        memset(value, candidate, sizeof(value));
        const u8 want_hex =
            (candidate >= '0' && candidate <= '9') || (candidate >= 'a' && candidate <= 'f');
        const u8 want_nonzero = candidate != '0';

        if (valid_traceparent_hex(value, sizeof(value)) != want_hex) {
            fprintf(stderr, "hex validation mismatch for byte 0x%02x\n", candidate);
            exit(1);
        }
        if (nonzero_traceparent_id(value, sizeof(value)) != want_nonzero) {
            fprintf(stderr, "nonzero validation mismatch for byte 0x%02x\n", candidate);
            exit(1);
        }
    }

    if (valid_traceparent_hex(value, sizeof(value) + 1) ||
        nonzero_traceparent_id(value, sizeof(value) + 1)) {
        fprintf(stderr, "traceparent validation accepted an oversized identifier\n");
        exit(1);
    }
}

static u32
traceparent_pos_after_read(const unsigned char *stale, const unsigned char *fresh, u32 fresh_len) {
    unsigned char buf[TRACE_BUF_SIZE] = {};

    memcpy(buf, stale, strlen((const char *)stale));
    memcpy(buf, fresh, fresh_len);

    struct callback_ctx ctx = {.buf = buf, .pos = k_tp_pos_not_found};

    bpf_loop(traceparent_scan_loop_count(fresh_len), tp_match, &ctx, 0);
    return ctx.pos;
}

static void test_stale_suffix_cannot_complete_traceparent_prefix(void) {
    const unsigned char stale[] =
        "xtraceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";
    const unsigned char fresh[] = "xtrace";

    const u32 got = traceparent_pos_after_read(stale, fresh, sizeof(fresh) - 1);

    assert_match_pos(k_tp_pos_not_found, got, __func__);
}

static void test_stale_value_cannot_complete_traceparent_header(void) {
    const unsigned char stale[] =
        "xtraceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";
    const unsigned char fresh[] = "xtraceparent: ";

    const u32 got = traceparent_pos_after_read(stale, fresh, sizeof(fresh) - 1);

    assert_match_pos(k_tp_pos_not_found, got, __func__);
}

static void test_fresh_traceparent_still_matches(void) {
    const unsigned char stale[] = "x";
    const unsigned char fresh[] =
        "GET / HTTP/1.1\r\n"
        "traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";

    const u32 got = traceparent_pos_after_read(stale, fresh, sizeof(fresh) - 1);

    assert_match_pos(sizeof("GET / HTTP/1.1\r\n") - 1, got, __func__);
}

static void test_embedded_traceparent_name_does_not_match(void) {
    const unsigned char stale[] = "x";
    const unsigned char fresh[] =
        "GET / HTTP/1.1\r\n"
        "xtraceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n"
        "X-Test: traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";

    const u32 got = traceparent_pos_after_read(stale, fresh, sizeof(fresh) - 1);

    assert_match_pos(k_tp_pos_not_found, got, __func__);
}

static void test_traceparent_with_tab_ows_matches(void) {
    const unsigned char stale[] = "x";
    const unsigned char fresh[] =
        "GET / HTTP/1.1\r\n"
        "traceparent:\t00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";

    const u32 got = traceparent_pos_after_read(stale, fresh, sizeof(fresh) - 1);

    assert_match_pos(sizeof("GET / HTTP/1.1\r\n") - 1, got, __func__);
}

static void test_traceparent_after_headers_does_not_match(void) {
    const unsigned char stale[] = "x";
    const unsigned char fresh[] =
        "GET /traceparent: HTTP/1.1\r\n"
        "\r\n"
        "traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";

    const u32 got = traceparent_pos_after_read(stale, fresh, sizeof(fresh) - 1);

    assert_match_pos(k_tp_pos_not_found, got, __func__);
}

static void assert_authoritative_scan(enum http1_traceparent_scan_result want,
                                      const unsigned char *headers,
                                      u32 want_pos,
                                      const char *name) {
    u32 pos = k_tp_pos_not_found;
    enum http1_traceparent_scan_result got =
        scan_http1_traceparent((unsigned char *)headers, (u16)strlen((const char *)headers), &pos);
    if (got != want || (got == k_http1_traceparent_scan_found && pos != want_pos)) {
        fprintf(stderr,
                "%s (bpf_loop): got result %u pos %u, want result %u pos %u\n",
                name,
                got,
                pos,
                want,
                want_pos);
        exit(1);
    }

    pos = k_tp_pos_not_found;
    got = scan_http1_traceparent_legacy(
        (unsigned char *)headers, (u16)strlen((const char *)headers), &pos);
    if (got != want || (got == k_http1_traceparent_scan_found && pos != want_pos)) {
        fprintf(stderr,
                "%s (legacy): got result %u pos %u, want result %u pos %u\n",
                name,
                got,
                pos,
                want,
                want_pos);
        exit(1);
    }
}

static void test_authoritative_http1_traceparent_scan(void) {
    const unsigned char single[] =
        "GET / HTTP/1.1\r\n"
        "tRaCePaReNt:\t00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n"
        "Host: example.test\r\n"
        "\r\n";
    const u32 field_pos = sizeof("GET / HTTP/1.1\r\n") - 1;
    assert_authoritative_scan(
        k_http1_traceparent_scan_found, single, field_pos, "one mixed-case traceparent");

    const unsigned char valid_valid[] =
        "GET / HTTP/1.1\r\n"
        "Traceparent:00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n"
        "tRaCePaReNt:\t00-fedcba9876543210fedcba9876543210-fedcba9876543210-00\r\n"
        "\r\n";
    assert_authoritative_scan(k_http1_traceparent_scan_present,
                              valid_valid,
                              k_tp_pos_not_found,
                              "duplicate valid traceparents");

    const unsigned char valid_malformed[] =
        "GET / HTTP/1.1\r\n"
        "Traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n"
        "traceparent:\tinvalid\r\n"
        "\r\n";
    assert_authoritative_scan(k_http1_traceparent_scan_present,
                              valid_malformed,
                              k_tp_pos_not_found,
                              "valid then malformed traceparent");

    const unsigned char malformed_valid[] =
        "GET / HTTP/1.1\r\n"
        "TRACEPARENT: invalid\r\n"
        "traceparent:\t00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n"
        "\r\n";
    assert_authoritative_scan(k_http1_traceparent_scan_present,
                              malformed_valid,
                              k_tp_pos_not_found,
                              "malformed then valid traceparent");

    const unsigned char incomplete[] =
        "GET / HTTP/1.1\r\n"
        "traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";
    assert_authoritative_scan(k_http1_traceparent_scan_present,
                              incomplete,
                              k_tp_pos_not_found,
                              "incomplete header capture");
}

static void test_ssl_transport_fallback_yields_to_header_authority(void) {
    const unsigned char duplicate[] =
        "GET / HTTP/1.1\r\n"
        "traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n"
        "Traceparent:\t00-fedcba9876543210fedcba9876543210-fedcba9876543210-00\r\n"
        "\r\n";
    const unsigned char malformed[] = "GET / HTTP/1.1\r\n"
                                      "TRACEPARENT: invalid\r\n"
                                      "\r\n";
    u32 pos = k_tp_pos_not_found;
    enum http1_traceparent_scan_result result =
        scan_http1_traceparent((unsigned char *)duplicate, sizeof(duplicate) - 1, &pos);
    if (result != k_http1_traceparent_scan_present || !http1_server_requires_root(result)) {
        fprintf(stderr, "SSL transport fallback survived duplicate application headers\n");
        exit(1);
    }

    result = scan_http1_traceparent((unsigned char *)malformed, sizeof(malformed) - 1, &pos);
    if (result != k_http1_traceparent_scan_present || !http1_server_requires_root(result)) {
        fprintf(stderr, "SSL transport fallback survived a malformed application header\n");
        exit(1);
    }

    if (!http1_server_requires_root(k_http1_traceparent_scan_unknown)) {
        fprintf(stderr, "SSL transport fallback survived failed read or scratch capture\n");
        exit(1);
    }
    if (http1_server_requires_root(k_http1_traceparent_scan_absent) ||
        http1_server_requires_root(k_http1_traceparent_scan_found)) {
        fprintf(stderr, "authoritative scan results discarded a valid transport/header parent\n");
        exit(1);
    }
}

int main(void) {
    test_traceparent_byte_validation();
    test_stale_suffix_cannot_complete_traceparent_prefix();
    test_stale_value_cannot_complete_traceparent_header();
    test_fresh_traceparent_still_matches();
    test_embedded_traceparent_name_does_not_match();
    test_traceparent_with_tab_ows_matches();
    test_traceparent_after_headers_does_not_match();
    test_authoritative_http1_traceparent_scan();
    test_ssl_transport_fallback_yields_to_header_authority();

    return 0;
}
