// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
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
#define bpf_probe_read_kernel test_probe_read
#include <gotracer/go_http1.h>
#undef bpf_probe_read_kernel
#undef bpf_probe_read

static unsigned int failures;

static void assert_bool(int want, int got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %d, got %d\n", message, want, got);
    failures++;
}

static void assert_bytes(const void *want, const void *got, size_t len, const char *message) {
    if (memcmp(want, got, len) == 0) {
        return;
    }
    fprintf(stderr, "%s: byte sequences differ\n", message);
    failures++;
}

static void test_decode_valid_traceparent(void) {
    const unsigned char field[] =
        "tRaCePaReNt: 00-0102030405060708090a0b0c0d0e0f10-1112131415161718-86\r\n";
    const unsigned char trace_id[] = {
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
        0x10,
    };
    const unsigned char span_id[] = {
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
    };
    go_http1_traceparent_t marker = {};

    assert_bool(1,
                go_http1_decode_traceparent(field, sizeof(field) - 1, &marker),
                "decode mixed-case traceparent field");
    assert_bytes(trace_id, marker.tp.trace_id, sizeof(trace_id), "decode trace ID");
    assert_bytes(span_id, marker.tp.span_id, sizeof(span_id), "decode span ID");
    assert_bool(k_flag_random, marker.tp.flags, "preserve supported trace flags");
    assert_bool(k_sampling_decision_applied,
                marker.tp.sampling_decision,
                "make application flags authoritative");
}

static void test_reject_invalid_fields(void) {
    unsigned char field[] =
        "Traceparent: 00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01\r\n";
    go_http1_traceparent_t marker;
    memset(&marker, 0x5a, sizeof(marker));
    const go_http1_traceparent_t original = marker;

    field[14] = '1';
    assert_bool(1,
                go_http1_decode_traceparent(field, sizeof(field) - 1, &marker),
                "accept a supported future traceparent version");
    assert_bool(k_flag_sampled, marker.tp.flags, "mask unsupported future-version flags");
    field[14] = '0';
    marker = original;

    field[16] = 'z';
    assert_bool(0,
                go_http1_decode_traceparent(field, sizeof(field) - 1, &marker),
                "reject invalid trace ID hex");
    field[16] = '0';

    memset(field + 16, '0', TRACE_ID_CHAR_LEN);
    assert_bool(
        0, go_http1_decode_traceparent(field, sizeof(field) - 1, &marker), "reject zero trace ID");
    memcpy(field + 16, "0102030405060708090a0b0c0d0e0f10", TRACE_ID_CHAR_LEN);

    memset(field + 49, '0', SPAN_ID_CHAR_LEN);
    assert_bool(
        0, go_http1_decode_traceparent(field, sizeof(field) - 1, &marker), "reject zero span ID");
    memcpy(field + 49, "1112131415161718", SPAN_ID_CHAR_LEN);

    field[66] = 'z';
    assert_bool(0,
                go_http1_decode_traceparent(field, sizeof(field) - 1, &marker),
                "reject invalid flags hex");
    field[66] = '0';

    field[68] = '-';
    assert_bool(0,
                go_http1_decode_traceparent(field, sizeof(field) - 1, &marker),
                "reject a version 00 suffix");
    field[68] = '\r';

    assert_bool(
        0,
        go_http1_decode_traceparent(field, k_go_http1_traceparent_min_field_len - 1, &marker),
        "reject a traceparent field with a truncated value");
    assert_bool(0,
                go_http1_decode_traceparent(field, k_go_http1_traceparent_field_len - 2, &marker),
                "reject a traceparent field without CRLF");
    assert_bool(0,
                go_http1_decode_traceparent(field, k_go_http1_traceparent_field_len - 1, &marker),
                "reject a traceparent field with CR but without LF");

    field[0] = 'X';
    assert_bool(0,
                go_http1_decode_traceparent(field, sizeof(field) - 1, &marker),
                "reject a different header name");
    assert_bytes(&original, &marker, sizeof(marker), "leave marker after invalid fields");
}

static void test_adopt_traceparent(void) {
    const unsigned char field[] =
        "Traceparent: 00-0102030405060708090a0b0c0d0e0f10-1112131415161718-00\r\n";
    go_http1_traceparent_t marker = {};
    tp_info_t tp = {
        .ts = 1234,
        .flags = 0xff,
        .sampling_decision = k_sampling_decision_pending,
    };
    memset(tp.parent_id, 0x77, sizeof(tp.parent_id));

    assert_bool(1,
                go_http1_decode_traceparent(field, sizeof(field) - 1, &marker),
                "decode traceparent for adoption");
    go_http1_adopt_traceparent(&tp, &marker);

    assert_bytes(marker.tp.trace_id, tp.trace_id, sizeof(tp.trace_id), "adopt trace ID");
    assert_bytes(marker.tp.span_id, tp.span_id, sizeof(tp.span_id), "adopt span ID");
    assert_bytes(marker.tp.parent_id, tp.parent_id, sizeof(tp.parent_id), "clear parent ID");
    assert_bool(marker.tp.flags, tp.flags, "adopt full trace flags");
    assert_bool(k_sampling_decision_applied, tp.sampling_decision, "adopt BPF decision");
    assert_bool(1234, tp.ts, "preserve invocation timestamp");
}

static void test_scan_rejects_invalid_duplicate(void) {
    unsigned char fields[] =
        "Traceparent: 00-00000000000000000000000000000000-1112131415161718-01\r\n"
        "tRaCePaReNt: 00-0102030405060708090a0b0c0d0e0f10-1112131415161718-86\r\n";
    go_http1_traceparent_t marker = {};

    assert_bool(k_go_http1_traceparent_scan_present,
                go_http1_scan_traceparent(fields, sizeof(fields) - 1, &marker),
                "bpf_loop scan rejects an invalid duplicate");
    assert_bool(0, marker.authoritative, "bpf_loop duplicate cannot publish context");

    memset(&marker, 0, sizeof(marker));
    assert_bool(k_go_http1_traceparent_scan_present,
                go_http1_scan_traceparent_legacy(fields, sizeof(fields) - 1, &marker),
                "legacy scan rejects an invalid duplicate");
    assert_bool(0, marker.authoritative, "legacy duplicate cannot publish context");
}

static void test_scan_rejects_valid_duplicate(void) {
    unsigned char fields[] =
        "Traceparent: 00-0102030405060708090a0b0c0d0e0f10-1112131415161718-86\r\n"
        "Traceparent: 00-2122232425262728292a2b2c2d2e2f30-3132333435363738-01\r\n";
    go_http1_traceparent_t marker = {};

    assert_bool(k_go_http1_traceparent_scan_present,
                go_http1_scan_traceparent(fields, sizeof(fields) - 1, &marker),
                "reject multiple valid traceparents");
    assert_bool(0, marker.authoritative, "ambiguous traceparent cannot publish context");
}

static void test_scan_rejects_embedded_header_text(void) {
    unsigned char fields[] =
        "X-Test: Traceparent: 00-0102030405060708090a0b0c0d0e0f10-1112131415161718-86\r\n";
    go_http1_traceparent_t marker = {};

    assert_bool(k_go_http1_traceparent_scan_absent,
                go_http1_scan_traceparent(fields, sizeof(fields) - 1, &marker),
                "ignore traceparent text embedded in another field");
}

static void test_scan_reports_legacy_partial_search(void) {
    unsigned char fields[500];
    memset(fields, 'x', sizeof(fields));
    fields[399] = '\n';
    memcpy(fields + 400,
           "Traceparent: 00-0102030405060708090a0b0c0d0e0f10-1112131415161718-86\r\n",
           k_go_http1_traceparent_field_len);
    go_http1_traceparent_t marker = {};

    assert_bool(k_go_http1_traceparent_scan_found,
                go_http1_scan_traceparent(fields, sizeof(fields), &marker),
                "bpf_loop scan covers the full captured region");
    assert_bool(k_go_http1_traceparent_scan_unknown,
                go_http1_scan_traceparent_legacy(fields, sizeof(fields), &marker),
                "legacy scan reports an incomplete search");
}

static void test_capture_region_bounds(void) {
    u32 region = 0;

    assert_bool(1,
                go_http1_header_map_is_definitively_empty(1, 20, 20),
                "empty header map makes an unchanged writer definitive");
    assert_bool(0,
                go_http1_header_map_is_definitively_empty(0, 20, 20),
                "nonempty header map with an unchanged writer is unknown");
    assert_bool(0,
                go_http1_header_map_is_definitively_empty(1, 20, 10),
                "empty header map cannot explain a reset writer offset");
    assert_bool(1,
                go_http1_capture_region(10, 20, 1024, TRACE_BUF_SIZE, &region),
                "capture a complete writer region");
    assert_bool(10, region, "captured writer region length");
    assert_bool(0,
                go_http1_capture_region(20, 20, 1024, TRACE_BUF_SIZE, &region),
                "flushed writer region is unknown");
    assert_bool(0,
                go_http1_capture_region(100, 20, 1024, TRACE_BUF_SIZE, &region),
                "reset writer offset is unknown");
    assert_bool(0,
                go_http1_capture_region(0, TRACE_BUF_SIZE, TRACE_BUF_SIZE, TRACE_BUF_SIZE, &region),
                "scratch-sized writer region is not partially scanned");
    assert_bool(0,
                go_http1_capture_region(0, 1025, 1024, TRACE_BUF_SIZE, &region),
                "out-of-range writer offset is unknown");
}

static void test_client_partial_traceparent_is_not_authoritative(void) {
    unsigned char no_crlf[] =
        "Traceparent: 00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01";
    unsigned char cr_only[] =
        "Traceparent: 00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01\r";
    go_http1_traceparent_t marker = {};

    assert_bool(k_go_http1_traceparent_scan_present,
                go_http1_scan_traceparent(no_crlf, sizeof(no_crlf) - 1, &marker),
                "client scan rejects a traceparent write without CRLF");
    assert_bool(0, marker.authoritative, "partial client write cannot publish application context");
    assert_bool(1,
                go_http1_should_suppress_fallback(0),
                "a nonempty client header map keeps blind fallback suppressed");

    memset(&marker, 0, sizeof(marker));
    assert_bool(k_go_http1_traceparent_scan_present,
                go_http1_scan_traceparent(cr_only, sizeof(cr_only) - 1, &marker),
                "client scan rejects a traceparent write with CR but without LF");
    assert_bool(0, marker.authoritative, "CR-only client write remains non-authoritative");
}

int main(void) {
    test_decode_valid_traceparent();
    test_reject_invalid_fields();
    test_adopt_traceparent();
    test_scan_rejects_invalid_duplicate();
    test_scan_rejects_valid_duplicate();
    test_scan_rejects_embedded_header_text();
    test_scan_reports_legacy_partial_search();
    test_capture_region_bounds();
    test_client_partial_traceparent_is_not_authoritative();

    return failures ? 1 : 0;
}
