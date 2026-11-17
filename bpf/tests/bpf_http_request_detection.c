// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

#include <common/http_types.h>

static int failures = 0;

// Callers pass a zero-padded buffer of MIN_HTTP2_SIZE bytes, so the payload is
// copied into one to mirror the data is_http_request_buf sees in production.
static u8 detect(const char *payload) {
    unsigned char buf[MIN_HTTP2_SIZE] = {0};
    const size_t len = strlen(payload);

    memcpy(buf, payload, len < sizeof(buf) ? len : sizeof(buf));

    return is_http_request_buf(buf);
}

static void check(const char *payload, u8 expected) {
    const u8 actual = detect(payload);

    if (actual != expected) {
        fprintf(stderr, "FAIL: \"%s\"\n  expected %u, got %u\n", payload, expected, actual);
        failures++;
        return;
    }

    printf("ok: \"%s\" -> %u\n", payload, actual);
}

static void test_known_methods_detected(void) {
    check("GET /users/7 HTTP/1.1", 1);
    check("POST /users HTTP/1.1", 1);
    check("PUT /users/7 HTTP/1.1", 1);
    check("PATCH /users/7 HTTP/1.1", 1);
    check("DELETE /users/7 HTTP/1.1", 1);
    check("HEAD /users/7 HTTP/1.1", 1);
    check("OPTIONS /users/7 HTTP/1.1", 1);
    check("TRACE /users/7 HTTP/1.1", 1);
    check("QUERY /users HTTP/1.1", 1);
}

static void test_absolute_form_detected(void) {
    check("GET http://example.com/ HTTP/1.1", 1);
    check("TRACE https://example.com/ HTTP/1.1", 1);
}

static void test_asterisk_form_only_for_options(void) {
    check("OPTIONS * HTTP/1.1", 1);
    check("GET * HTTP/1.1", 0);
    check("TRACE * HTTP/1.1", 0);
    check("QUERY * HTTP/1.1", 0);
}

static void test_connect_authority_form_detected(void) {
    check("CONNECT example.com:443 HTTP/1.1", 1);
    check("CONNECT 10.0.0.1:8080 HTTP/1.1", 1);
    check("CONNECT [::1]:443 HTTP/1.1", 1);
}

static void test_nats_connect_rejected(void) {
    check("CONNECT {\"verbose\":false,\"pedantic\":false}\r\n", 0);
    check("CONNECT {}\r\n", 0);
}

static void test_invalid_requests_rejected(void) {
    check("TRACEX / HTTP/1.1", 0);
    check("QUERY users HTTP/1.1", 0);
    check("OPTIONS users HTTP/1.1", 0);
    check("CONNECTX example.com:443", 0);
    check("trace / HTTP/1.1", 0);
    check("PROPFIND / HTTP/1.1", 0);
    check("HTTP/1.1 200 OK", 0);
}

int main(void) {
    test_known_methods_detected();
    test_absolute_form_detected();
    test_asterisk_form_only_for_options();
    test_connect_authority_form_detected();
    test_nats_connect_rejected();
    test_invalid_requests_rejected();

    if (failures > 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }

    printf("all HTTP request detection tests passed\n");
    return 0;
}
