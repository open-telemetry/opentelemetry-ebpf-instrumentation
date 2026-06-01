// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run me with: make && ./test_trace_util

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/vmlinux.h>

static inline long
bpf_loop(u32 nr_loops, int (*callback_fn)(u32, void *), void *callback_ctx, u64 flags) {
    (void)flags;

    for (u32 i = 0; i < nr_loops; i++) {
        if (callback_fn(i, callback_ctx)) {
            break;
        }
    }

    return 0;
}

static inline u32 bpf_get_prandom_u32(void) {
    return 0;
}

#include <common/globals.h>

#define g_bpf_traceparent_enabled true
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wunused-variable"
#include <common/trace_util.h>
#pragma clang diagnostic pop
#undef g_bpf_traceparent_enabled

static int failed_tests;

static const unsigned char valid_traceparent[] =
    "traceparent: 00-11111111111111111111111111111111-2222222222222222-01";

static void assert_true(bool condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        failed_tests++;
        return;
    }

    printf("PASS: %s\n", message);
}

static void
write_current_payload(unsigned char *scratch, const unsigned char *payload, size_t payload_len) {
    memcpy(scratch, payload, payload_len);
    scratch[payload_len] = '\0';
}

static void test_valid_traceparent_is_found(void) {
    unsigned char scratch[TRACE_BUF_SIZE] = {0};
    const size_t valid_len = sizeof(valid_traceparent) - 1;

    write_current_payload(scratch, valid_traceparent, valid_len);

    assert_true(bpf_strstr_tp_loop__legacy(scratch, (u16)valid_len) == scratch,
                "legacy scanner finds a complete traceparent in the fresh payload");
}

static void test_short_traceparent_prefix_does_not_reuse_stale_value(void) {
    unsigned char scratch[TRACE_BUF_SIZE] = {0};
    static const unsigned char prefix_only[] = "traceparent: ";

    const size_t valid_len = sizeof(valid_traceparent) - 1;
    const size_t prefix_len = sizeof(prefix_only) - 1;

    write_current_payload(scratch, valid_traceparent, valid_len);
    assert_true(bpf_strstr_tp_loop__legacy(scratch, (u16)valid_len) == scratch,
                "legacy scanner sees the initial full traceparent");

    write_current_payload(scratch, prefix_only, prefix_len);

    assert_true(bpf_strstr_tp_loop__legacy(scratch, (u16)prefix_len) == NULL,
                "short traceparent prefix does not match stale scratch bytes");
}

static void test_scan_stops_before_candidate_crosses_fresh_payload_end(void) {
    unsigned char scratch[TRACE_BUF_SIZE] = {0};
    const size_t fresh_len = TRACE_PARENT_HEADER_LEN;

    scratch[0] = 'x';
    memcpy(scratch + 1, valid_traceparent, fresh_len - 1);
    scratch[fresh_len] = '\0';

    assert_true(bpf_strstr_tp_loop__legacy(scratch, (u16)fresh_len) == NULL,
                "legacy scanner ignores traceparent candidates without full fresh payload");
}

int main(void) {
    test_valid_traceparent_is_found();
    test_short_traceparent_prefix_does_not_reuse_stale_value();
    test_scan_stops_before_candidate_crosses_fresh_payload_end();

    return failed_tests == 0 ? 0 : 1;
}
