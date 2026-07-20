// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#include <common/trace_util.h>

static void assert_match_pos(u32 want, u32 got, const char *name) {
    if (want != got) {
        fprintf(stderr, "%s: got pos %u, want %u\n", name, got, want);
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
        "xtraceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";

    const u32 got = traceparent_pos_after_read(stale, fresh, sizeof(fresh) - 1);

    assert_match_pos(1, got, __func__);
}

int main(void) {
    test_stale_suffix_cannot_complete_traceparent_prefix();
    test_stale_value_cannot_complete_traceparent_header();
    test_fresh_traceparent_still_matches();

    return 0;
}
