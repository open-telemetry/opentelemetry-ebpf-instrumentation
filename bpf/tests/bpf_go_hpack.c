// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
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

#include <gotracer/go_hpack.h>

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
    const unsigned char name[] = "traceparent";
    const unsigned char value[] = "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-85";
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
    const unsigned char zero_parent[SPAN_ID_SIZE_BYTES] = {};
    go_hpack_block_t block = {};

    assert_bool(
        1,
        go_hpack_decode_traceparent(name, sizeof(name) - 1, value, sizeof(value) - 1, &block),
        "decode valid traceparent");
    assert_bytes(trace_id, block.tp.trace_id, sizeof(trace_id), "decode trace ID");
    assert_bytes(span_id, block.tp.span_id, sizeof(span_id), "decode span ID");
    assert_bytes(zero_parent, block.tp.parent_id, sizeof(zero_parent), "decode clears parent ID");
    assert_bool(k_flag_sampled, block.tp.flags, "ignore unsupported trace flags");
    assert_bool(k_sampling_decision_applied,
                block.tp.sampling_decision,
                "decode makes wire decision authoritative");
    assert_bool(k_go_hpack_block_request, block.state, "decode marks request block");
    assert_bool(1, block.has_traceparent, "decode marks traceparent present");
    assert_bool(1, block.authoritative, "version 00 is adoptable");
}

static void test_reject_invalid_fields(void) {
    const unsigned char name[] = "traceparent";
    const unsigned char other_name[] = "tracestatex";
    unsigned char value[] = "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01";
    go_hpack_block_t block;
    memset(&block, 0x5a, sizeof(block));
    const go_hpack_block_t original = block;

    assert_bool(0,
                go_hpack_decode_traceparent(
                    other_name, sizeof(other_name) - 1, value, sizeof(value) - 1, &block),
                "reject non-traceparent field");
    assert_bytes(&original, &block, sizeof(block), "leave block after other field");

    value[3] = 'z';
    assert_bool(
        0,
        go_hpack_decode_traceparent(name, sizeof(name) - 1, value, sizeof(value) - 1, &block),
        "reject invalid traceparent value");
    assert_bytes(&original, &block, sizeof(block), "leave block after invalid value");

    value[3] = '0';
    assert_bool(
        0,
        go_hpack_decode_traceparent(name, sizeof(name) - 1, value, sizeof(value) - 2, &block),
        "reject wrong traceparent length");
    assert_bytes(&original, &block, sizeof(block), "leave block after wrong length");
}

static void test_adopt_traceparent(void) {
    const unsigned char name[] = "traceparent";
    const unsigned char value[] = "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-00";
    go_hpack_block_t block = {};
    tp_info_t tp = {
        .ts = 1234,
        .flags = 0xff,
        .sampling_decision = k_sampling_decision_pending,
    };
    memset(tp.parent_id, 0x77, sizeof(tp.parent_id));

    assert_bool(
        1,
        go_hpack_decode_traceparent(name, sizeof(name) - 1, value, sizeof(value) - 1, &block),
        "decode traceparent for adoption");
    block.tp.parent_remote = 1;
    go_hpack_adopt_traceparent(&tp, &block);

    assert_bytes(block.tp.trace_id, tp.trace_id, sizeof(tp.trace_id), "adopt trace ID");
    assert_bytes(block.tp.span_id, tp.span_id, sizeof(tp.span_id), "adopt span ID");
    assert_bytes(block.tp.parent_id, tp.parent_id, sizeof(tp.parent_id), "adopt parent ID");
    assert_bool(block.tp.flags, tp.flags, "adopt trace flags");
    assert_bool(k_sampling_decision_applied, tp.sampling_decision, "adopt authoritative decision");
    assert_bool(1, tp.parent_remote, "adopt remote-parent state");
    assert_bool(1234, tp.ts, "adopt preserves trace timestamp");
}

static void test_xnet_initial_request_and_trailer(void) {
    const unsigned char authority[] = ":authority";
    const unsigned char method[] = ":method";
    const unsigned char name[] = "traceparent";
    const unsigned char value[] = "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01";
    go_hpack_block_t block = {};

    assert_bool(k_go_hpack_block_store,
                go_hpack_observe_pseudo_header(&block, authority, sizeof(authority) - 1),
                "x/net authority starts request candidate");
    assert_bool(
        k_go_hpack_block_request_candidate, block.state, "x/net authority waits for method");
    assert_bool(
        k_go_hpack_traceparent_non_authoritative,
        go_hpack_capture_traceparent(&block, name, sizeof(name) - 1, value, sizeof(value) - 1),
        "candidate block classifies traceparent as non-authoritative");

    assert_bool(k_go_hpack_block_store,
                go_hpack_observe_pseudo_header(&block, method, sizeof(method) - 1),
                "x/net method enables request block");
    assert_bool(
        k_go_hpack_traceparent_authoritative,
        go_hpack_capture_traceparent(&block, name, sizeof(name) - 1, value, sizeof(value) - 1),
        "initial x/net block accepts traceparent");
    assert_bool(1, block.has_traceparent, "initial x/net block records traceparent");

    go_hpack_clear_block(&block);
    assert_bool(
        k_go_hpack_traceparent_non_authoritative,
        go_hpack_capture_traceparent(&block, name, sizeof(name) - 1, value, sizeof(value) - 1),
        "trailer traceparent only suppresses duplicate append");
    assert_bool(k_go_hpack_block_non_request, block.state, "trailer remains non-authoritative");
    assert_bool(1, block.has_traceparent, "trailer records field presence");

    tp_info_t initial = {.ts = 1234, .flags = 0x85};
    memset(initial.trace_id, 0x22, sizeof(initial.trace_id));
    memset(initial.span_id, 0x33, sizeof(initial.span_id));
    memset(initial.parent_id, 0x44, sizeof(initial.parent_id));
    const tp_info_t original = initial;
    go_hpack_adopt_traceparent(&initial, &block);
    assert_bytes(&original, &initial, sizeof(initial), "trailer cannot alter request context");
}

static void test_grpc_initial_request_order(void) {
    const unsigned char method[] = ":method";
    const unsigned char scheme[] = ":scheme";
    const unsigned char path[] = ":path";
    const unsigned char authority[] = ":authority";
    const unsigned char name[] = "traceparent";
    const unsigned char value[] = "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01";
    go_hpack_block_t block = {};

    assert_bool(k_go_hpack_block_store,
                go_hpack_observe_pseudo_header(&block, method, sizeof(method) - 1),
                "gRPC method enables request block");
    assert_bool(k_go_hpack_block_unchanged,
                go_hpack_observe_pseudo_header(&block, scheme, sizeof(scheme) - 1),
                "gRPC scheme preserves request block");
    assert_bool(k_go_hpack_block_unchanged,
                go_hpack_observe_pseudo_header(&block, path, sizeof(path) - 1),
                "gRPC path preserves request block");
    assert_bool(k_go_hpack_block_unchanged,
                go_hpack_observe_pseudo_header(&block, authority, sizeof(authority) - 1),
                "gRPC authority preserves request block");
    assert_bool(
        k_go_hpack_traceparent_authoritative,
        go_hpack_capture_traceparent(&block, name, sizeof(name) - 1, value, sizeof(value) - 1),
        "initial gRPC block accepts traceparent");
}

static void test_non_request_blocks_clear_or_reject(void) {
    const unsigned char method[] = ":method";
    const unsigned char status[] = ":status";
    const unsigned char name[] = "traceparent";
    const unsigned char value[] = "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01";
    go_hpack_block_t block = {};

    go_hpack_observe_pseudo_header(&block, method, sizeof(method) - 1);
    assert_bool(
        k_go_hpack_traceparent_authoritative,
        go_hpack_capture_traceparent(&block, name, sizeof(name) - 1, value, sizeof(value) - 1),
        "request block records traceparent before response");
    assert_bool(k_go_hpack_block_clear,
                go_hpack_observe_pseudo_header(&block, status, sizeof(status) - 1),
                "response status clears request state");
    assert_bool(k_go_hpack_block_none, block.state, "response block is disabled");
    assert_bool(0, block.has_traceparent, "response clears request traceparent");
    assert_bool(
        k_go_hpack_traceparent_non_authoritative,
        go_hpack_capture_traceparent(&block, name, sizeof(name) - 1, value, sizeof(value) - 1),
        "response traceparent is non-authoritative");

    go_hpack_clear_block(&block);
    assert_bool(
        k_go_hpack_traceparent_non_authoritative,
        go_hpack_capture_traceparent(&block, name, sizeof(name) - 1, value, sizeof(value) - 1),
        "custom encoder without method is non-authoritative");
}

static void test_preserve_future_versions(void) {
    const unsigned char method[] = ":method";
    const unsigned char name[] = "traceparent";
    const unsigned char exact_v01[] = "01-0102030405060708090a0b0c0d0e0f10-1112131415161718-85";
    const unsigned char extended_v01[] =
        "01-0102030405060708090a0b0c0d0e0f10-1112131415161718-85-extra";
    go_hpack_block_t block = {};

    go_hpack_observe_pseudo_header(&block, method, sizeof(method) - 1);
    assert_bool(k_go_hpack_traceparent_authoritative,
                go_hpack_capture_traceparent(
                    &block, name, sizeof(name) - 1, exact_v01, sizeof(exact_v01) - 1),
                "exact future version base fields are authoritative");
    assert_bool(1, block.has_traceparent, "future version records field presence");
    assert_bool(1, block.authoritative, "future version base fields are adoptable");
    assert_bool(k_flag_sampled, block.tp.flags, "future version ignores unsupported trace flags");

    tp_info_t tp = {.flags = 0x85, .sampling_decision = k_sampling_decision_applied};
    memset(tp.trace_id, 0x22, sizeof(tp.trace_id));
    memset(tp.span_id, 0x33, sizeof(tp.span_id));
    go_hpack_adopt_traceparent(&tp, &block);
    assert_bytes(block.tp.trace_id, tp.trace_id, sizeof(tp.trace_id), "adopt future trace ID");
    assert_bytes(block.tp.span_id, tp.span_id, sizeof(tp.span_id), "adopt future span ID");
    assert_bool(block.tp.flags, tp.flags, "adopt future trace flags");

    go_hpack_clear_block(&block);
    go_hpack_observe_pseudo_header(&block, method, sizeof(method) - 1);
    assert_bool(k_go_hpack_traceparent_authoritative,
                go_hpack_capture_traceparent(
                    &block, name, sizeof(name) - 1, extended_v01, sizeof(extended_v01) - 1),
                "extended future version base fields are authoritative");
    assert_bool(1, block.has_traceparent, "extended version records field presence");
    assert_bool(1, block.authoritative, "extended version base fields are adoptable");
}

static void test_invalid_or_duplicate_traceparent_is_non_authoritative(void) {
    const unsigned char method[] = ":method";
    const unsigned char name[] = "traceparent";
    const unsigned char invalid[] = "00-00000000000000000000000000000000-1112131415161718-01";
    const unsigned char valid[] = "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01";
    const unsigned char other_valid[] = "00-2122232425262728292a2b2c2d2e2f30-3132333435363738-01";
    go_hpack_block_t block = {};

    go_hpack_observe_pseudo_header(&block, method, sizeof(method) - 1);
    assert_bool(
        k_go_hpack_traceparent_non_authoritative,
        go_hpack_capture_traceparent(&block, name, sizeof(name) - 1, invalid, sizeof(invalid) - 1),
        "invalid first traceparent records non-authoritative presence");
    assert_bool(1, block.has_traceparent, "invalid traceparent records field presence");
    assert_bool(0, block.authoritative, "invalid first traceparent cannot be adopted");

    assert_bool(
        k_go_hpack_traceparent_non_authoritative,
        go_hpack_capture_traceparent(&block, name, sizeof(name) - 1, valid, sizeof(valid) - 1),
        "valid traceparent after an invalid duplicate remains non-authoritative");
    assert_bool(0, block.tp.trace_id[0], "later duplicate traceparent is not decoded");

    go_hpack_clear_block(&block);
    go_hpack_observe_pseudo_header(&block, method, sizeof(method) - 1);
    assert_bool(
        k_go_hpack_traceparent_authoritative,
        go_hpack_capture_traceparent(&block, name, sizeof(name) - 1, valid, sizeof(valid) - 1),
        "first valid traceparent is authoritative");
    assert_bool(k_go_hpack_traceparent_non_authoritative,
                go_hpack_capture_traceparent(
                    &block, name, sizeof(name) - 1, other_valid, sizeof(other_valid) - 1),
                "second valid traceparent makes the block non-authoritative");
    assert_bool(0, block.authoritative, "duplicate traceparents cannot be adopted");

    tp_info_t tp = {.ts = 1234, .flags = 0x85};
    memset(tp.trace_id, 0x22, sizeof(tp.trace_id));
    memset(tp.span_id, 0x33, sizeof(tp.span_id));
    const tp_info_t original = tp;
    go_hpack_adopt_traceparent(&tp, &block);
    assert_bytes(&original, &tp, sizeof(tp), "duplicate traceparent cannot alter request context");
}

static void test_only_proven_absence_allows_direct_injection(void) {
    const unsigned char method[] = ":method";
    const unsigned char authority[] = ":authority";
    go_hpack_block_t block = {};

    assert_bool(k_go_hpack_traceparent_unknown,
                go_hpack_traceparent_class(&block),
                "missing block observation is unknown");
    assert_bool(0,
                go_hpack_can_inject_traceparent(go_hpack_traceparent_class(&block)),
                "unknown observation suppresses direct injection");

    go_hpack_observe_pseudo_header(&block, authority, sizeof(authority) - 1);
    assert_bool(k_go_hpack_traceparent_unknown,
                go_hpack_traceparent_class(&block),
                "request candidate does not prove field absence");
    assert_bool(0,
                go_hpack_can_inject_traceparent(go_hpack_traceparent_class(&block)),
                "request candidate suppresses direct injection");

    go_hpack_observe_pseudo_header(&block, method, sizeof(method) - 1);
    assert_bool(k_go_hpack_traceparent_absent,
                go_hpack_traceparent_class(&block),
                "completed request observation proves field absence");
    assert_bool(1,
                go_hpack_can_inject_traceparent(go_hpack_traceparent_class(&block)),
                "only proven absence allows direct injection");
}

int main(void) {
    test_decode_valid_traceparent();
    test_reject_invalid_fields();
    test_adopt_traceparent();
    test_xnet_initial_request_and_trailer();
    test_grpc_initial_request_order();
    test_non_request_blocks_clear_or_reject();
    test_preserve_future_versions();
    test_invalid_or_duplicate_traceparent_is_non_authoritative();
    test_only_proven_absence_allows_direct_injection();

    return failures ? 1 : 0;
}
