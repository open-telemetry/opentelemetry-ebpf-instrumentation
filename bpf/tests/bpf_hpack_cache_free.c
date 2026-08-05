// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#define OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE 0
#include <common/hpack.h>

#define TP_VALUE "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01"

static unsigned int failures;

static void assert_u32(unsigned int want, unsigned int got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %u, got %u\n", message, want, got);
    failures++;
}

static hpack_traceparent_result_t
scan(const unsigned char *block, unsigned int block_len, hpack_dynamic_name_state_t *dynamic) {
    hpack_traceparent_scan_state_t state = {};
    hpack_dynamic_name_state_init(dynamic);
    hpack_traceparent_scan_init(&state, block_len, 1);
    for (u32 step = 0; step < k_hpack_tp_max_scan && !state.done; step++) {
        hpack_traceparent_scan_step(block, &state, dynamic);
    }
    if (!state.done) {
        hpack_traceparent_scan_fail(&state);
    }
    return hpack_traceparent_scan_result(&state);
}

static void test_literal_traceparent_remains_authoritative(void) {
    static const unsigned char block[] = "\x40\x0b"
                                         "traceparent"
                                         "\x37" TP_VALUE;
    hpack_dynamic_name_state_t dynamic = {};
    const hpack_traceparent_result_t result = scan(block, sizeof(block) - 1, &dynamic);
    assert_u32(k_hpack_traceparent_found, result.status, "cache-free literal traceparent");
    assert_u32(1, dynamic.entry_count, "cache-free scanner remembers current-block names");
    assert_u32(0, dynamic.table_size, "cache-free scanner keeps no transient table size");
}

static void test_same_block_dynamic_reference_preserves_later_traceparent(void) {
    static const unsigned char block[] = "\x40\x01"
                                         "x"
                                         "\x00\xbe\x10\x0b"
                                         "traceparent"
                                         "\x37" TP_VALUE;
    hpack_dynamic_name_state_t dynamic = {};
    const hpack_traceparent_result_t result = scan(block, sizeof(block) - 1, &dynamic);
    assert_u32(k_hpack_traceparent_found,
               result.status,
               "known current-block dynamic reference preserves later traceparent");
    assert_u32(1, dynamic.entry_count, "current-block dynamic name remains addressable");
}

static void test_same_block_dynamic_name_preserves_later_traceparent(void) {
    static const unsigned char block[] = "\x40\x01"
                                         "x"
                                         "\x00\x0f\x2f\x00\x10\x0b"
                                         "traceparent"
                                         "\x37" TP_VALUE;
    hpack_dynamic_name_state_t dynamic = {};
    const hpack_traceparent_result_t result = scan(block, sizeof(block) - 1, &dynamic);
    assert_u32(k_hpack_traceparent_found,
               result.status,
               "known current-block dynamic name preserves later traceparent");
}

static void test_pre_block_dynamic_reference_fails_closed(void) {
    static const unsigned char block[] = "\xbe\x10\x0b"
                                         "traceparent"
                                         "\x37" TP_VALUE;
    hpack_dynamic_name_state_t dynamic = {};
    const hpack_traceparent_result_t result = scan(block, sizeof(block) - 1, &dynamic);
    assert_u32(k_hpack_traceparent_unknown,
               result.status,
               "pre-block dynamic reference remains conservatively unresolved");
}

static void test_dynamic_traceparent_value_fails_closed(void) {
    static const unsigned char block[] = "\x40\x0b"
                                         "traceparent"
                                         "\x37" TP_VALUE "\xbe";
    hpack_dynamic_name_state_t dynamic = {};
    const hpack_traceparent_result_t result = scan(block, sizeof(block) - 1, &dynamic);
    assert_u32(k_hpack_traceparent_unknown,
               result.status,
               "cache-free indexed traceparent has no authoritative decoded value");
}

static void test_lazy_eviction_membership(void) {
    static const unsigned char active_block[] = "\x3f\x09"
                                                "\x40\x01x\x00"
                                                "\x40\x01y\x00"
                                                "\x0f\x2f\x00\x10\x0b"
                                                "traceparent"
                                                "\x37" TP_VALUE;
    hpack_dynamic_name_state_t dynamic = {};
    hpack_traceparent_result_t result = scan(active_block, sizeof(active_block) - 1, &dynamic);
    assert_u32(k_hpack_traceparent_found,
               result.status,
               "newest current-block entry remains active after lazy eviction");
    assert_u32(2, dynamic.entry_count, "lazy eviction retains bounded insertion history");

    static const unsigned char evicted_block[] = "\x3f\x09"
                                                 "\x40\x01x\x00"
                                                 "\x40\x01y\x00"
                                                 "\x0f\x30\x00\x10\x0b"
                                                 "traceparent"
                                                 "\x37" TP_VALUE;
    result = scan(evicted_block, sizeof(evicted_block) - 1, &dynamic);
    assert_u32(k_hpack_traceparent_unknown,
               result.status,
               "evicted current-block entry cannot become authoritative");
}

static void test_zero_table_oversized_insert_clears_history(void) {
    static const unsigned char block[] = "\x20\x41\x00\x10\x0b"
                                         "traceparent"
                                         "\x37" TP_VALUE;
    hpack_dynamic_name_state_t dynamic = {};
    const hpack_traceparent_result_t result = scan(block, sizeof(block) - 1, &dynamic);
    assert_u32(k_hpack_traceparent_found,
               result.status,
               "oversized insert at a zero table does not hide later traceparent");
    assert_u32(0, dynamic.entry_count, "oversized insert clears current-block history");
    assert_u32(0, dynamic.max_table_size, "zero table update remains authoritative locally");
}

static void test_maximum_current_block_history(void) {
    unsigned char block[k_hpack_tp_max_scan] = {};
    u32 pos = 0;
    for (u32 i = 0; i < k_hpack_max_cache_free_dynamic_entries; i++) {
        block[pos++] = 0x41;
        block[pos++] = 0x00;
    }
    block[pos++] = 0x82;
    assert_u32(k_hpack_tp_max_scan, pos, "maximum history fills the bounded block");

    hpack_dynamic_name_state_t dynamic = {};
    const hpack_traceparent_result_t result = scan(block, pos, &dynamic);
    assert_u32(k_hpack_traceparent_absent, result.status, "maximum history remains parseable");
    assert_u32(k_hpack_max_cache_free_dynamic_entries,
               dynamic.entry_count,
               "maximum bounded insertion count remains exact");
    assert_u32(1,
               hpack_dynamic_name_state_bounds_valid(&dynamic),
               "maximum bounded insertion history satisfies resume invariants");

    u16 name_size = 0;
    u8 classification = k_hpack_name_unknown;
    assert_u32(1,
               hpack_lookup_dynamic_name(
                   &dynamic, k_hpack_static_table_size + 1, &name_size, &classification),
               "newest entry remains active at the history boundary");
    assert_u32(10, name_size, "static :authority name size remains exact");
    assert_u32(
        k_hpack_name_non_traceparent, classification, "static :authority remains non-traceparent");
    assert_u32(0,
               hpack_lookup_dynamic_name(&dynamic,
                                         k_hpack_static_table_size +
                                             k_hpack_max_cache_free_dynamic_entries,
                                         NULL,
                                         NULL),
               "oldest lazily evicted entry is unresolved");
}

static void test_raw_value_jump_preserves_later_traceparent(void) {
    unsigned char block[192] = {};
    u32 pos = 0;
    block[pos++] = 0x01;
    block[pos++] = 100;
    memset(block + pos, 'a', 100);
    pos += 100;
    block[pos++] = 0x10;
    block[pos++] = k_hpack_tp_name_len;
    memcpy(block + pos, k_hpack_tp_name, k_hpack_tp_name_len);
    pos += k_hpack_tp_name_len;
    block[pos++] = k_hpack_value_len_tp;
    memcpy(block + pos, TP_VALUE, k_hpack_value_len_tp);
    pos += k_hpack_value_len_tp;

    hpack_dynamic_name_state_t dynamic = {};
    const hpack_traceparent_result_t result = scan(block, pos, &dynamic);
    assert_u32(k_hpack_traceparent_found,
               result.status,
               "cache-free scanner resumes after a raw value position jump");
}

int main(void) {
    test_literal_traceparent_remains_authoritative();
    test_same_block_dynamic_reference_preserves_later_traceparent();
    test_same_block_dynamic_name_preserves_later_traceparent();
    test_pre_block_dynamic_reference_fails_closed();
    test_dynamic_traceparent_value_fails_closed();
    test_lazy_eviction_membership();
    test_zero_table_oversized_insert_clears_history();
    test_maximum_current_block_history();
    test_raw_value_jump_preserves_later_traceparent();

    if (failures) {
        fprintf(stderr, "%u test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
