// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include <common/hpack.h>

static unsigned int failures;

static void assert_u32(unsigned int want, unsigned int got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %u, got %u\n", message, want, got);
    failures++;
}

static hpack_traceparent_result_t scan_with_dynamic_state(const unsigned char *block,
                                                          unsigned int block_len,
                                                          unsigned int complete,
                                                          hpack_dynamic_name_state_t *dynamic) {
    hpack_traceparent_scan_state_t scan = {};
    hpack_traceparent_scan_init(&scan, block_len, complete);

    for (u32 step = 0; step < k_hpack_tp_max_scan && !scan.done; step++) {
        hpack_traceparent_scan_step(block, &scan, dynamic);
    }
    if (!scan.done) {
        hpack_traceparent_scan_fail(&scan);
        hpack_dynamic_name_state_invalidate(dynamic);
    }
    return hpack_traceparent_scan_result(&scan);
}

static hpack_traceparent_decode_result_t
decode_and_cache_traceparent(const unsigned char *block,
                             const hpack_traceparent_result_t *result,
                             hpack_dynamic_name_state_t *dynamic,
                             tp_info_t *tp,
                             unsigned int *cache_result) {
    const hpack_traceparent_decode_result_t decoded = hpack_decode_traceparent_value(
        block + result->value_offset, result->encoded_value_len, result->value_huffman, tp, 1);
    *cache_result = 0;
    if (decoded.valid && result->inserted_identity_valid) {
        *cache_result = hpack_dynamic_store_traceparent(
            dynamic, result->inserted_slot, result->inserted_generation, tp);
    }
    return decoded;
}

static void assert_result(const unsigned char *block,
                          unsigned int block_len,
                          unsigned int status,
                          unsigned int value_offset,
                          unsigned int encoded_value_len,
                          unsigned int representation,
                          const char *message) {
    const hpack_traceparent_result_t result = hpack_find_traceparent(block, block_len, 1);
    assert_u32(status, result.status, message);
    if (status == k_hpack_traceparent_found) {
        assert_u32(value_offset, result.value_offset, "traceparent value offset");
        assert_u32(encoded_value_len, result.encoded_value_len, "traceparent encoded value length");
        assert_u32(representation, result.representation, "traceparent representation");
    }
}

static hpack_traceparent_decode_result_t decode_in_validation_chunks(const unsigned char *data,
                                                                     u32 encoded_len,
                                                                     tp_info_t *tp,
                                                                     u32 *validation_calls) {
    hpack_traceparent_decoder_state_t state = {};
    hpack_traceparent_decoder_init(&state, encoded_len, 0, 0, tp);
    *validation_calls = 0;

    for (u32 validation = 0; validation < k_h2_hpack_max_validation_calls && !state.done;
         validation++) {
        for (u32 call = 0; call < k_h2_hpack_decode_calls_per_validation && !state.done; call++) {
            for (u32 step = 0; step < k_h2_hpack_decode_steps_per_call && !state.done; step++) {
                hpack_traceparent_decoder_step(data, &state, tp);
            }
        }
        (*validation_calls)++;
    }
    if (!state.done) {
        state.value.valid_base = 0;
        hpack_traceparent_decoder_finish(&state, tp);
    }
    return hpack_traceparent_decoder_result(&state);
}

#define TP_VALUE "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01"
#define TP_VALUE_B "00-2122232425262728292a2b2c2d2e2f30-3132333435363738-00"
#define FUTURE_TP_VALUE "01-0102030405060708090a0b0c0d0e0f10-1112131415161718-ff-foo"

static const unsigned char huffman_tp_value[] = {
    0x00, 0x16, 0x00, 0x40, 0x20, 0x32, 0x06, 0x80, 0xd8, 0x1c, 0x03, 0xa0, 0x78,
    0x0f, 0x80, 0x60, 0x8c, 0x04, 0x04, 0x80, 0x28, 0x25, 0x08, 0x16, 0x08, 0x42,
    0x20, 0xb2, 0x16, 0x82, 0xd8, 0x5c, 0x0b, 0xa1, 0x79, 0x60, 0x07,
};

static const unsigned char huffman_future_tp_value[] = {
    0x00, 0x56, 0x00, 0x40, 0x20, 0x32, 0x06, 0x80, 0xd8, 0x1c, 0x03, 0xa0, 0x78, 0x0f,
    0x80, 0x60, 0x8c, 0x04, 0x04, 0x80, 0x28, 0x25, 0x08, 0x16, 0x08, 0x42, 0x20, 0xb2,
    0x16, 0x82, 0xd8, 0x5c, 0x0b, 0xa1, 0x79, 0x69, 0x65, 0x5a, 0x53, 0x9f,
};

// Emitted by golang.org/x/net/http2/hpack with one encoder reused for both
// fields. The second field is a literal with incremental indexing whose name
// is dynamic index 62.
static const unsigned char realistic_first_stream[] = {
    0x40, 0x88, 0x4d, 0x83, 0x21, 0x6b, 0x1d, 0x85, 0xa9, 0x3f, 0xa5, 0x00, 0x16, 0x00, 0x40, 0x20,
    0x32, 0x06, 0x80, 0xd8, 0x1c, 0x03, 0xa0, 0x78, 0x0f, 0x80, 0x60, 0x8c, 0x04, 0x04, 0x80, 0x28,
    0x25, 0x08, 0x16, 0x08, 0x42, 0x20, 0xb2, 0x16, 0x82, 0xd8, 0x5c, 0x0b, 0xa1, 0x79, 0x60, 0x07,
};

static const unsigned char realistic_second_stream[] = {
    0x7e, 0xa6, 0x00, 0x16, 0x10, 0x44, 0x21, 0x32, 0x26, 0x84, 0xd8, 0x9c, 0x13, 0xa2,
    0x78, 0x4f, 0x88, 0x62, 0x8c, 0x44, 0x14, 0x82, 0x28, 0xa5, 0x64, 0x0b, 0x32, 0x16,
    0x44, 0xcb, 0x2c, 0xb4, 0xcb, 0x6c, 0xb8, 0xcb, 0xac, 0xbc, 0xb0, 0x01,
};

static void test_literal_representations(void) {
    static const unsigned char no_index[] = "\x00\x0b"
                                            "traceparent"
                                            "\x37" TP_VALUE;
    static const unsigned char never_indexed[] = "\x10\x0b"
                                                 "traceparent"
                                                 "\x37" TP_VALUE;
    static const unsigned char incremental[] = "\x40\x0b"
                                               "traceparent"
                                               "\x37" TP_VALUE;

    assert_result(no_index,
                  sizeof(no_index) - 1,
                  k_hpack_traceparent_found,
                  k_hpack_tp_val_offset,
                  k_hpack_value_len_tp,
                  k_hpack_representation_without_indexing,
                  "literal without indexing");
    assert_result(never_indexed,
                  sizeof(never_indexed) - 1,
                  k_hpack_traceparent_found,
                  k_hpack_tp_val_offset,
                  k_hpack_value_len_tp,
                  k_hpack_representation_never_indexed,
                  "literal never indexed");
    assert_result(incremental,
                  sizeof(incremental) - 1,
                  k_hpack_traceparent_found,
                  k_hpack_tp_val_offset,
                  k_hpack_value_len_tp,
                  k_hpack_representation_incremental,
                  "literal with incremental indexing");
}

static void test_huffman_name(void) {
    static const unsigned char block[] = "\x10\x88\x4d\x83\x21\x6b\x1d\x85\xa9\x3f"
                                         "\x37" TP_VALUE;

    assert_result(block,
                  sizeof(block) - 1,
                  k_hpack_traceparent_found,
                  k_hpack_tp_val_offset_huffman,
                  k_hpack_value_len_tp,
                  k_hpack_representation_never_indexed,
                  "huffman traceparent name");
}

static void test_static_and_dynamic_indices(void) {
    static const unsigned char static_indexed[] = {0x82, 0x84};
    static const unsigned char static_name[] = {0x0f, 0x08, 0x01, 'x'};
    static const unsigned char incremental_static_name[] = {0x60, 0x01, 'x'};
    static const unsigned char dynamic_indexed[] = {0xbe};
    static const unsigned char dynamic_name[] = {0x0f, 0x2f, 0x01, 'x'};

    assert_result(static_indexed,
                  sizeof(static_indexed),
                  k_hpack_traceparent_absent,
                  0,
                  0,
                  0,
                  "static indexed headers");
    assert_result(static_name,
                  sizeof(static_name),
                  k_hpack_traceparent_absent,
                  0,
                  0,
                  0,
                  "static indexed name");
    assert_result(incremental_static_name,
                  sizeof(incremental_static_name),
                  k_hpack_traceparent_absent,
                  0,
                  0,
                  0,
                  "incremental static indexed name");
    assert_result(dynamic_indexed,
                  sizeof(dynamic_indexed),
                  k_hpack_traceparent_unknown,
                  0,
                  0,
                  0,
                  "dynamic indexed header");
    assert_result(dynamic_name,
                  sizeof(dynamic_name),
                  k_hpack_traceparent_unknown,
                  0,
                  0,
                  0,
                  "dynamic indexed name");
}

static void test_malformed_and_incomplete(void) {
    static const unsigned char truncated_integer[] = {0xff, 0x80};
    static const unsigned char truncated_string[] = {0x00, 0x0b, 't'};
    static const unsigned char truncated_huffman_name[] = {0x40, 0x82, 0x00};
    static const unsigned char complete_static[] = {0x82};
    static const unsigned char insert_x[] = {0x40, 0x01, 'x', 0x00};

    assert_result(truncated_integer,
                  sizeof(truncated_integer),
                  k_hpack_traceparent_unknown,
                  0,
                  0,
                  0,
                  "truncated integer");
    assert_result(truncated_string,
                  sizeof(truncated_string),
                  k_hpack_traceparent_unknown,
                  0,
                  0,
                  0,
                  "truncated string");

    const hpack_traceparent_result_t incomplete =
        hpack_find_traceparent(complete_static, sizeof(complete_static), 0);
    assert_u32(
        k_hpack_traceparent_unknown, incomplete.status, "incomplete header block is unknown");

    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    hpack_traceparent_result_t result =
        scan_with_dynamic_state(insert_x, sizeof(insert_x), 1, &dynamic);
    assert_u32(k_hpack_traceparent_absent, result.status, "prepopulate dynamic mirror");
    assert_u32(1, dynamic.entry_count, "prepopulated dynamic entry");

    result = scan_with_dynamic_state(truncated_integer, sizeof(truncated_integer), 1, &dynamic);
    assert_u32(k_hpack_traceparent_unknown,
               result.status,
               "truncated integer invalidates a prepopulated mirror");
    assert_u32(0, dynamic.valid, "truncated integer invalidates dynamic authority");
    assert_u32(0, dynamic.entry_count, "truncated integer clears dynamic entries");

    hpack_dynamic_name_state_init(&dynamic);
    result = scan_with_dynamic_state(insert_x, sizeof(insert_x), 1, &dynamic);
    assert_u32(k_hpack_traceparent_absent, result.status, "repopulate dynamic mirror");
    result = scan_with_dynamic_state(
        truncated_huffman_name, sizeof(truncated_huffman_name), 1, &dynamic);
    assert_u32(k_hpack_traceparent_unknown,
               result.status,
               "truncated huffman name invalidates a prepopulated mirror");
    assert_u32(0, dynamic.valid, "truncated huffman name invalidates dynamic authority");
    assert_u32(0, dynamic.entry_count, "truncated huffman name clears dynamic entries");
}

static void test_huffman_scan_resumes_across_parser_chunks(void) {
    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);

    hpack_traceparent_scan_state_t scan = {};
    hpack_traceparent_scan_init(&scan, sizeof(realistic_first_stream), 1);

    u32 steps = 0;
    for (; steps < 16; steps++) {
        hpack_traceparent_scan_step(realistic_first_stream, &scan, &dynamic);
    }
    assert_u32(0, scan.done, "huffman scan remains active after one parser chunk");
    assert_u32(
        k_hpack_scan_value_huffman, scan.phase, "huffman value resumes in the next parser chunk");
    assert_u32(0, dynamic.entry_count, "incomplete huffman value is not inserted");

    for (; steps < k_hpack_tp_max_scan && !scan.done; steps++) {
        hpack_traceparent_scan_step(realistic_first_stream, &scan, &dynamic);
    }
    const hpack_traceparent_result_t result = hpack_traceparent_scan_result(&scan);
    assert_u32(k_hpack_traceparent_found, result.status, "chunked huffman scan completes");
    assert_u32(sizeof(realistic_first_stream), steps, "one scan step consumes one huffman byte");
    assert_u32(sizeof(realistic_first_stream) - sizeof(huffman_tp_value),
               result.value_offset,
               "chunked huffman value offset");
    assert_u32(
        sizeof(huffman_tp_value), result.encoded_value_len, "chunked huffman encoded value length");
    assert_u32(1, dynamic.entry_count, "validated huffman field is inserted once");
    assert_u32(98, dynamic.table_size, "huffman insertion uses exact decoded RFC entry size");
}

static void test_scan_rejects_lost_data_len_bound(void) {
    static const unsigned char insert_x[] = {0x40, 0x01, 'x', 0x00};
    unsigned char block[k_hpack_tp_max_scan + 1] = {};

    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    const hpack_traceparent_result_t inserted =
        scan_with_dynamic_state(insert_x, sizeof(insert_x), 1, &dynamic);
    assert_u32(k_hpack_traceparent_absent, inserted.status, "prepopulate bounded scan mirror");
    assert_u32(1, dynamic.entry_count, "bounded scan mirror has one entry");

    hpack_traceparent_scan_state_t scan = {};
    scan.pos = k_hpack_tp_max_scan;
    scan.data_len = k_hpack_tp_max_scan + 1;
    scan.complete = 1;
    hpack_traceparent_scan_step(block, &scan, &dynamic);

    assert_u32(1, scan.done, "out-of-range map-backed scan state terminates");
    assert_u32(k_hpack_traceparent_unknown,
               scan.status,
               "out-of-range map-backed scan state fails closed");
    assert_u32(0, dynamic.valid, "out-of-range scan state revokes dynamic authority");
    assert_u32(0, dynamic.entry_count, "out-of-range scan state clears dynamic entries");
}

static void test_decoder_rejects_lost_encoded_len_bound(void) {
    unsigned char block[k_hpack_tp_max_scan + 1] = {};
    tp_info_t tp = {};
    memset(tp.trace_id, 0xff, sizeof(tp.trace_id));
    memset(tp.span_id, 0xff, sizeof(tp.span_id));

    hpack_traceparent_decoder_state_t decoder = {};
    decoder.value.valid_base = 1;
    decoder.encoded_pos = k_hpack_tp_max_scan;
    decoder.encoded_len = k_hpack_tp_max_scan + 1;
    decoder.initialized = 1;
    hpack_traceparent_decoder_step(block, &decoder, &tp);

    assert_u32(1, decoder.done, "out-of-range map-backed decoder terminates");
    assert_u32(0, decoder.valid, "out-of-range map-backed decoder fails closed");
    assert_u32(0, tp.trace_id[0], "out-of-range decoder clears the partial trace ID");
    assert_u32(0, tp.span_id[0], "out-of-range decoder clears the partial span ID");
}

static void test_huffman_value(void) {
    static const unsigned char block[] = {
        0x00, 0x0b, 't',  'r',  'a',  'c',  'e',  'p',  'a',  'r',  'e',  'n',  't',
        0xa5, 0x00, 0x16, 0x00, 0x40, 0x20, 0x32, 0x06, 0x80, 0xd8, 0x1c, 0x03, 0xa0,
        0x78, 0x0f, 0x80, 0x60, 0x8c, 0x04, 0x04, 0x80, 0x28, 0x25, 0x08, 0x16, 0x08,
        0x42, 0x20, 0xb2, 0x16, 0x82, 0xd8, 0x5c, 0x0b, 0xa1, 0x79, 0x60, 0x07,
    };
    const hpack_traceparent_result_t result = hpack_find_traceparent(block, sizeof(block), 1);

    assert_u32(k_hpack_traceparent_found, result.status, "huffman value presence");
    assert_u32(1, result.value_huffman, "huffman value marker");
    assert_u32(
        sizeof(huffman_tp_value), result.encoded_value_len, "huffman traceparent encoded length");

    tp_info_t tp = {};
    const hpack_traceparent_decode_result_t decoded = hpack_decode_traceparent_value(
        block + result.value_offset, result.encoded_value_len, result.value_huffman, &tp, 0);
    assert_u32(1, decoded.valid, "valid huffman traceparent");
    assert_u32(k_hpack_value_len_tp, decoded.value_len, "huffman traceparent decoded length");
    assert_u32(0, decoded.version, "huffman traceparent version");
    assert_u32(1, tp.flags, "huffman traceparent flags");
    assert_u32(0x01, tp.trace_id[0], "huffman trace id first byte");
    assert_u32(0x10, tp.trace_id[15], "huffman trace id last byte");
    assert_u32(0x11, tp.span_id[0], "huffman span id first byte");
    assert_u32(0x18, tp.span_id[7], "huffman span id last byte");
}

static void test_huffman_validation(void) {
    unsigned char invalid_padding[sizeof(huffman_tp_value)];
    memcpy(invalid_padding, huffman_tp_value, sizeof(invalid_padding));
    invalid_padding[sizeof(invalid_padding) - 1] &= 0xfe;

    tp_info_t tp = {};
    hpack_traceparent_decode_result_t decoded =
        hpack_decode_traceparent_value(invalid_padding, sizeof(invalid_padding), 1, &tp, 0);
    assert_u32(0, decoded.valid, "reject invalid huffman padding");

    static const unsigned char eos[] = {0xff, 0xff, 0xff, 0xff};
    decoded = hpack_decode_traceparent_value(eos, sizeof(eos), 1, &tp, 0);
    assert_u32(0, decoded.valid, "reject huffman EOS symbol");

    static const unsigned char explicit_eos[] = {
        0x00,
        0x0b,
        't',
        'r',
        'a',
        'c',
        'e',
        'p',
        'a',
        'r',
        'e',
        'n',
        't',
        0x84,
        0xff,
        0xff,
        0xff,
        0xff,
    };
    const hpack_traceparent_result_t result =
        hpack_find_traceparent(explicit_eos, sizeof(explicit_eos), 1);
    assert_u32(k_hpack_traceparent_unknown,
               result.status,
               "malformed huffman field poisons the header block");

    unsigned char invalid_incremental[sizeof(realistic_first_stream)];
    memcpy(invalid_incremental, realistic_first_stream, sizeof(invalid_incremental));
    invalid_incremental[sizeof(invalid_incremental) - 1] &= 0xfe;
    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    const hpack_traceparent_result_t invalid_incremental_result =
        scan_with_dynamic_state(invalid_incremental, sizeof(invalid_incremental), 1, &dynamic);
    assert_u32(k_hpack_traceparent_unknown,
               invalid_incremental_result.status,
               "invalid final huffman padding poisons an incremental field");
    assert_u32(0, dynamic.valid, "invalid final huffman padding revokes dynamic authority");
    assert_u32(0, dynamic.entry_count, "invalid huffman field is never inserted");

    static const unsigned char truncated[] = {0x00};
    decoded = hpack_decode_traceparent_value(truncated, sizeof(truncated), 1, &tp, 0);
    assert_u32(0, decoded.valid, "reject truncated huffman traceparent");
}

static void test_duplicate_traceparents(void) {
    static const unsigned char valid_then_valid[] = "\x00\x0b"
                                                    "traceparent"
                                                    "\x37" TP_VALUE "\x00\x0b"
                                                    "traceparent"
                                                    "\x37" TP_VALUE;
    static const unsigned char valid_then_malformed[] = "\x00\x0b"
                                                        "traceparent"
                                                        "\x37" TP_VALUE "\x00\x0b"
                                                        "traceparent"
                                                        "\x03"
                                                        "bad";
    static const unsigned char malformed_then_valid[] = "\x00\x0b"
                                                        "traceparent"
                                                        "\x03"
                                                        "bad"
                                                        "\x00\x0b"
                                                        "traceparent"
                                                        "\x37" TP_VALUE;

    assert_result(valid_then_valid,
                  sizeof(valid_then_valid) - 1,
                  k_hpack_traceparent_unknown,
                  0,
                  0,
                  0,
                  "two valid traceparents are non-authoritative");
    assert_result(valid_then_malformed,
                  sizeof(valid_then_malformed) - 1,
                  k_hpack_traceparent_unknown,
                  0,
                  0,
                  0,
                  "valid traceparent followed by malformed duplicate is non-authoritative");
    assert_result(malformed_then_valid,
                  sizeof(malformed_then_valid) - 1,
                  k_hpack_traceparent_unknown,
                  0,
                  0,
                  0,
                  "malformed traceparent followed by valid duplicate is non-authoritative");
}

static void test_future_version_lengths(void) {
    static const unsigned char block[] = "\x10\x0b"
                                         "traceparent"
                                         "\x3b" FUTURE_TP_VALUE;
    assert_result(block,
                  sizeof(block) - 1,
                  k_hpack_traceparent_found,
                  k_hpack_tp_val_offset,
                  sizeof(FUTURE_TP_VALUE) - 1,
                  k_hpack_representation_never_indexed,
                  "future-version encoded length");

    tp_info_t tp = {};
    hpack_traceparent_decode_result_t decoded = hpack_decode_traceparent_value(
        (const unsigned char *)FUTURE_TP_VALUE, sizeof(FUTURE_TP_VALUE) - 1, 0, &tp, 0);
    assert_u32(1, decoded.valid, "valid raw future-version traceparent");
    assert_u32(sizeof(FUTURE_TP_VALUE) - 1, decoded.value_len, "raw future value length");
    assert_u32(1, decoded.version, "raw future version");
    assert_u32(k_flag_sampled, tp.flags, "raw future flags masked");

    decoded = hpack_decode_traceparent_value(
        huffman_future_tp_value, sizeof(huffman_future_tp_value), 1, &tp, 0);
    assert_u32(1, decoded.valid, "valid huffman future-version traceparent");
    assert_u32(sizeof(FUTURE_TP_VALUE) - 1, decoded.value_len, "huffman future value length");
    assert_u32(1, decoded.version, "huffman future version");
    assert_u32(k_flag_sampled, tp.flags, "huffman future flags masked");

    unsigned char max_future[k_hpack_tp_max_scan];
    memcpy(max_future, TP_VALUE, k_hpack_value_len_tp);
    max_future[1] = '1';
    max_future[k_hpack_value_len_tp] = '-';
    memset(
        max_future + k_hpack_value_len_tp + 1, 'a', sizeof(max_future) - k_hpack_value_len_tp - 1);
    u32 validation_calls = 0;
    decoded = decode_in_validation_chunks(max_future, sizeof(max_future), &tp, &validation_calls);
    assert_u32(1, decoded.valid, "valid maximum raw future-version traceparent");
    assert_u32(sizeof(max_future), decoded.value_len, "maximum raw future value length");
    assert_u32(1, decoded.version, "maximum raw future version");
    assert_u32(
        1, validation_calls, "raw future-version suffix fast-forwards in one validation call");

    max_future[k_hpack_value_len_tp] = 'x';
    decoded = decode_in_validation_chunks(max_future, sizeof(max_future), &tp, &validation_calls);
    assert_u32(0, decoded.valid, "maximum raw future value still requires an extension dash");

    unsigned char invalid_huffman_future[sizeof(huffman_future_tp_value)];
    memcpy(invalid_huffman_future, huffman_future_tp_value, sizeof(invalid_huffman_future));
    invalid_huffman_future[sizeof(invalid_huffman_future) - 1] &= 0xfe;
    decoded = hpack_decode_traceparent_value(
        invalid_huffman_future, sizeof(invalid_huffman_future), 1, &tp, 0);
    assert_u32(0, decoded.valid, "huffman future suffix still validates final padding");

    static const unsigned char v00_extension[] = TP_VALUE "-extra";
    decoded = hpack_decode_traceparent_value(v00_extension, sizeof(v00_extension) - 1, 0, &tp, 0);
    assert_u32(0, decoded.valid, "reject v00 extension");
}

static void test_raw_string_fast_forward_scan(void) {
    unsigned char absent[k_hpack_tp_max_scan] = {0x41, 100};
    memset(absent + 2, 'a', 100);
    memset(absent + 102, 0x82, sizeof(absent) - 102);
    assert_result(absent,
                  sizeof(absent),
                  k_hpack_traceparent_absent,
                  0,
                  0,
                  0,
                  "maximum absent block survives a raw value position jump");

    unsigned char followed[192] = {};
    u32 pos = 0;
    followed[pos++] = 0x01;
    followed[pos++] = 100;
    memset(followed + pos, 'b', 100);
    pos += 100;
    followed[pos++] = 0x10;
    followed[pos++] = k_hpack_tp_name_len;
    memcpy(followed + pos, k_hpack_tp_name, k_hpack_tp_name_len);
    pos += k_hpack_tp_name_len;
    followed[pos++] = k_hpack_value_len_tp;
    const u32 value_offset = pos;
    memcpy(followed + pos, TP_VALUE, k_hpack_value_len_tp);
    pos += k_hpack_value_len_tp;

    assert_result(followed,
                  pos,
                  k_hpack_traceparent_found,
                  value_offset,
                  k_hpack_value_len_tp,
                  k_hpack_representation_never_indexed,
                  "traceparent after a skipped raw field remains discoverable");
}

static void test_dynamic_name_persists_across_streams(void) {
    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);

    hpack_traceparent_result_t result = scan_with_dynamic_state(
        realistic_first_stream, sizeof(realistic_first_stream), 1, &dynamic);
    assert_u32(k_hpack_traceparent_found, result.status, "first encoded stream traceparent");
    assert_u32(k_hpack_representation_incremental,
               result.representation,
               "first encoded stream representation");
    assert_u32(1, dynamic.entry_count, "first stream inserts one dynamic entry");
    assert_u32(k_hpack_name_traceparent,
               hpack_classify_dynamic_name(&dynamic, k_hpack_static_table_size + 1),
               "newest dynamic name is traceparent");

    tp_info_t first = {};
    hpack_traceparent_decode_result_t decoded =
        hpack_decode_traceparent_value(realistic_first_stream + result.value_offset,
                                       result.encoded_value_len,
                                       result.value_huffman,
                                       &first,
                                       1);
    assert_u32(1, decoded.valid, "first encoded stream value decodes");
    assert_u32(0x01, first.trace_id[0], "first stream trace ID");
    assert_u32(0x10, first.trace_id[15], "first stream trace ID tail");
    assert_u32(0x11, first.parent_id[0], "first stream parent ID");
    assert_u32(0x18, first.parent_id[7], "first stream parent ID tail");
    assert_u32(k_flag_sampled, first.flags, "first stream flags");

    result = scan_with_dynamic_state(
        realistic_second_stream, sizeof(realistic_second_stream), 1, &dynamic);
    assert_u32(k_hpack_traceparent_found, result.status, "second encoded stream traceparent");
    assert_u32(k_hpack_representation_incremental,
               result.representation,
               "second encoded stream representation");
    assert_u32(2, result.value_offset, "second stream value follows its dynamic name index");
    assert_u32(2, dynamic.entry_count, "second stream preserves and extends the table");

    tp_info_t second = {};
    decoded = hpack_decode_traceparent_value(realistic_second_stream + result.value_offset,
                                             result.encoded_value_len,
                                             result.value_huffman,
                                             &second,
                                             1);
    assert_u32(1, decoded.valid, "second encoded stream value decodes");
    assert_u32(0x21, second.trace_id[0], "second stream trace ID");
    assert_u32(0x30, second.trace_id[15], "second stream trace ID tail");
    assert_u32(0x31, second.parent_id[0], "second stream parent ID");
    assert_u32(0x38, second.parent_id[7], "second stream parent ID tail");
    assert_u32(0, second.flags, "second stream flags");
}

static void test_trailer_maintenance_preserves_dynamic_order(void) {
    static const unsigned char trailer_insert[] = {0x40, 0x01, 'x', 0x01, 'y'};
    unsigned char after_trailer[sizeof(realistic_second_stream) + 1] = {0x7f, 0x00};
    memcpy(after_trailer + 2, realistic_second_stream + 1, sizeof(realistic_second_stream) - 1);

    hpack_dynamic_name_state_t maintained = {};
    hpack_dynamic_name_state_init(&maintained);
    (void)scan_with_dynamic_state(
        realistic_first_stream, sizeof(realistic_first_stream), 1, &maintained);
    hpack_traceparent_result_t result =
        scan_with_dynamic_state(trailer_insert, sizeof(trailer_insert), 1, &maintained);
    assert_u32(
        k_hpack_traceparent_absent, result.status, "existing-stream trailer has no traceparent");
    assert_u32(2, maintained.entry_count, "existing-stream trailer mutates the shared table");
    assert_u32(k_hpack_name_non_traceparent,
               hpack_classify_dynamic_name(&maintained, k_hpack_static_table_size + 1),
               "trailer insertion is the newest entry");
    assert_u32(k_hpack_name_traceparent,
               hpack_classify_dynamic_name(&maintained, k_hpack_static_table_size + 2),
               "prior traceparent name shifts after trailer insertion");

    result = scan_with_dynamic_state(after_trailer, sizeof(after_trailer), 1, &maintained);
    assert_u32(k_hpack_traceparent_found,
               result.status,
               "new stream resolves traceparent name after maintained trailer order");
    tp_info_t decoded_tp = {};
    const hpack_traceparent_decode_result_t decoded =
        hpack_decode_traceparent_value(after_trailer + result.value_offset,
                                       result.encoded_value_len,
                                       result.value_huffman,
                                       &decoded_tp,
                                       1);
    assert_u32(1, decoded.valid, "post-trailer dynamic-name value decodes");
    assert_u32(0x21, decoded_tp.trace_id[0], "post-trailer trace identity");
    assert_u32(0x31, decoded_tp.parent_id[0], "post-trailer parent identity");

    hpack_dynamic_name_state_t skipped = {};
    hpack_dynamic_name_state_init(&skipped);
    (void)scan_with_dynamic_state(
        realistic_first_stream, sizeof(realistic_first_stream), 1, &skipped);
    result = scan_with_dynamic_state(after_trailer, sizeof(after_trailer), 1, &skipped);
    assert_u32(k_hpack_traceparent_unknown,
               result.status,
               "skipping an existing-stream trailer loses dynamic ordering authority");
}

static void test_fully_indexed_traceparent_preserves_exact_value(void) {
    static const unsigned char indexed_traceparent[] = {0xbe};
    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    hpack_traceparent_result_t result = scan_with_dynamic_state(
        realistic_first_stream, sizeof(realistic_first_stream), 1, &dynamic);
    tp_info_t first = {};
    unsigned int cache_result = 0;
    hpack_traceparent_decode_result_t decoded = decode_and_cache_traceparent(
        realistic_first_stream, &result, &dynamic, &first, &cache_result);
    assert_u32(1, decoded.valid, "first indexed source value decodes");
    assert_u32(1, cache_result, "first indexed source value is cached");

    result = scan_with_dynamic_state(indexed_traceparent, sizeof(indexed_traceparent), 1, &dynamic);
    assert_u32(k_hpack_traceparent_found, result.status, "fully indexed sampled traceparent");
    assert_u32(1, result.value_cached, "fully indexed sampled value is authoritative");
    assert_u32(0x01, result.cached_trace_id[0], "fully indexed sampled trace ID");
    assert_u32(0x11, result.cached_parent_id[0], "fully indexed sampled parent ID");
    assert_u32(k_flag_sampled, result.cached_flags, "fully indexed sampled flags");

    result = scan_with_dynamic_state(
        realistic_second_stream, sizeof(realistic_second_stream), 1, &dynamic);
    tp_info_t second = {};
    decoded = decode_and_cache_traceparent(
        realistic_second_stream, &result, &dynamic, &second, &cache_result);
    assert_u32(1, decoded.valid, "second indexed source value decodes");
    assert_u32(1, cache_result, "second indexed source value is cached");

    result = scan_with_dynamic_state(indexed_traceparent, sizeof(indexed_traceparent), 1, &dynamic);
    assert_u32(k_hpack_traceparent_found, result.status, "fully indexed unsampled traceparent");
    assert_u32(1, result.value_cached, "fully indexed unsampled value is authoritative");
    assert_u32(0x21, result.cached_trace_id[0], "fully indexed unsampled trace ID");
    assert_u32(0x31, result.cached_parent_id[0], "fully indexed unsampled parent ID");
    assert_u32(0, result.cached_flags, "fully indexed unsampled flags");
    assert_u32(2, dynamic.entry_count, "indexed lookup does not mutate the dynamic table");
}

static void test_same_block_dynamic_reference_precedes_literal_traceparent(void) {
    static const unsigned char dynamic_field_then_literal[] = "\x40\x01"
                                                              "x"
                                                              "\x00\xbe\x00\x0b"
                                                              "traceparent"
                                                              "\x37" TP_VALUE;
    static const unsigned char dynamic_name_then_literal[] = "\x40\x01"
                                                             "x"
                                                             "\x00\x0f\x2f\x00\x00\x0b"
                                                             "traceparent"
                                                             "\x37" TP_VALUE;

    assert_result(dynamic_field_then_literal,
                  sizeof(dynamic_field_then_literal) - 1,
                  k_hpack_traceparent_found,
                  k_hpack_tp_val_offset + 5,
                  k_hpack_value_len_tp,
                  k_hpack_representation_without_indexing,
                  "same-block unrelated dynamic field before literal traceparent");
    assert_result(dynamic_name_then_literal,
                  sizeof(dynamic_name_then_literal) - 1,
                  k_hpack_traceparent_found,
                  k_hpack_tp_val_offset + 7,
                  k_hpack_value_len_tp,
                  k_hpack_representation_without_indexing,
                  "same-block unrelated dynamic name before literal traceparent");
}

static void test_unresolved_dynamic_reference_precedes_literal_traceparent(void) {
    static const unsigned char prior_block_dynamic_field[] = "\xbe\x00\x0b"
                                                             "traceparent"
                                                             "\x37" TP_VALUE;
    static const unsigned char prior_block_dynamic_name[] = "\x0f\x2f\x01x\x00\x0b"
                                                            "traceparent"
                                                            "\x37" TP_VALUE;

    assert_result(prior_block_dynamic_field,
                  sizeof(prior_block_dynamic_field) - 1,
                  k_hpack_traceparent_unknown,
                  0,
                  0,
                  0,
                  "prior-block dynamic field before literal traceparent");
    assert_result(prior_block_dynamic_name,
                  sizeof(prior_block_dynamic_name) - 1,
                  k_hpack_traceparent_unknown,
                  0,
                  0,
                  0,
                  "prior-block dynamic name before literal traceparent");
}

static void test_dynamic_table_size_and_eviction(void) {
    static const unsigned char literal_traceparent[] = "\x40\x0b"
                                                       "traceparent"
                                                       "\x37" TP_VALUE;
    unsigned char sized_first[sizeof(literal_traceparent) + 1] = {0x3f, 0x61};
    memcpy(sized_first + 2, literal_traceparent, sizeof(literal_traceparent) - 1);

    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    hpack_traceparent_result_t result =
        scan_with_dynamic_state(sized_first, sizeof(sized_first), 1, &dynamic);
    assert_u32(k_hpack_traceparent_found, result.status, "traceparent after table-size update");
    assert_u32(128, dynamic.max_table_size, "table-size update sets capacity");
    assert_u32(98, dynamic.table_size, "RFC entry size uses decoded name and value lengths");

    static const unsigned char insert_x[] = {0x40, 0x01, 'x', 0x00};
    result = scan_with_dynamic_state(insert_x, sizeof(insert_x), 1, &dynamic);
    assert_u32(k_hpack_traceparent_absent, result.status, "unrelated insertion is absent");
    assert_u32(33, dynamic.table_size, "insertion evicts to the configured byte capacity");
    assert_u32(1, dynamic.entry_count, "eviction retains only the newest entry");
    assert_u32(k_hpack_name_non_traceparent,
               hpack_classify_dynamic_name(&dynamic, k_hpack_static_table_size + 1),
               "newest entry survives eviction");
    assert_u32(k_hpack_name_unknown,
               hpack_classify_dynamic_name(&dynamic, k_hpack_static_table_size + 2),
               "evicted traceparent is no longer addressable");

    static const unsigned char clear_table[] = {0x20};
    result = scan_with_dynamic_state(clear_table, sizeof(clear_table), 1, &dynamic);
    assert_u32(k_hpack_traceparent_absent, result.status, "zero table-size update is absent");
    assert_u32(0, dynamic.max_table_size, "zero update disables the table");
    assert_u32(0, dynamic.entry_count, "zero update evicts every entry");

    result =
        scan_with_dynamic_state(literal_traceparent, sizeof(literal_traceparent) - 1, 1, &dynamic);
    assert_u32(k_hpack_traceparent_found, result.status, "oversized insertion still exposes field");
    assert_u32(0, dynamic.entry_count, "entry larger than capacity is not inserted");

    static const unsigned char restore_default[] = {0x3f, 0xe1, 0x1f};
    result = scan_with_dynamic_state(restore_default, sizeof(restore_default), 1, &dynamic);
    assert_u32(k_hpack_traceparent_absent, result.status, "restore default table size");
    assert_u32(
        k_hpack_default_dynamic_table_size, dynamic.max_table_size, "default capacity restored");

    static const unsigned char unsupported_size[] = {0x3f, 0xe2, 0x1f};
    result = scan_with_dynamic_state(unsupported_size, sizeof(unsupported_size), 1, &dynamic);
    assert_u32(k_hpack_traceparent_unknown, result.status, "unsupported table size fails closed");
    assert_u32(0, dynamic.valid, "unsupported table size invalidates the mirror");

    result = scan_with_dynamic_state(clear_table, sizeof(clear_table), 1, &dynamic);
    assert_u32(
        k_hpack_traceparent_absent, result.status, "zero update resynchronizes invalid state");
    assert_u32(1, dynamic.valid, "zero update reestablishes exact table state");
}

static void test_cumulative_dynamic_eviction(void) {
    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    dynamic.cumulative_size = 0xfff0;

    for (unsigned int i = 0; i < k_hpack_max_tracked_dynamic_entries; i++) {
        assert_u32(1,
                   hpack_dynamic_insert(&dynamic, 0, 0, k_hpack_name_non_traceparent, NULL, NULL),
                   "minimum-size dynamic insertion");
    }
    assert_u32(k_hpack_max_tracked_dynamic_entries,
               dynamic.entry_count,
               "default table retains 128 minimum-size entries");
    assert_u32(k_hpack_default_dynamic_table_size,
               dynamic.table_size,
               "minimum-size entries exactly fill the default table");
    assert_u32(0x0ff0, dynamic.cumulative_size, "cumulative entry size wraps modulo u16");

    hpack_dynamic_name_state_t boundary = dynamic;
    assert_u32(1,
               hpack_dynamic_table_resize(&boundary, 4095),
               "one-byte shrink from a full table succeeds");
    assert_u32(127, boundary.entry_count, "one-byte shrink evicts one minimum-size entry");
    assert_u32(4064, boundary.table_size, "one-byte shrink retains the maximal byte suffix");

    boundary = dynamic;
    assert_u32(1, hpack_dynamic_table_resize(&boundary, 31), "sub-minimum table limit succeeds");
    assert_u32(0, boundary.entry_count, "sub-minimum limit evicts every entry");
    assert_u32(0, boundary.table_size, "sub-minimum limit leaves an empty table");

    assert_u32(1,
               hpack_dynamic_table_resize(&dynamic, 2049),
               "odd table limit evicts with bounded probes");
    assert_u32(64, dynamic.entry_count, "odd table limit retains the maximal entry prefix");
    assert_u32(2048, dynamic.table_size, "odd table limit retains the exact suffix size");

    assert_u32(1,
               hpack_dynamic_insert(&dynamic, 1, 0, k_hpack_name_non_traceparent, NULL, NULL),
               "mixed-size insertion after cumulative wrap");
    assert_u32(64, dynamic.entry_count, "mixed-size insertion evicts one oldest entry");
    assert_u32(2049, dynamic.table_size, "mixed-size insertion fills the odd limit exactly");
    assert_u32(1,
               hpack_dynamic_table_resize(&dynamic, 2048),
               "one-byte shrink evicts the exact oldest boundary");
    assert_u32(63, dynamic.entry_count, "one-byte shrink removes one whole entry");
    assert_u32(2017, dynamic.table_size, "one-byte shrink retains exact mixed entry sizes");

    hpack_dynamic_name_state_t corrupt = {};
    hpack_dynamic_name_state_init(&corrupt);
    (void)hpack_dynamic_insert(&corrupt, 0, 0, k_hpack_name_non_traceparent, NULL, NULL);
    (void)hpack_dynamic_insert(&corrupt, 0, 0, k_hpack_name_non_traceparent, NULL, NULL);
    const u32 oldest = (corrupt.head + corrupt.entry_count - 1) & k_hpack_dynamic_entry_mask;
    corrupt.entries[oldest].cumulative_start++;
    assert_u32(0,
               hpack_dynamic_table_resize(&corrupt, 32),
               "inconsistent cumulative boundary fails closed");
    assert_u32(0, corrupt.valid, "inconsistent cumulative boundary invalidates authority");
}

static void test_cumulative_eviction_matches_queue_model(void) {
    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    dynamic.cumulative_size = 0xff00;

    unsigned int model[k_hpack_max_tracked_dynamic_entries] = {};
    unsigned int model_count = 0;
    unsigned int model_size = 0;
    unsigned int model_limit = k_hpack_default_dynamic_table_size;
    unsigned int random = 0x2793;

    for (unsigned int operation = 0; operation < 2048; operation++) {
        random = random * 1103515245U + 12345U;
        if ((random & 3U) == 0) {
            model_limit = (random >> 8) % (k_hpack_default_dynamic_table_size + 1);
            while (model_size > model_limit) {
                model_size -= model[--model_count];
            }
            assert_u32(1,
                       hpack_dynamic_table_resize(&dynamic, model_limit),
                       "random table resize remains authoritative");
        } else {
            const unsigned int entry_size = k_hpack_dynamic_entry_overhead + ((random >> 8) % 160);
            if (entry_size > model_limit) {
                model_count = 0;
                model_size = 0;
            } else {
                while (model_size + entry_size > model_limit) {
                    model_size -= model[--model_count];
                }
                memmove(model + 1, model, model_count * sizeof(model[0]));
                model[0] = entry_size;
                model_count++;
                model_size += entry_size;
            }
            assert_u32(1,
                       hpack_dynamic_insert(&dynamic,
                                            entry_size - k_hpack_dynamic_entry_overhead,
                                            0,
                                            k_hpack_name_non_traceparent,
                                            NULL,
                                            NULL),
                       "random dynamic insertion remains authoritative");
        }

        assert_u32(model_limit, dynamic.max_table_size, "random model table limit");
        assert_u32(model_count, dynamic.entry_count, "random model entry count");
        assert_u32(model_size, dynamic.table_size, "random model table size");
        unsigned int suffix_size = 0;
        for (unsigned int entry = 0; entry < model_count; entry++) {
            suffix_size += model[entry];
            assert_u32(suffix_size,
                       hpack_dynamic_suffix_size(&dynamic, entry + 1),
                       "random model cumulative suffix");
        }
    }
}

static void test_bulk_eviction_preserves_retained_cache(void) {
    static const unsigned char literal_traceparent[] = "\x40\x0b"
                                                       "traceparent"
                                                       "\x37" TP_VALUE;
    static const unsigned char indexed_traceparent[] = {0xbe};

    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    for (unsigned int i = 0; i < k_hpack_max_tracked_dynamic_entries; i++) {
        (void)hpack_dynamic_insert(&dynamic, 0, 0, k_hpack_name_non_traceparent, NULL, NULL);
    }

    hpack_traceparent_result_t result =
        scan_with_dynamic_state(literal_traceparent, sizeof(literal_traceparent) - 1, 1, &dynamic);
    tp_info_t decoded_tp = {};
    unsigned int cache_result = 0;
    (void)decode_and_cache_traceparent(
        literal_traceparent, &result, &dynamic, &decoded_tp, &cache_result);
    assert_u32(1, cache_result, "newest traceparent is cached after bulk eviction");

    assert_u32(1,
               hpack_dynamic_table_resize(&dynamic, 98),
               "bulk resize retains the newest traceparent exactly");
    assert_u32(1, dynamic.entry_count, "bulk resize evicts every older minimum-size entry");
    assert_u32(98, dynamic.table_size, "bulk resize preserves exact traceparent entry size");

    result = scan_with_dynamic_state(indexed_traceparent, sizeof(indexed_traceparent), 1, &dynamic);
    assert_u32(k_hpack_traceparent_found,
               result.status,
               "retained traceparent remains authoritative after bulk eviction");
    assert_u32(1, result.value_cached, "bulk eviction preserves retained cache ownership");
    assert_u32(0x01, result.cached_trace_id[0], "retained cache preserves trace identity");
    assert_u32(0x11, result.cached_parent_id[0], "retained cache preserves parent identity");
    assert_u32(k_flag_sampled, result.cached_flags, "retained cache preserves sampled flags");
}

static void test_lazy_cache_reclaim_preserves_live_owner(void) {
    static const unsigned char literal_a[] = "\x40\x0b"
                                             "traceparent"
                                             "\x37" TP_VALUE;
    static const unsigned char literal_b[] = "\x40\x0b"
                                             "traceparent"
                                             "\x37" TP_VALUE_B;
    static const unsigned char newest_indexed[] = {0xbe};
    static const unsigned char second_indexed[] = {0xbf};

    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    tp_info_t decoded_tp = {};
    unsigned int cache_result = 0;

    hpack_traceparent_result_t result =
        scan_with_dynamic_state(literal_a, sizeof(literal_a) - 1, 1, &dynamic);
    (void)decode_and_cache_traceparent(literal_a, &result, &dynamic, &decoded_tp, &cache_result);
    assert_u32(1, cache_result, "traceparent A occupies the first cache slot");

    result = scan_with_dynamic_state(literal_b, sizeof(literal_b) - 1, 1, &dynamic);
    (void)decode_and_cache_traceparent(literal_b, &result, &dynamic, &decoded_tp, &cache_result);
    assert_u32(1, cache_result, "traceparent B occupies the second cache slot");

    assert_u32(1,
               hpack_dynamic_table_resize(&dynamic, 98),
               "resize evicts cached A while retaining cached B");
    assert_u32(1,
               hpack_dynamic_table_resize(&dynamic, 196),
               "capacity grows without disturbing retained B");

    result = scan_with_dynamic_state(literal_a, sizeof(literal_a) - 1, 1, &dynamic);
    (void)decode_and_cache_traceparent(literal_a, &result, &dynamic, &decoded_tp, &cache_result);
    assert_u32(1, cache_result, "traceparent C lazily reclaims evicted A's cache slot");

    result = scan_with_dynamic_state(newest_indexed, sizeof(newest_indexed), 1, &dynamic);
    assert_u32(k_hpack_traceparent_found, result.status, "reclaimed newest cache is indexed");
    assert_u32(0x01, result.cached_trace_id[0], "reclaimed cache contains current traceparent C");

    result = scan_with_dynamic_state(second_indexed, sizeof(second_indexed), 1, &dynamic);
    assert_u32(k_hpack_traceparent_found, result.status, "retained B remains indexed");
    assert_u32(0x21, result.cached_trace_id[0], "lazy reclaim preserves retained B trace ID");
    assert_u32(0x31, result.cached_parent_id[0], "lazy reclaim preserves retained B parent ID");
    assert_u32(0, result.cached_flags, "lazy reclaim preserves retained B flags");
}

static void test_cache_owner_aba_without_clear(void) {
    static const unsigned char literal_a[] = "\x40\x0b"
                                             "traceparent"
                                             "\x37" TP_VALUE;
    static const unsigned char literal_b[] = "\x40\x0b"
                                             "traceparent"
                                             "\x37" TP_VALUE_B;
    static const unsigned char newest_indexed[] = {0xbe};

    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    assert_u32(
        1, hpack_dynamic_table_resize(&dynamic, 98), "ABA fixture uses a one-traceparent table");

    hpack_traceparent_result_t result =
        scan_with_dynamic_state(literal_a, sizeof(literal_a) - 1, 1, &dynamic);
    tp_info_t decoded_tp = {};
    unsigned int cache_result = 0;
    (void)decode_and_cache_traceparent(literal_a, &result, &dynamic, &decoded_tp, &cache_result);
    assert_u32(1, cache_result, "ABA fixture caches the original owner");
    const u8 original_slot = result.inserted_slot;
    const u8 original_generation = result.inserted_generation;

    for (unsigned int insertion = 0; insertion < 255; insertion++) {
        assert_u32(1,
                   hpack_dynamic_insert(&dynamic, 66, 0, k_hpack_name_non_traceparent, NULL, NULL),
                   "ABA fixture rotates one exact-size entry");
    }

    result = scan_with_dynamic_state(literal_b, sizeof(literal_b) - 1, 1, &dynamic);
    assert_u32(original_slot,
               result.inserted_slot,
               "256 insertions reuse the original physical ring slot");
    assert_u32(original_generation,
               result.inserted_generation,
               "256 insertions wrap the original generation");
    (void)decode_and_cache_traceparent(literal_b, &result, &dynamic, &decoded_tp, &cache_result);
    assert_u32(
        1, cache_result, "zeroed backlink lets the wrapped owner reclaim its stale cache record");

    result = scan_with_dynamic_state(newest_indexed, sizeof(newest_indexed), 1, &dynamic);
    assert_u32(k_hpack_traceparent_found, result.status, "wrapped current owner remains indexed");
    assert_u32(0x21, result.cached_trace_id[0], "wrapped owner never aliases the old trace ID");
    assert_u32(0x31, result.cached_parent_id[0], "wrapped owner never aliases the old parent ID");
    assert_u32(0, result.cached_flags, "wrapped owner never aliases the old sampled flag");
}

static void test_cache_slot_ownership_after_clear_and_reuse(void) {
    static const unsigned char insert_x[] = {0x40, 0x01, 'x', 0x00};
    static const unsigned char literal_a[] = "\x40\x0b"
                                             "traceparent"
                                             "\x37" TP_VALUE;
    static const unsigned char literal_b[] = "\x40\x0b"
                                             "traceparent"
                                             "\x37" TP_VALUE_B;
    static const unsigned char indexed_a[] = {0xc0};

    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    (void)scan_with_dynamic_state(insert_x, sizeof(insert_x), 1, &dynamic);
    hpack_traceparent_result_t result =
        scan_with_dynamic_state(literal_a, sizeof(literal_a) - 1, 1, &dynamic);
    tp_info_t decoded_tp = {};
    unsigned int cache_result = 0;
    (void)decode_and_cache_traceparent(literal_a, &result, &dynamic, &decoded_tp, &cache_result);
    assert_u32(1, cache_result, "pre-clear traceparent cache owner");

    hpack_dynamic_name_state_clear(&dynamic);
    result = scan_with_dynamic_state(literal_a, sizeof(literal_a) - 1, 1, &dynamic);
    (void)decode_and_cache_traceparent(literal_a, &result, &dynamic, &decoded_tp, &cache_result);
    assert_u32(1, cache_result, "post-clear traceparent A cache owner");

    (void)scan_with_dynamic_state(insert_x, sizeof(insert_x), 1, &dynamic);
    result = scan_with_dynamic_state(literal_b, sizeof(literal_b) - 1, 1, &dynamic);
    (void)decode_and_cache_traceparent(literal_b, &result, &dynamic, &decoded_tp, &cache_result);
    assert_u32(1, cache_result, "post-clear traceparent B cache owner");

    result = scan_with_dynamic_state(indexed_a, sizeof(indexed_a), 1, &dynamic);
    assert_u32(k_hpack_traceparent_found, result.status, "older live cache owner remains indexed");
    assert_u32(0x01, result.cached_trace_id[0], "stale ring slot never aliases traceparent A");
    assert_u32(0x11, result.cached_parent_id[0], "traceparent A parent remains exact");
    assert_u32(k_flag_sampled, result.cached_flags, "traceparent A flags remain exact");
}

static void test_evicted_deferred_cache_store_does_not_leak(void) {
    static const unsigned char first_tp_then_x[] = "\x3f\x61\x40\x0b"
                                                   "traceparent"
                                                   "\x37" TP_VALUE "\x40\x01x\x00";
    static const unsigned char tp_then_x[] = "\x40\x0b"
                                             "traceparent"
                                             "\x37" TP_VALUE "\x40\x01x\x00";
    static const unsigned char live_tp[] = "\x40\x0b"
                                           "traceparent"
                                           "\x37" TP_VALUE_B;
    static const unsigned char newest_indexed[] = {0xbe};

    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    for (unsigned int i = 0; i < k_hpack_max_cached_traceparents + 8; i++) {
        const unsigned char *block = i ? tp_then_x : first_tp_then_x;
        const unsigned int block_len = i ? sizeof(tp_then_x) - 1 : sizeof(first_tp_then_x) - 1;
        hpack_traceparent_result_t result = scan_with_dynamic_state(block, block_len, 1, &dynamic);
        tp_info_t decoded_tp = {};
        unsigned int cache_result = 0;
        const hpack_traceparent_decode_result_t decoded =
            decode_and_cache_traceparent(block, &result, &dynamic, &decoded_tp, &cache_result);
        assert_u32(1, decoded.valid, "evicted deferred traceparent still decodes");
        assert_u32(2, cache_result, "evicted deferred insertion is not cached");
        assert_u32(0,
                   dynamic.traceparent_slots_used,
                   "evicted deferred insertion never consumes a cache slot");
    }

    hpack_traceparent_result_t result =
        scan_with_dynamic_state(live_tp, sizeof(live_tp) - 1, 1, &dynamic);
    tp_info_t decoded_tp = {};
    unsigned int cache_result = 0;
    (void)decode_and_cache_traceparent(live_tp, &result, &dynamic, &decoded_tp, &cache_result);
    assert_u32(1, cache_result, "live traceparent still has cache capacity");
    result = scan_with_dynamic_state(newest_indexed, sizeof(newest_indexed), 1, &dynamic);
    assert_u32(k_hpack_traceparent_found, result.status, "live traceparent remains indexable");
    assert_u32(0x21, result.cached_trace_id[0], "live cached traceparent remains exact");
}

static void test_cache_generation_wrap(void) {
    static const unsigned char literal_a[] = "\x40\x0b"
                                             "traceparent"
                                             "\x37" TP_VALUE;
    static const unsigned char literal_b[] = "\x40\x0b"
                                             "traceparent"
                                             "\x37" TP_VALUE_B;
    static const unsigned char newest_indexed[] = {0xbe};

    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    dynamic.next_generation = 0xfe;
    hpack_traceparent_result_t result =
        scan_with_dynamic_state(literal_a, sizeof(literal_a) - 1, 1, &dynamic);
    assert_u32(0xff, result.inserted_generation, "cache generation reaches 255");
    tp_info_t decoded_tp = {};
    unsigned int cache_result = 0;
    (void)decode_and_cache_traceparent(literal_a, &result, &dynamic, &decoded_tp, &cache_result);
    assert_u32(1, cache_result, "generation 255 insertion caches");

    hpack_dynamic_name_state_clear(&dynamic);
    result = scan_with_dynamic_state(literal_b, sizeof(literal_b) - 1, 1, &dynamic);
    assert_u32(0, result.inserted_generation, "cache generation wraps to zero");
    (void)decode_and_cache_traceparent(literal_b, &result, &dynamic, &decoded_tp, &cache_result);
    assert_u32(1, cache_result, "wrapped live insertion caches without stale ownership");
    result = scan_with_dynamic_state(newest_indexed, sizeof(newest_indexed), 1, &dynamic);
    assert_u32(k_hpack_traceparent_found, result.status, "wrapped cache remains indexable");
    assert_u32(0x21, result.cached_trace_id[0], "wrapped cache resolves the current owner");
}

static void test_dynamic_lookup_miss_persistently_invalidates(void) {
    static const unsigned char out_of_range_index[] = {0xbf};
    static const unsigned char stale_index_one[] = {0xbe};

    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    hpack_traceparent_result_t result = scan_with_dynamic_state(
        realistic_first_stream, sizeof(realistic_first_stream), 1, &dynamic);
    tp_info_t decoded_tp = {};
    unsigned int cache_result = 0;
    (void)decode_and_cache_traceparent(
        realistic_first_stream, &result, &dynamic, &decoded_tp, &cache_result);
    assert_u32(1, cache_result, "stale-parent chain starts with an exact cache");

    result = scan_with_dynamic_state(out_of_range_index, sizeof(out_of_range_index), 1, &dynamic);
    assert_u32(k_hpack_traceparent_unknown, result.status, "unresolved dynamic index is unknown");
    assert_u32(0, dynamic.valid, "unresolved dynamic index invalidates persistent authority");

    result = scan_with_dynamic_state(stale_index_one, sizeof(stale_index_one), 1, &dynamic);
    assert_u32(k_hpack_traceparent_unknown,
               result.status,
               "later index one can never reuse the stale cached parent");
    assert_u32(0, result.value_cached, "stale cached identity is never returned");
}

static void test_invalid_traceparent_never_occupies_cache(void) {
    static const unsigned char invalid_literal[] = "\x40\x0b"
                                                   "traceparent"
                                                   "\x37"
                                                   "00-00000000000000000000000000000000-"
                                                   "1112131415161718-01";
    static const unsigned char newest_indexed[] = {0xbe};

    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    hpack_traceparent_result_t result =
        scan_with_dynamic_state(invalid_literal, sizeof(invalid_literal) - 1, 1, &dynamic);
    tp_info_t decoded_tp = {};
    unsigned int cache_result = 0;
    const hpack_traceparent_decode_result_t decoded = decode_and_cache_traceparent(
        invalid_literal, &result, &dynamic, &decoded_tp, &cache_result);
    assert_u32(0, decoded.valid, "zero trace ID is invalid");
    assert_u32(0, cache_result, "invalid traceparent is not cached");
    assert_u32(0, dynamic.traceparent_slots_used, "invalid value occupies no cache slot");

    result = scan_with_dynamic_state(newest_indexed, sizeof(newest_indexed), 1, &dynamic);
    assert_u32(k_hpack_traceparent_unknown,
               result.status,
               "indexed uncached traceparent revokes authority conservatively");
    assert_u32(0, dynamic.valid, "uncached indexed value persistently invalidates the mirror");
}

static unsigned int append_frame(unsigned char *raw,
                                 unsigned int pos,
                                 const unsigned char *payload,
                                 unsigned int payload_len,
                                 unsigned int type,
                                 unsigned int flags,
                                 unsigned int stream_id) {
    raw[pos] = payload_len >> 16;
    raw[pos + 1] = payload_len >> 8;
    raw[pos + 2] = payload_len;
    raw[pos + 3] = type;
    raw[pos + 4] = flags;
    raw[pos + 5] = stream_id >> 24;
    raw[pos + 6] = stream_id >> 16;
    raw[pos + 7] = stream_id >> 8;
    raw[pos + 8] = stream_id;
    memcpy(raw + pos + k_h2_frame_header_len, payload, payload_len);
    return pos + k_h2_frame_header_len + payload_len;
}

static void test_split_outer_frame_header_preserves_dynamic_order(void) {
    static const unsigned char insert_x[] = {0x40, 0x01, 'x', 0x00};
    static const unsigned char newest_indexed[] = {0xbe};
    unsigned char raw[k_kprobes_http2_buf_size] = {};
    const unsigned int raw_len = append_frame(
        raw, 0, insert_x, sizeof(insert_x), k_h2_frame_headers, k_h2_flag_end_headers, 3);

    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    hpack_traceparent_result_t result = scan_with_dynamic_state(
        realistic_first_stream, sizeof(realistic_first_stream), 1, &dynamic);
    tp_info_t decoded_tp = {};
    unsigned int cache_result = 0;
    (void)decode_and_cache_traceparent(
        realistic_first_stream, &result, &dynamic, &decoded_tp, &cache_result);
    assert_u32(1, cache_result, "split-header chain starts with cached traceparent A");

    h2_request_frame_cursor_t cursor = {};
    memcpy(cursor.header, raw, 4);
    cursor.header_len = 4;
    assert_u32(1, h2_request_frame_cursor_active(&cursor), "partial outer header is retained");
    memcpy(cursor.header + cursor.header_len,
           raw + cursor.header_len,
           k_h2_frame_header_len - cursor.header_len);
    cursor.header_len = k_h2_frame_header_len;
    assert_u32(sizeof(insert_x),
               h2_raw_frame_length(cursor.header),
               "split outer header restores payload length");
    assert_u32(
        3, h2_raw_frame_stream_id(cursor.header), "split outer header restores stream identity");

    h2_hpack_stream_state_t stream = {};
    h2_hpack_stream_begin(&stream, 1);
    u16 consumed = 0;
    h2_hpack_stream_consume(&stream, cursor.header, k_h2_frame_header_len, &consumed);
    assert_u32(k_h2_frame_header_len, consumed, "reconstructed outer header is consumed");
    h2_request_frame_cursor_reset(&cursor);
    h2_hpack_stream_consume(
        &stream, raw + k_h2_frame_header_len, raw_len - k_h2_frame_header_len, &consumed);
    assert_u32(1, stream.complete, "split outer header resumes through END_HEADERS");
    result = scan_with_dynamic_state(stream.block, stream.block_len, 1, &dynamic);
    assert_u32(k_hpack_traceparent_absent,
               result.status,
               "hidden non-traceparent insertion is maintained in wire order");

    result = scan_with_dynamic_state(newest_indexed, sizeof(newest_indexed), 1, &dynamic);
    assert_u32(k_hpack_traceparent_absent,
               result.status,
               "actual index one resolves X rather than stale traceparent A");
    assert_u32(0, result.value_cached, "split-header chain never returns stale parent flags");
}

static void test_coalesced_header_blocks_revoke_authority(void) {
    static const unsigned char static_method[] = {0x82};
    static const unsigned char insert_x[] = {0x40, 0x01, 'x', 0x00};
    static const unsigned char indexed_traceparent[] = {0xbe};
    unsigned char raw[k_kprobes_http2_buf_size] = {};
    unsigned int first_end = append_frame(
        raw, 0, static_method, sizeof(static_method), k_h2_frame_headers, k_h2_flag_end_headers, 1);
    const unsigned int raw_len = append_frame(
        raw, first_end, insert_x, sizeof(insert_x), k_h2_frame_headers, k_h2_flag_end_headers, 3);

    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    hpack_traceparent_result_t result = scan_with_dynamic_state(
        realistic_first_stream, sizeof(realistic_first_stream), 1, &dynamic);
    tp_info_t decoded_tp = {};
    unsigned int cache_result = 0;
    (void)decode_and_cache_traceparent(
        realistic_first_stream, &result, &dynamic, &decoded_tp, &cache_result);

    h2_hpack_stream_state_t stream = {};
    h2_hpack_stream_begin(&stream, 1);
    u16 consumed = 0;
    h2_hpack_stream_consume(&stream, raw, raw_len, &consumed);
    assert_u32(1, stream.complete, "first coalesced header block completes");
    assert_u32(first_end, consumed, "consumer stops exactly after first END_HEADERS");
    assert_u32(1,
               h2_hpack_stream_has_trailing_bytes(raw_len, consumed),
               "second coalesced header block is detected as trailing bytes");

    hpack_dynamic_name_state_invalidate(&dynamic);
    result = scan_with_dynamic_state(indexed_traceparent, sizeof(indexed_traceparent), 1, &dynamic);
    assert_u32(k_hpack_traceparent_unknown,
               result.status,
               "coalesced unprocessed block revokes cached-parent authority");
    assert_u32(0, result.value_cached, "coalesced block never returns a stale cached value");
}

static void test_continuation_block_collection(void) {
    enum { first_fragment_len = 17 };
    unsigned char raw[k_kprobes_http2_buf_size] = {};
    unsigned int raw_len =
        append_frame(raw, 0, realistic_first_stream, first_fragment_len, k_h2_frame_headers, 0, 1);
    raw_len = append_frame(raw,
                           raw_len,
                           realistic_first_stream + first_fragment_len,
                           sizeof(realistic_first_stream) - first_fragment_len,
                           k_h2_frame_continuation,
                           k_h2_flag_end_headers,
                           1);

    unsigned char block[k_hpack_tp_max_scan] = {};
    h2_hpack_block_t collected = {};
    h2_collect_hpack_block(raw, raw_len, block, &collected);
    assert_u32(1, collected.valid, "continuation sequence is valid");
    assert_u32(1, collected.complete, "END_HEADERS completes continuation sequence");
    assert_u32(sizeof(realistic_first_stream), collected.len, "continuation payload length");
    assert_u32(0,
               memcmp(block, realistic_first_stream, sizeof(realistic_first_stream)),
               "continuation payloads compact without frame bytes");

    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    const hpack_traceparent_result_t result =
        scan_with_dynamic_state(block, collected.len, collected.complete, &dynamic);
    assert_u32(k_hpack_traceparent_found, result.status, "collected continuation block parses");

    const unsigned int second_header = k_h2_frame_header_len + first_fragment_len;
    raw[second_header + k_h2_frame_stream_id_offset + 3] = 3;
    memset(&collected, 0, sizeof(collected));
    h2_collect_hpack_block(raw, raw_len, block, &collected);
    assert_u32(0, collected.valid, "wrong-stream CONTINUATION is rejected");

    raw[second_header + k_h2_frame_stream_id_offset + 3] = 1;
    memset(&collected, 0, sizeof(collected));
    h2_collect_hpack_block(raw, raw_len - 1, block, &collected);
    assert_u32(1, collected.valid, "truncated continuation retains framing confidence");
    assert_u32(0, collected.complete, "truncated continuation is never END_HEADERS-complete");
}

static void test_continuation_across_callbacks(void) {
    enum { first_fragment_len = 17 };
    unsigned char raw[k_kprobes_http2_buf_size] = {};
    unsigned int raw_len =
        append_frame(raw, 0, realistic_first_stream, first_fragment_len, k_h2_frame_headers, 0, 3);
    const unsigned int continuation_pos = raw_len;
    raw_len = append_frame(raw,
                           raw_len,
                           realistic_first_stream + first_fragment_len,
                           sizeof(realistic_first_stream) - first_fragment_len,
                           k_h2_frame_continuation,
                           k_h2_flag_end_headers,
                           3);

    h2_hpack_stream_state_t stream = {};
    h2_hpack_stream_begin(&stream, 7);
    unsigned int pos = 0;
    const unsigned int cuts[] = {
        k_h2_frame_header_len + 5,
        continuation_pos - 3,
        continuation_pos + 4,
        raw_len,
    };
    for (unsigned int i = 0; i < sizeof(cuts) / sizeof(cuts[0]); i++) {
        u16 consumed = 0;
        h2_hpack_stream_consume(&stream, raw + pos, cuts[i] - pos, &consumed);
        assert_u32(cuts[i] - pos, consumed, "fragment callback consumes all available bytes");
        pos = cuts[i];
        if (i + 1 < sizeof(cuts) / sizeof(cuts[0])) {
            assert_u32(0, stream.complete, "fragment callback remains pending before END_HEADERS");
        }
    }

    assert_u32(1, stream.complete, "later CONTINUATION callback completes request headers");
    assert_u32(0, stream.invalid, "split callback sequence retains framing authority");
    assert_u32(3, stream.stream_id, "split callback sequence retains stream identity");
    assert_u32(7, stream.direction, "split callback sequence retains connection direction");
    assert_u32(sizeof(realistic_first_stream), stream.block_len, "split HPACK block length");
    assert_u32(0,
               memcmp(stream.block, realistic_first_stream, sizeof(realistic_first_stream)),
               "split HPACK block reconstructs exact bytes");
    assert_u32(raw_len, stream.raw_len, "split callbacks reconstruct event bytes");
    assert_u32(0, memcmp(stream.raw, raw, raw_len), "split callbacks preserve framed bytes");

    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    const hpack_traceparent_result_t result =
        scan_with_dynamic_state(stream.block, stream.block_len, stream.complete, &dynamic);
    assert_u32(k_hpack_traceparent_found,
               result.status,
               "resumed CONTINUATION starts with an authoritative traceparent");
}

static void test_tracked_framing_accepts_reserved_and_unknown_types(void) {
    static const unsigned char method[] = {0x82};
    unsigned char raw[k_kprobes_http2_buf_size] = {};
    const unsigned int raw_len =
        append_frame(raw, 0, method, sizeof(method), k_h2_frame_headers, k_h2_flag_end_headers, 3);
    raw[5] |= k_h2_reserved_bit_mask;

    h2_hpack_stream_state_t stream = {};
    h2_hpack_stream_begin(&stream, 1);
    u16 consumed = 0;
    h2_hpack_stream_consume(&stream, raw, raw_len, &consumed);
    assert_u32(1, stream.complete, "reserved stream bit is ignored on a tracked connection");
    assert_u32(0, stream.invalid, "reserved stream bit keeps HPACK framing authoritative");
    assert_u32(3, stream.stream_id, "reserved stream bit is masked from stream identity");

    assert_u32(1,
               h2_tracked_frame_stream_valid(0x20, 0),
               "tracked extension type 0x20 is ignorable on stream zero");
    assert_u32(1,
               h2_tracked_frame_stream_valid(0xff, 0),
               "all unknown 8-bit tracked frame types are ignorable");
    assert_u32(0,
               h2_tracked_frame_stream_valid(k_h2_frame_headers, 0),
               "known stream-scoped frames still reject stream zero");

    h2_request_frame_cursor_t cursor = {};
    unsigned char unknown[k_h2_frame_header_len] = {};
    unknown[3] = 0xff;
    unknown[5] = k_h2_reserved_bit_mask;
    memcpy(cursor.header, unknown, 4);
    cursor.header_len = 4;
    memcpy(cursor.header + cursor.header_len,
           unknown + cursor.header_len,
           k_h2_frame_header_len - cursor.header_len);
    cursor.header_len = k_h2_frame_header_len;
    assert_u32(
        1,
        h2_tracked_frame_stream_valid(cursor.header[3], h2_raw_frame_stream_id(cursor.header)),
        "split unknown frame header is skippable after reconstruction");
}

static void test_zero_length_and_many_continuations(void) {
    static const unsigned char first[] = {0x82};
    static const unsigned char final[] = {0x84};
    static const unsigned char empty[] = {0};
    unsigned char raw[k_kprobes_http2_buf_size] = {};
    unsigned int raw_len = append_frame(raw, 0, first, sizeof(first), k_h2_frame_headers, 0, 5);
    raw_len =
        append_frame(raw, raw_len, empty, 0, k_h2_frame_continuation, k_h2_flag_end_headers, 5);

    h2_hpack_stream_state_t stream = {};
    h2_hpack_stream_begin(&stream, 1);
    u16 consumed = 0;
    h2_hpack_stream_consume(&stream, raw, raw_len, &consumed);
    assert_u32(1, stream.complete, "empty END_HEADERS continuation completes the block");
    assert_u32(0, stream.invalid, "empty END_HEADERS continuation remains authoritative");
    assert_u32(sizeof(first), stream.block_len, "empty continuation adds no HPACK bytes");

    memset(raw, 0, sizeof(raw));
    raw_len = append_frame(raw, 0, first, sizeof(first), k_h2_frame_headers, 0, 7);
    raw_len = append_frame(raw, raw_len, empty, 0, k_h2_frame_continuation, 0, 7);
    raw_len = append_frame(
        raw, raw_len, final, sizeof(final), k_h2_frame_continuation, k_h2_flag_end_headers, 7);
    h2_hpack_stream_begin(&stream, 1);
    h2_hpack_stream_consume(&stream, raw, raw_len, &consumed);
    assert_u32(1, stream.complete, "empty nonterminal continuation advances to the final fragment");
    assert_u32(0, stream.invalid, "empty nonterminal continuation is valid");
    assert_u32(2, stream.block_len, "fragments around an empty continuation are retained");

    memset(raw, 0, sizeof(raw));
    raw_len = append_frame(raw, 0, first, sizeof(first), k_h2_frame_headers, 0, 9);
    for (unsigned int fragment = 1; fragment < 5; fragment++) {
        raw_len = append_frame(raw,
                               raw_len,
                               final,
                               sizeof(final),
                               k_h2_frame_continuation,
                               fragment == 4 ? k_h2_flag_end_headers : 0,
                               9);
    }
    h2_hpack_stream_begin(&stream, 1);
    h2_hpack_stream_consume(&stream, raw, raw_len, &consumed);
    assert_u32(1, stream.complete, "five-fragment header block completes");
    assert_u32(0, stream.invalid, "five retained fragments do not reuse the sniffing bound");
    assert_u32(5, stream.frame_count, "persistent accumulator counts all five fragments");
}

static void test_server_tail_depth_model(void) {
    assert_u32(
        31,
        h2_server_tail_depth(1, k_h2_server_max_parser_passes, k_h2_server_max_decoder_passes),
        "one maximal maintenance block fits the 33-call limit");
    assert_u32(1,
               h2_server_tail_depth(1,
                                    k_h2_server_max_parser_passes,
                                    k_h2_server_max_decoder_passes) <= k_h2_tail_call_limit,
               "accepted maximal path is within the kernel limit");
    assert_u32(1,
               h2_server_tail_depth(2,
                                    k_h2_server_max_parser_passes,
                                    k_h2_server_max_decoder_passes) > k_h2_tail_call_limit,
               "a second maximal block is rejected before tail-call exhaustion");
}

static void test_fragment_failure_reset_and_connection_reuse(void) {
    enum { first_fragment_len = 8 };
    unsigned char first[k_kprobes_http2_buf_size] = {};
    const unsigned int first_len = append_frame(
        first, 0, realistic_first_stream, first_fragment_len, k_h2_frame_headers, 0, 1);
    unsigned char wrong[k_kprobes_http2_buf_size] = {};
    const unsigned int wrong_len = append_frame(wrong,
                                                0,
                                                realistic_first_stream + first_fragment_len,
                                                sizeof(realistic_first_stream) - first_fragment_len,
                                                k_h2_frame_continuation,
                                                k_h2_flag_end_headers,
                                                5);

    h2_hpack_stream_state_t stream = {};
    h2_hpack_stream_begin(&stream, 1);
    u16 consumed = 0;
    h2_hpack_stream_consume(&stream, first, first_len, &consumed);
    assert_u32(0, stream.complete, "truncated header block remains resumable");
    h2_hpack_stream_consume(&stream, wrong, wrong_len, &consumed);
    assert_u32(1, stream.complete, "wrong-stream continuation terminates accumulation");
    assert_u32(1, stream.framing_invalid, "wrong-stream continuation fails closed");

    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    (void)scan_with_dynamic_state(
        realistic_first_stream, sizeof(realistic_first_stream), 1, &dynamic);
    assert_u32(1, dynamic.entry_count, "old connection has dynamic state before cleanup");
    hpack_dynamic_name_state_invalidate(&dynamic);
    h2_hpack_stream_reset(&stream);
    assert_u32(0, stream.active, "teardown clears a truncated accumulator");
    assert_u32(0, stream.block_len, "teardown drops truncated HPACK bytes");

    // A replacement connection generation begins with neither the old table
    // nor the old framing cursor.
    hpack_dynamic_name_state_init(&dynamic);
    h2_hpack_stream_begin(&stream, 1);
    assert_u32(0, dynamic.entry_count, "connection reuse starts with an empty dynamic table");
    assert_u32(0, stream.frame_header_len, "connection reuse starts at a frame boundary");
    assert_u32(0, stream.block_len, "connection reuse has no prior header fragment");
}

static void test_incomplete_block_invalidates_dynamic_state(void) {
    hpack_dynamic_name_state_t dynamic = {};
    hpack_dynamic_name_state_init(&dynamic);
    const hpack_traceparent_result_t result = scan_with_dynamic_state(
        realistic_first_stream, sizeof(realistic_first_stream), 0, &dynamic);
    assert_u32(k_hpack_traceparent_unknown, result.status, "incomplete block is non-authoritative");
    assert_u32(0, dynamic.valid, "incomplete block invalidates dynamic state");

    hpack_dynamic_name_state_init(&dynamic);
    assert_u32(1, dynamic.valid, "new connection generation reinitializes HPACK state");
    assert_u32(0, dynamic.entry_count, "new connection generation starts with an empty table");
    assert_u32(k_hpack_default_dynamic_table_size,
               dynamic.max_table_size,
               "new connection generation restores the RFC default capacity");
}

static void test_server_parent_authority(void) {
    assert_u32(k_hpack_server_parent_connection_fallback,
               hpack_server_parent_authority(k_hpack_traceparent_absent, 0),
               "absent traceparent permits connection fallback");
    assert_u32(k_hpack_server_parent_traceparent,
               hpack_server_parent_authority(k_hpack_traceparent_found, 1),
               "decoded traceparent is authoritative");
    assert_u32(k_hpack_server_parent_force_root,
               hpack_server_parent_authority(k_hpack_traceparent_found, 0),
               "invalid traceparent forces a root");
    assert_u32(k_hpack_server_parent_force_root,
               hpack_server_parent_authority(k_hpack_traceparent_unknown, 0),
               "ambiguous traceparent state forces a root");
}

int main(void) {
    test_literal_representations();
    test_huffman_name();
    test_static_and_dynamic_indices();
    test_malformed_and_incomplete();
    test_huffman_scan_resumes_across_parser_chunks();
    test_scan_rejects_lost_data_len_bound();
    test_decoder_rejects_lost_encoded_len_bound();
    test_huffman_value();
    test_huffman_validation();
    test_duplicate_traceparents();
    test_future_version_lengths();
    test_raw_string_fast_forward_scan();
    test_dynamic_name_persists_across_streams();
    test_trailer_maintenance_preserves_dynamic_order();
    test_fully_indexed_traceparent_preserves_exact_value();
    test_same_block_dynamic_reference_precedes_literal_traceparent();
    test_unresolved_dynamic_reference_precedes_literal_traceparent();
    test_dynamic_table_size_and_eviction();
    test_cumulative_dynamic_eviction();
    test_cumulative_eviction_matches_queue_model();
    test_bulk_eviction_preserves_retained_cache();
    test_lazy_cache_reclaim_preserves_live_owner();
    test_cache_owner_aba_without_clear();
    test_cache_slot_ownership_after_clear_and_reuse();
    test_evicted_deferred_cache_store_does_not_leak();
    test_cache_generation_wrap();
    test_dynamic_lookup_miss_persistently_invalidates();
    test_invalid_traceparent_never_occupies_cache();
    test_split_outer_frame_header_preserves_dynamic_order();
    test_coalesced_header_blocks_revoke_authority();
    test_continuation_block_collection();
    test_continuation_across_callbacks();
    test_tracked_framing_accepts_reserved_and_unknown_types();
    test_zero_length_and_many_continuations();
    test_server_tail_depth_model();
    test_fragment_failure_reset_and_connection_reuse();
    test_incomplete_block_invalidates_dynamic_state();
    test_server_parent_authority();

    if (failures) {
        fprintf(stderr, "%u test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
